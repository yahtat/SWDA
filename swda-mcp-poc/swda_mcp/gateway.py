"""MCP gateway: JSON-RPC 2.0 / Model Context Protocol server core (transport-agnostic).

Every tools/call passes this pipeline - the agent cannot be reached any other way:
  authN (transport) -> registry lookup (APPROVED + manifest hash intact) -> scope authZ -> rate limit
  -> size limit -> input-schema validation -> timeout-bounded invocation under tool broker
  -> output-contract validation -> audit record (+ metrics)
"""
from __future__ import annotations
import concurrent.futures as cf, json, threading, time
from collections import Counter
from . import __version__, agent as agent_mod
from .audit import AuditLog
from .jsonschema_lite import validate
from .registry import Registry
from .security import Client, RateLimiter, canonical_json, sha256_hex

SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"]
E_PARSE, E_INVALID, E_METHOD, E_PARAMS, E_INTERNAL = -32700, -32600, -32601, -32602, -32603
E_RATE = -32029  # implementation-defined: mapped to HTTP 429 by the transport


class Metrics:
    """Tiny Prometheus-style registry (production: OpenTelemetry -> CloudWatch/Datadog/Grafana)."""

    def __init__(self):
        self.calls: Counter = Counter()
        self.latency_sum: dict[str, float] = {}
        self.latency_n: Counter = Counter()
        self._lock = threading.Lock()

    def observe(self, agent: str, outcome: str, seconds: float):
        with self._lock:
            self.calls[(agent, outcome)] += 1
            self.latency_sum[agent] = self.latency_sum.get(agent, 0.0) + seconds
            self.latency_n[agent] += 1

    def render(self) -> str:
        lines = ["# TYPE mcp_tool_calls_total counter"]
        for (agent, outcome), n in sorted(self.calls.items()):
            lines.append(f'mcp_tool_calls_total{{agent="{agent}",outcome="{outcome}"}} {n}')
        lines.append("# TYPE mcp_tool_latency_seconds_sum counter")
        for agent, s in sorted(self.latency_sum.items()):
            lines.append(f'mcp_tool_latency_seconds_sum{{agent="{agent}"}} {s:.6f}')
            lines.append(f'mcp_tool_latency_seconds_count{{agent="{agent}"}} {self.latency_n[agent]}')
        return "\n".join(lines) + "\n"


def _ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_, code, message, data=None):
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": e}


def _tool_result(payload: dict | None = None, error: str | None = None) -> dict:
    if error:
        return {"content": [{"type": "text", "text": error}], "isError": True}
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload, "isError": False}


class MCPGateway:
    def __init__(self, registry: Registry, audit: AuditLog, limiter: RateLimiter | None = None, workers: int = 8):
        self.registry, self.audit = registry, audit
        self.limiter = limiter or RateLimiter()
        self.metrics = Metrics()
        self._pool = cf.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="agent")

    # ---------------- helpers ----------------
    def _exposed(self) -> dict[str, dict]:
        """tool_name -> registry record, for APPROVED agents with intact manifest hash."""
        self.registry.refresh()
        for key in self.registry.integrity_violations():
            self.audit.write("registry_integrity_violation", agent=key)
        return {r["manifest"]["mcp"]["tool_name"]: r for r in self.registry.approved_agents()}

    @staticmethod
    def _visible(client: Client, rec: dict) -> bool:
        return rec["manifest"]["mcp"]["required_scope"] in client.scopes

    # ---------------- JSON-RPC entry ----------------
    def handle(self, msg, client: Client) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _err(msg.get("id") if isinstance(msg, dict) else None, E_INVALID, "Invalid Request (batching is not supported)")
        id_, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        is_notification = "id" not in msg
        try:
            if method == "initialize":
                return _ok(id_, self._initialize(params))
            if method == "ping":
                return _ok(id_, {})
            if method.startswith("notifications/"):
                return None
            if method == "tools/list":
                return _ok(id_, self._tools_list(client))
            if method == "tools/call":
                return self._tools_call(id_, params, client)
            return None if is_notification else _err(id_, E_METHOD, f"Method not found: {method}")
        except Exception as exc:  # never leak internals to the caller
            self.audit.write("gateway_error", client_id=client.client_id, method=method, error=type(exc).__name__)
            return _err(id_, E_INTERNAL, "Internal error")

    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
        return {"protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "swda-governed-mcp-gateway", "version": __version__},
                "instructions": "Only SWDA-approved agents are exposed. Outputs are advisory; a caseworker decides."}

    def _tools_list(self, client: Client) -> dict:
        tools = []
        for name, rec in sorted(self._exposed().items()):
            if not self._visible(client, rec):
                continue
            m = rec["manifest"]
            tools.append({"name": name, "title": m["name"], "description": m["description"],
                          "inputSchema": m["mcp"]["input_schema"], "outputSchema": m["mcp"]["output_schema"],
                          "annotations": m["mcp"].get("annotations", {}),
                          "_meta": {"swda/agent_id": m["agent_id"], "swda/version": m["version"],
                                    "swda/risk_tier": m["risk_tier"], "swda/manifest_sha256": rec["manifest_sha256"][:16]}})
        return {"tools": tools}

    def _tools_call(self, id_, params: dict, client: Client) -> dict:
        t0 = time.perf_counter()
        name, args = params.get("name"), params.get("arguments") or {}
        rec = self._exposed().get(name)
        base = {"client_id": client.client_id, "tool": name}

        # Unknown, unapproved, suspended AND out-of-scope all look identical to the caller (no enumeration).
        if rec is None or not self._visible(client, rec):
            reason = "unknown_or_unapproved" if rec is None else "denied_scope"
            self.audit.write("tools/call", **base, outcome=reason)
            self.metrics.observe(name or "?", reason, time.perf_counter() - t0)
            return _err(id_, E_PARAMS, f"Unknown tool: {name}")

        m = rec["manifest"]
        agent_id = m["agent_id"]
        base.update(agent_id=agent_id, agent_version=m["version"], manifest_sha256=rec["manifest_sha256"][:16])
        in_digest = sha256_hex(canonical_json(args))

        def finish(outcome, result, **extra):
            dt = time.perf_counter() - t0
            self.audit.write("tools/call", **base, outcome=outcome, input_sha256=in_digest,
                             latency_ms=round(dt * 1000, 2), **extra)
            self.metrics.observe(agent_id, outcome, dt)
            return _ok(id_, result)

        limit = min(client.rate_limit_per_min, m["mcp"].get("rate_limit_per_min", 60))
        if not self.limiter.allow(f"{client.client_id}:{agent_id}", limit):
            self.audit.write("tools/call", **base, outcome="rate_limited", input_sha256=in_digest)
            self.metrics.observe(agent_id, "rate_limited", time.perf_counter() - t0)
            return _err(id_, E_RATE, "Rate limit exceeded")

        if len(canonical_json(args).encode()) > m["limits"]["max_request_bytes"]:
            return finish("rejected_too_large", _tool_result(error="Request too large"))

        errors = validate(args, m["mcp"]["input_schema"])
        if errors:
            return finish("rejected_invalid_input", _tool_result(error="Invalid arguments: " + "; ".join(errors[:5])))

        future = self._pool.submit(agent_mod.invoke, m, args)
        try:
            response, trace = future.result(timeout=m["limits"]["timeout_seconds"])
        except cf.TimeoutError:
            future.cancel()
            return finish("timeout", _tool_result(error="Agent timed out"))
        except agent_mod.ToolDenied as exc:
            return finish("tool_denied", _tool_result(error="Agent attempted a non-approved tool; call blocked"), detail=str(exc))
        except Exception as exc:
            return finish("agent_error", _tool_result(error="Agent failed"), error=type(exc).__name__)

        out_errors = validate(response, m["mcp"]["output_schema"])
        if out_errors:  # fail closed: never return a response that violates the approved contract
            return finish("output_contract_violation", _tool_result(error="Agent produced an invalid response"))

        return finish("ok", _tool_result(response), tools_used=[t["tool"] for t in trace],
                      needs_human_review=response["needs_human_review"],
                      top_programmes=[r["programme_id"] for r in response["recommendations"]])
