# SWDA Governed MCP Gateway - Proof of Concept

A small, runnable, **dependency-free** (Python 3.10+ standard library only) implementation of the
"controlled exposure of approved agents through MCP" part of the SWDA MLOps/AIOps design.

It contains:

| Piece | File | Production counterpart |
|---|---|---|
| Service Recommendation Agent (deterministic tools, synthetic data) | `swda_mcp/agent.py`, `swda_mcp/tools.py`, `swda_mcp/data/` | Agent runtime on ECS/EKS; tools backed by Databricks SQL / feature tables |
| Tool broker (allow-list, call budget, trace) | `agent.py: ToolBroker` | MCP tool gateway policy + IAM-scoped service roles |
| Agent registry + approval workflow (state machine, gates G1-G6, separation of duties, hash pinning) | `swda_mcp/registry.py` | Registry table in Unity Catalog / DynamoDB + change-management integration |
| MCP gateway (initialize, tools/list, tools/call; JSON-RPC 2.0) | `swda_mcp/gateway.py` | Same, behind API Gateway/ALB + WAF, OIDC |
| Transports: stdio and HTTP `POST /mcp` | `swda_mcp/transports.py` | Streamable HTTP, mTLS |
| Authn/z, rate limit, PII redaction | `swda_mcp/security.py` | IdP (OIDC/JWT), WAF, DLP |
| Hash-chained audit log | `swda_mcp/audit.py` | CloudWatch -> S3 Object Lock + Delta audit table |
| Metrics | `gateway.py: Metrics`, `GET /metrics` | OpenTelemetry -> CloudWatch / Grafana |

## Run it

```bash
python -m swda_mcp.cli demo            # full governance story end-to-end (resets ./var)
python -m unittest discover -s tests -t .   # 39 tests
```

Manual flow:

```bash
python -m swda_mcp.cli registry submit agents/service_recommendation/manifest.json --by alice.owner
python -m swda_mcp.cli registry validate service-recommendation-agent 1.0.0
python -m swda_mcp.cli registry approve  service-recommendation-agent 1.0.0 --approver bob   --role ml_lead
python -m swda_mcp.cli registry approve  service-recommendation-agent 1.0.0 --approver carol --role security
python -m swda_mcp.cli registry approve  service-recommendation-agent 1.0.0 --approver dave  --role governance
python -m swda_mcp.cli serve --transport http --port 8808
```

Call it:

```bash
curl -s localhost:8808/mcp -H 'Authorization: Bearer demo-token-caseworker-portal' \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

curl -s localhost:8808/mcp -H 'Authorization: Bearer demo-token-caseworker-portal' \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"recommend_services","arguments":{"request_id":"SR-1","description":"Landlord gave an eviction notice","age":34,"region":"east","household_income_monthly":1800,"household_size":3,"urgency":"high"}}}'
```

stdio (for desktop MCP hosts):

```bash
SWDA_MCP_TOKEN=demo-token-caseworker-portal python -m swda_mcp.cli serve --transport stdio
```

Demo clients (token -> scopes): `demo-token-caseworker-portal` (invoke), `demo-token-analytics-readonly`
(catalogue read only - sees no agents), `demo-token-throttle-demo` (3 calls/min). Only SHA-256 digests are stored.

## What the gateway enforces on every `tools/call`

1. Authenticated client (bearer token -> identity); browser `Origin` rejected.
2. Agent must be **APPROVED** and its manifest hash must equal the hash that was approved.
3. Client must hold the agent's scope. Unknown / unapproved / out-of-scope are indistinguishable (no enumeration).
4. Per-client, per-agent rate limit.
5. Request size limit and strict input-schema validation (`additionalProperties: false`).
6. Agent runs under a tool broker: only manifest-listed tools, bounded call count, bounded time.
7. Output validated against the approved output schema (fail closed).
8. Audit record (digests + redacted metadata, never raw free text) and metrics.

## Known limitations (deliberate for a PoC)

- Agent logic is rule-based; evaluation set is tiny and synthetic (100% scores demonstrate the *gate*, not model quality).
- Timeout abandons the worker thread rather than killing it; production uses process/container isolation.
- Static bearer tokens; production uses OIDC with short-lived, audience-bound tokens and mTLS.
- Stateless HTTP, JSON responses only (no SSE streaming, no sessions, no batching).
- Single-node file-backed registry/audit; production uses managed, access-controlled stores.
- `/metrics` and `/healthz` are unauthenticated and must be bound to loopback / private network.
