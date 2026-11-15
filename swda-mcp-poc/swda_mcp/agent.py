"""Service Recommendation Agent: orchestrates deterministic tools through a policy-enforcing broker."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from .tools import TOOL_CATALOGUE, CATEGORY_LABELS

AGENT_ID = "service-recommendation-agent"


class ToolDenied(Exception):
    pass


@dataclass
class ToolBroker:
    """Mediates every tool call: allow-list, call budget, and a trace for audit.

    The agent never holds direct references to tool functions - least privilege by construction.
    """
    allowed: frozenset[str]
    max_calls: int = 8
    trace: list[dict] = field(default_factory=list)

    def call(self, name: str, **kwargs):
        if name not in TOOL_CATALOGUE:
            self.trace.append({"tool": name, "outcome": "denied_unknown"}); raise ToolDenied(f"unknown tool '{name}'")
        if name not in self.allowed:
            self.trace.append({"tool": name, "outcome": "denied_not_allowlisted"}); raise ToolDenied(f"tool '{name}' is not approved for this agent")
        if sum(1 for t in self.trace if t["outcome"] == "ok") >= self.max_calls:
            self.trace.append({"tool": name, "outcome": "denied_budget"}); raise ToolDenied("tool-call budget exhausted")
        t0 = time.perf_counter()
        result = TOOL_CATALOGUE[name].fn(**kwargs)
        self.trace.append({"tool": name, "outcome": "ok", "ms": round((time.perf_counter() - t0) * 1000, 2)})
        return result


def recommend(request: dict, broker: ToolBroker, top_k: int = 3) -> dict:
    """Pure, deterministic orchestration: classify -> search -> eligibility -> rank."""
    cls = broker.call("classify_request", description=request["description"])
    cats = [c["category"] for c in cls["categories"]]
    candidates = broker.call("search_programmes", categories=cats, region=request["region"])["programmes"] if cats else []

    cat_conf = {c["category"]: c["confidence"] for c in cls["categories"]}
    text_hits = lambda p: sum(1 for k in p["keywords"] if k in request["description"].lower())
    recs = []
    for p in candidates:
        elig = broker.call("check_eligibility", programme_id=p["programme_id"], age=request.get("age"),
                           household_income_monthly=request.get("household_income_monthly"),
                           household_size=request.get("household_size", 1), region=request["region"])
        score = cat_conf.get(p["category"], 0.0) + 0.05 * text_hits(p)
        if not elig["eligible"]:
            score *= 0.25
        recs.append({"programme_id": p["programme_id"], "name": p["name"], "category": p["category"],
                     "score": round(score, 3), "eligible": elig["eligible"], "rationale": elig["reasons"]})
    recs.sort(key=lambda r: (-r["score"], r["programme_id"]))
    recs = recs[:top_k]

    top_conf = cls["categories"][0]["confidence"] if cls["categories"] else 0.0
    reasons = []
    if not cats:
        reasons.append("no category matched")
    if top_conf < 0.5:
        reasons.append("low classification confidence")
    if cls["crisis_flag"] or request.get("urgency") == "high":
        reasons.append("high urgency or crisis indicators")
    if not any(r["eligible"] for r in recs):
        reasons.append("no indicative eligible programme")

    return {
        "request_id": request["request_id"],
        "predicted_categories": cls["categories"],
        "recommendations": recs,
        "needs_human_review": bool(reasons),
        "review_reasons": reasons,
        "disclaimer": "Indicative recommendation only. A caseworker makes the final decision.",
        "agent": {"id": AGENT_ID},
    }


def invoke(manifest: dict, request: dict) -> tuple[dict, list[dict]]:
    """Run the agent under the *approved manifest's* tool allow-list. Returns (response, tool_trace)."""
    broker = ToolBroker(allowed=frozenset(manifest["allowed_tools"]), max_calls=manifest["limits"]["max_tool_calls"])
    try:
        resp = recommend(request, broker)
    finally:
        trace = broker.trace
    resp["agent"] = {"id": manifest["agent_id"], "version": manifest["version"]}
    return resp, trace
