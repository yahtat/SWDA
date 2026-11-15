"""Deterministic tools available to agents, plus the tool catalogue used by approval gates.

Every tool declares a sensitivity level. The registry refuses to approve an agent that
requests a tool above the ceiling for its risk tier, and the ToolBroker refuses to run
any tool that is not on the agent's approved allow-list - even if the agent code tries.
"""
from __future__ import annotations
import json, re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DATA = Path(__file__).parent / "data"
_PROGRAMMES = json.loads((DATA / "programmes.json").read_text())["programmes"]
_BY_ID = {p["programme_id"]: p for p in _PROGRAMMES}

CRISIS_TERMS = ("violence", "abuse", "suicide", "self-harm", "unsafe", "threat", "homeless", "evict")
CATEGORY_LABELS = sorted({p["category"] for p in _PROGRAMMES})


def _tokens(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9\- ]+", " ", text.lower()) + " "


# ---------------- tool implementations (pure functions) ----------------
def classify_request(description: str) -> dict:
    """Keyword-weighted category scoring. Deterministic stand-in for the production classifier."""
    text = _tokens(description)
    scores: dict[str, float] = {}
    matched: dict[str, list[str]] = {}
    for p in _PROGRAMMES:
        for kw in p["keywords"]:
            if f" {kw} " in text or (len(kw) > 4 and f" {kw}" in text):
                scores[p["category"]] = scores.get(p["category"], 0.0) + 1.0
                matched.setdefault(p["category"], []).append(kw)
    total = sum(scores.values()) or 1.0
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    cats = [{"category": c, "confidence": round(s / total, 3), "matched_keywords": sorted(set(matched[c]))} for c, s in ranked]
    return {"categories": cats[:3], "crisis_flag": any(t in text for t in CRISIS_TERMS)}


def search_programmes(categories: list[str], region: str) -> dict:
    hits = [p for p in _PROGRAMMES if p["category"] in categories and region in p["regions"]]
    return {"programmes": [{"programme_id": p["programme_id"], "name": p["name"], "category": p["category"],
                            "description": p["description"], "keywords": p["keywords"]} for p in hits]}


def check_eligibility(programme_id: str, age: int | None, household_income_monthly: float | None,
                      household_size: int, region: str) -> dict:
    p = _BY_ID.get(programme_id)
    if not p:
        return {"programme_id": programme_id, "eligible": False, "reasons": ["unknown programme"]}
    reasons, eligible = [], True
    if age is not None:
        if p["min_age"] is not None and age < p["min_age"]:
            eligible = False; reasons.append(f"applicant age {age} below minimum {p['min_age']}")
        if p["max_age"] is not None and age > p["max_age"]:
            eligible = False; reasons.append(f"applicant age {age} above maximum {p['max_age']}")
    if p["income_cap_monthly"] is not None and household_income_monthly is not None:
        per_capita_cap = p["income_cap_monthly"]
        if household_income_monthly > per_capita_cap * max(1, household_size) / 2:
            eligible = False; reasons.append("household income above indicative threshold")
    if region not in p["regions"]:
        eligible = False; reasons.append("programme not offered in region")
    if eligible:
        reasons.append("meets indicative criteria (final decision by caseworker)")
    return {"programme_id": programme_id, "eligible": eligible, "reasons": reasons}


def lookup_case_history(client_ref: str) -> dict:  # RESTRICTED - exists to prove the broker blocks it
    raise RuntimeError("restricted tool executed - the broker should have blocked this")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable
    sensitivity: str          # public | internal | restricted
    description: str


TOOL_CATALOGUE: dict[str, ToolSpec] = {t.name: t for t in [
    ToolSpec("classify_request", classify_request, "internal", "Classify free text into service categories."),
    ToolSpec("search_programmes", search_programmes, "internal", "List candidate programmes by category and region."),
    ToolSpec("check_eligibility", check_eligibility, "internal", "Indicative eligibility check against programme criteria."),
    ToolSpec("lookup_case_history", lookup_case_history, "restricted", "Read a client's historical case file."),
]}

SENSITIVITY_RANK = {"public": 0, "internal": 1, "restricted": 2}
