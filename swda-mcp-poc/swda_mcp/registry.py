"""Agent registry + approval workflow.

Lifecycle:  DRAFT -> SUBMITTED -> VALIDATED -> APPROVED -> (SUSPENDED | RETIRED)
  * submit    : owner registers a manifest (content-hashed)
  * validate  : automated gates G1-G6 (schema, tools, evaluation, safety, determinism, limits)
  * approve   : each required role approves once; approver must differ from the owner
  * the gateway only exposes APPROVED agents whose manifest hash still equals the approved hash
Production mapping: records live in a Delta/DynamoDB table with Unity Catalog / IAM write controls;
approvals arrive via the change-management tool (e.g. ServiceNow/Jira) with SSO identities.
"""
from __future__ import annotations
import json, time
from pathlib import Path
from . import agent as agent_mod
from .jsonschema_lite import validate
from .security import canonical_json, sha256_hex
from .tools import TOOL_CATALOGUE, SENSITIVITY_RANK

STATES = ("SUBMITTED", "VALIDATED", "APPROVED", "SUSPENDED", "RETIRED", "REJECTED")
# Highest tool sensitivity an agent of a given risk tier may request in this PoC.
TIER_CEILING = {"low": "internal", "medium": "internal", "high": "internal"}
ROOT = Path(__file__).resolve().parent.parent

_MANIFEST_SCHEMA = {
    "type": "object",
    "required": ["agent_id", "version", "name", "owner", "risk_tier", "data_classification", "implementation",
                 "allowed_tools", "limits", "evaluation", "mcp", "approval"],
    "properties": {
        "agent_id": {"type": "string", "pattern": "^[a-z0-9-]{3,64}$"},
        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "risk_tier": {"type": "string", "enum": ["low", "medium", "high"]},
        "allowed_tools": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "limits": {"type": "object", "required": ["max_tool_calls", "timeout_seconds", "max_request_bytes"]},
        "mcp": {"type": "object", "required": ["tool_name", "required_scope", "input_schema", "output_schema"]},
        "approval": {"type": "object", "required": ["required_roles"]},
    },
}


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = json.loads(self.path.read_text()) if self.path.exists() else {"agents": {}}

    # ---- persistence ----
    def refresh(self):
        """Re-read the store so suspensions (kill switch) take effect on the very next request."""
        if self.path.exists():
            self._db = json.loads(self.path.read_text())

    def _save(self):
        self.path.write_text(json.dumps(self._db, indent=2, sort_keys=True))

    def _key(self, agent_id, version):
        return f"{agent_id}@{version}"

    def _get(self, agent_id, version) -> dict:
        rec = self._db["agents"].get(self._key(agent_id, version))
        if not rec:
            raise RegistryError(f"{agent_id}@{version} is not registered")
        return rec

    def _event(self, rec, actor, action, note=""):
        rec["history"].append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "actor": actor, "action": action, "note": note})

    # ---- workflow ----
    def submit(self, manifest: dict, submitted_by: str) -> dict:
        errs = validate(manifest, _MANIFEST_SCHEMA)
        if errs:
            raise RegistryError("manifest invalid: " + "; ".join(errs))
        key = self._key(manifest["agent_id"], manifest["version"])
        if key in self._db["agents"]:
            raise RegistryError(f"{key} already registered - versions are immutable, bump the version")
        rec = {"manifest": manifest, "manifest_sha256": sha256_hex(canonical_json(manifest)), "state": "SUBMITTED",
               "gate_results": None, "approvals": [], "history": []}
        self._event(rec, submitted_by, "submit")
        self._db["agents"][key] = rec
        self._save()
        return rec

    def validate_agent(self, agent_id: str, version: str, actor: str = "ci-pipeline") -> dict:
        rec = self._get(agent_id, version)
        if rec["state"] not in ("SUBMITTED", "VALIDATED"):
            raise RegistryError(f"cannot validate from state {rec['state']}")
        results = run_gates(rec["manifest"])
        rec["gate_results"] = results
        passed = all(g["passed"] for g in results)
        rec["state"] = "VALIDATED" if passed else "REJECTED"
        self._event(rec, actor, "validate", "all gates passed" if passed else "gate failure")
        self._save()
        return rec

    def approve(self, agent_id: str, version: str, approver: str, role: str) -> dict:
        rec = self._get(agent_id, version)
        m = rec["manifest"]
        if rec["state"] not in ("VALIDATED", "APPROVED"):
            raise RegistryError(f"cannot approve from state {rec['state']} (run validation first)")
        if role not in m["approval"]["required_roles"]:
            raise RegistryError(f"role '{role}' is not a required approver role")
        if approver == m["owner"] or approver == rec["history"][0]["actor"]:
            raise RegistryError("separation of duties: the owner/submitter cannot approve their own agent")
        if any(a["role"] == role for a in rec["approvals"]):
            raise RegistryError(f"role '{role}' already approved")
        if any(a["approver"] == approver for a in rec["approvals"]):
            raise RegistryError(f"'{approver}' already approved under another role - distinct people required")
        rec["approvals"].append({"approver": approver, "role": role, "manifest_sha256": rec["manifest_sha256"]})
        self._event(rec, approver, "approve", role)
        if {a["role"] for a in rec["approvals"]} >= set(m["approval"]["required_roles"]):
            rec["state"] = "APPROVED"
            self._event(rec, "registry", "state", "APPROVED")
        self._save()
        return rec

    def set_state(self, agent_id, version, state, actor, note=""):
        if state not in ("SUSPENDED", "RETIRED"):
            raise RegistryError("only SUSPENDED/RETIRED can be set directly (kill switch)")
        rec = self._get(agent_id, version)
        rec["state"] = state
        self._event(rec, actor, state.lower(), note)
        self._save()
        return rec

    # ---- read side used by the gateway ----
    def approved_agents(self) -> list[dict]:
        """Approved agents whose stored manifest still matches the hash that was approved (tamper check)."""
        out = []
        for rec in self._db["agents"].values():
            if rec["state"] != "APPROVED":
                continue
            current = sha256_hex(canonical_json(rec["manifest"]))
            if current != rec["manifest_sha256"] or any(a["manifest_sha256"] != current for a in rec["approvals"]):
                continue  # silently excluded; the gateway audits this as a registry-integrity event
            out.append(rec)
        return out

    def integrity_violations(self) -> list[str]:
        bad = []
        for key, rec in self._db["agents"].items():
            if rec["state"] == "APPROVED" and sha256_hex(canonical_json(rec["manifest"])) != rec["manifest_sha256"]:
                bad.append(key)
        return bad


# ------------------------- automated approval gates -------------------------
def run_gates(manifest: dict) -> list[dict]:
    results = []

    def gate(gid, name, fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # a crashing gate is a failing gate
            ok, detail = False, f"gate crashed: {exc!r}"
        results.append({"gate": gid, "name": name, "passed": bool(ok), "detail": detail})

    def g1_schema():
        for key in ("input_schema", "output_schema"):
            s = manifest["mcp"][key]
            if s.get("type") != "object":
                return False, f"{key} must be an object schema"
        if manifest["mcp"]["input_schema"].get("additionalProperties") is not False:
            return False, "input_schema must set additionalProperties=false (reject unknown fields)"
        return True, "input/output schemas are strict object schemas"

    def g2_tools():
        unknown = [t for t in manifest["allowed_tools"] if t not in TOOL_CATALOGUE]
        if unknown:
            return False, f"unknown tools requested: {unknown}"
        ceiling = SENSITIVITY_RANK[TIER_CEILING[manifest["risk_tier"]]]
        too_hot = [t for t in manifest["allowed_tools"] if SENSITIVITY_RANK[TOOL_CATALOGUE[t].sensitivity] > ceiling]
        if too_hot:
            return False, f"tools exceed sensitivity ceiling for tier {manifest['risk_tier']}: {too_hot}"
        return True, f"{len(manifest['allowed_tools'])} tools, all within ceiling"

    cases = None

    def _load_cases():
        nonlocal cases
        if cases is None:
            cases = json.loads((ROOT / manifest["evaluation"]["golden_set"]).read_text())
        return cases

    def g3_quality():
        c = _load_cases()["cases"]
        cat_ok = hit = 0
        for case in c:
            resp, _ = agent_mod.invoke(manifest, case["request"])
            top_cat = resp["predicted_categories"][0]["category"] if resp["predicted_categories"] else None
            cat_ok += top_cat == case["expected_category"]
            hit += case["expected_programme"] in [r["programme_id"] for r in resp["recommendations"]]
        acc, hr = cat_ok / len(c), hit / len(c)
        ev = manifest["evaluation"]
        ok = acc >= ev["min_category_accuracy"] and hr >= ev["min_programme_hit_rate_top3"]
        return ok, f"category_accuracy={acc:.2f} (min {ev['min_category_accuracy']}), programme_hit_rate@3={hr:.2f} (min {ev['min_programme_hit_rate_top3']}), n={len(c)}"

    def g4_safety():
        bad = 0
        for case in _load_cases()["adversarial"]:
            resp, trace = agent_mod.invoke(manifest, case["request"])
            bad += sum(1 for t in trace if t["tool"] in case["forbidden_tools"])
            top = resp["predicted_categories"][0]["category"] if resp["predicted_categories"] else None
            bad += top != case["expected_category"]
        return bad <= manifest["evaluation"]["max_forbidden_tool_calls"], f"adversarial violations={bad}"

    def g5_determinism():
        req = _load_cases()["cases"][0]["request"]
        a, _ = agent_mod.invoke(manifest, req)
        b, _ = agent_mod.invoke(manifest, req)
        return canonical_json(a) == canonical_json(b), "identical output across repeated runs"

    def g6_output_contract():
        for case in _load_cases()["cases"]:
            resp, _ = agent_mod.invoke(manifest, case["request"])
            errs = validate(resp, manifest["mcp"]["output_schema"])
            if errs:
                return False, errs[0]
            if not validate(case["request"], manifest["mcp"]["input_schema"]) == []:
                return False, "golden request violates declared input schema"
        return True, "golden outputs conform to output schema"

    gate("G1", "Schema strictness", g1_schema)
    gate("G2", "Tool allow-list & sensitivity", g2_tools)
    gate("G3", "Offline evaluation thresholds", g3_quality)
    gate("G4", "Adversarial / injection safety", g4_safety)
    gate("G5", "Determinism / reproducibility", g5_determinism)
    gate("G6", "Output contract", g6_output_contract)
    return results
