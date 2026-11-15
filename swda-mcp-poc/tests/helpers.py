import copy, json, tempfile
from pathlib import Path
from swda_mcp.audit import AuditLog
from swda_mcp.gateway import MCPGateway
from swda_mcp.registry import Registry, ROOT
from swda_mcp.security import ClientDirectory, RateLimiter

MANIFEST = json.loads((ROOT / "agents/service_recommendation/manifest.json").read_text())
CLIENTS = ClientDirectory(ROOT / "config/clients.json")
PORTAL = CLIENTS.authenticate("demo-token-caseworker-portal")
ANALYTICS = CLIENTS.authenticate("demo-token-analytics-readonly")
GOOD_ARGS = {"request_id": "SR-1", "description": "My landlord served an eviction notice, we have nowhere to go.",
             "age": 34, "region": "east", "household_income_monthly": 1800, "household_size": 3, "urgency": "medium"}


def new_env(approve=True, manifest=None):
    tmp = Path(tempfile.mkdtemp())
    reg = Registry(tmp / "registry.json")
    m = copy.deepcopy(manifest or MANIFEST)
    reg.submit(m, "alice.owner")
    if approve:
        reg.validate_agent(m["agent_id"], m["version"])
        for who, role in [("bob", "ml_lead"), ("carol", "security"), ("dave", "governance")]:
            reg.approve(m["agent_id"], m["version"], who, role)
    audit = AuditLog(tmp / "audit.jsonl")
    gw = MCPGateway(reg, audit, RateLimiter())
    return tmp, reg, audit, gw


def rpc(gw, client, method, params=None, id_=1):
    return gw.handle({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}, client)


def set_limits(reg, **limits):
    """Test helper: change manifest limits and re-pin the approved hash (simulates a re-approved release)."""
    from swda_mcp.security import canonical_json, sha256_hex
    rec = reg._db["agents"]["service-recommendation-agent@1.0.0"]
    rec["manifest"]["limits"].update(limits)
    rec["manifest_sha256"] = sha256_hex(canonical_json(rec["manifest"]))
    for a in rec["approvals"]:
        a["manifest_sha256"] = rec["manifest_sha256"]
    reg._save()
