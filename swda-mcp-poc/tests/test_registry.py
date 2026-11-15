import copy, json, unittest
from swda_mcp.registry import Registry, RegistryError
from tests.helpers import MANIFEST, new_env


class RegistryTests(unittest.TestCase):
    def test_happy_path_requires_all_roles(self):
        tmp, reg, *_ = new_env(approve=False)
        a, v = MANIFEST["agent_id"], MANIFEST["version"]
        reg.validate_agent(a, v)
        reg.approve(a, v, "bob", "ml_lead"); reg.approve(a, v, "carol", "security")
        self.assertEqual(reg._get(a, v)["state"], "VALIDATED")
        reg.approve(a, v, "dave", "governance")
        self.assertEqual(reg._get(a, v)["state"], "APPROVED")

    def test_cannot_approve_before_validation(self):
        _, reg, *_ = new_env(approve=False)
        with self.assertRaises(RegistryError): reg.approve(MANIFEST["agent_id"], MANIFEST["version"], "bob", "ml_lead")

    def test_separation_of_duties(self):
        _, reg, *_ = new_env(approve=False)
        a, v = MANIFEST["agent_id"], MANIFEST["version"]; reg.validate_agent(a, v)
        with self.assertRaises(RegistryError): reg.approve(a, v, "alice.owner", "ml_lead")   # submitter
        reg.approve(a, v, "bob", "ml_lead")
        with self.assertRaises(RegistryError): reg.approve(a, v, "bob", "security")          # same person twice

    def test_versions_are_immutable(self):
        _, reg, *_ = new_env(approve=False)
        with self.assertRaises(RegistryError): reg.submit(copy.deepcopy(MANIFEST), "alice.owner")

    def test_restricted_tool_fails_gate_and_is_rejected(self):
        m = copy.deepcopy(MANIFEST); m["version"] = "1.0.1"; m["allowed_tools"].append("lookup_case_history")
        _, reg, *_ = new_env(approve=False, manifest=m)
        rec = reg.validate_agent(m["agent_id"], m["version"])
        self.assertEqual(rec["state"], "REJECTED")
        self.assertFalse(next(g for g in rec["gate_results"] if g["gate"] == "G2")["passed"])

    def test_quality_gate_blocks_underperforming_agent(self):
        m = copy.deepcopy(MANIFEST); m["version"] = "1.0.2"; m["evaluation"]["min_category_accuracy"] = 1.01
        _, reg, *_ = new_env(approve=False, manifest=m)
        rec = reg.validate_agent(m["agent_id"], m["version"])
        self.assertFalse(next(g for g in rec["gate_results"] if g["gate"] == "G3")["passed"])

    def test_loose_input_schema_fails_gate(self):
        m = copy.deepcopy(MANIFEST); m["version"] = "1.0.3"; m["mcp"]["input_schema"].pop("additionalProperties")
        _, reg, *_ = new_env(approve=False, manifest=m)
        self.assertEqual(reg.validate_agent(m["agent_id"], m["version"])["state"], "REJECTED")

    def test_tampering_after_approval_removes_exposure(self):
        tmp, reg, *_ = new_env()
        self.assertEqual(len(reg.approved_agents()), 1)
        db = json.loads((tmp / "registry.json").read_text())
        db["agents"][f"{MANIFEST['agent_id']}@{MANIFEST['version']}"]["manifest"]["allowed_tools"].append("lookup_case_history")
        (tmp / "registry.json").write_text(json.dumps(db)); reg.refresh()
        self.assertEqual(reg.approved_agents(), []); self.assertTrue(reg.integrity_violations())


if __name__ == "__main__":
    unittest.main()
