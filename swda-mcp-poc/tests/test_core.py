import unittest
from swda_mcp.jsonschema_lite import validate
from swda_mcp.agent import ToolBroker, ToolDenied, recommend
from swda_mcp.security import redact, RateLimiter
from tests.helpers import GOOD_ARGS

ALLOWED = frozenset({"classify_request", "search_programmes", "check_eligibility"})


class SchemaTests(unittest.TestCase):
    S = {"type": "object", "required": ["a"], "additionalProperties": False,
         "properties": {"a": {"type": "integer", "minimum": 1}, "b": {"type": "string", "enum": ["x"]}}}

    def test_valid(self): self.assertEqual(validate({"a": 2, "b": "x"}, self.S), [])
    def test_missing_and_extra(self): self.assertEqual(len(validate({"z": 1}, self.S)), 2)
    def test_bool_is_not_integer(self): self.assertTrue(validate({"a": True}, self.S))
    def test_range_and_enum(self): self.assertEqual(len(validate({"a": 0, "b": "y"}, self.S)), 2)


class AgentTests(unittest.TestCase):
    def test_recommendation_is_deterministic_and_sensible(self):
        r1 = recommend(GOOD_ARGS, ToolBroker(ALLOWED)); r2 = recommend(GOOD_ARGS, ToolBroker(ALLOWED))
        self.assertEqual(r1, r2)
        self.assertEqual(r1["predicted_categories"][0]["category"], "housing")
        self.assertEqual(r1["recommendations"][0]["programme_id"], "PRG-HSG-01")

    def test_ineligible_programme_is_down_ranked_and_explained(self):
        req = dict(GOOD_ARGS, description="I want a rental flat, affordable housing please", age=19, household_income_monthly=9000)
        top = recommend(req, ToolBroker(ALLOWED))["recommendations"][0]
        self.assertFalse(top["eligible"]); self.assertIn("household income above indicative threshold", top["rationale"])

    def test_unmatched_text_goes_to_human(self):
        r = recommend(dict(GOOD_ARGS, description="zzz qqq www"), ToolBroker(ALLOWED))
        self.assertTrue(r["needs_human_review"]); self.assertEqual(r["recommendations"], [])

    def test_broker_blocks_restricted_and_unlisted_tools(self):
        b = ToolBroker(ALLOWED)
        with self.assertRaises(ToolDenied): b.call("lookup_case_history", client_ref="C-1")
        with self.assertRaises(ToolDenied): b.call("does_not_exist")
        self.assertEqual([t["outcome"] for t in b.trace], ["denied_not_allowlisted", "denied_unknown"])

    def test_broker_call_budget(self):
        b = ToolBroker(ALLOWED, max_calls=1)
        b.call("classify_request", description="rent")
        with self.assertRaises(ToolDenied): b.call("classify_request", description="rent")


class SecurityTests(unittest.TestCase):
    def test_redaction(self):
        out = redact("mail a.b@x.org call +65 9123 4567 id S1234567D")
        self.assertNotIn("a.b@x.org", out); self.assertNotIn("9123", out); self.assertNotIn("S1234567D", out)

    def test_rate_limiter_refills(self):
        t = [0.0]; rl = RateLimiter(clock=lambda: t[0])
        self.assertTrue(all(rl.allow("c", 2) for _ in range(2))); self.assertFalse(rl.allow("c", 2))
        t[0] = 31.0; self.assertTrue(rl.allow("c", 2))


if __name__ == "__main__":
    unittest.main()
