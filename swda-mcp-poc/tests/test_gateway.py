import json, os, subprocess, sys, tempfile, unittest
from unittest import mock
from swda_mcp import agent as agent_mod
from swda_mcp.audit import AuditLog
from swda_mcp.client import MCPHttpClient
from swda_mcp.registry import ROOT
from swda_mcp.transports import make_http_server, run_in_thread
from tests.helpers import ANALYTICS, CLIENTS, GOOD_ARGS, PORTAL, new_env, rpc, set_limits

CALL = lambda args, name="recommend_services": {"name": name, "arguments": args}


class ProtocolTests(unittest.TestCase):
    def setUp(self): self.tmp, self.reg, self.audit, self.gw = new_env()

    def test_initialize_negotiates_version_and_advertises_tools_only(self):
        r = rpc(self.gw, PORTAL, "initialize", {"protocolVersion": "2025-03-26"})["result"]
        self.assertEqual(r["protocolVersion"], "2025-03-26"); self.assertEqual(list(r["capabilities"]), ["tools"])
        self.assertEqual(rpc(self.gw, PORTAL, "initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"], "2025-06-18")

    def test_notifications_get_no_reply_and_unknown_methods_error(self):
        self.assertIsNone(self.gw.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, PORTAL))
        self.assertEqual(rpc(self.gw, PORTAL, "resources/list")["error"]["code"], -32601)
        self.assertEqual(self.gw.handle([{"jsonrpc": "2.0"}], PORTAL)["error"]["code"], -32600)

    def test_tools_list_is_scope_filtered(self):
        tools = rpc(self.gw, PORTAL, "tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["recommend_services"])
        self.assertTrue(tools[0]["annotations"]["readOnlyHint"]); self.assertIn("inputSchema", tools[0])
        self.assertEqual(rpc(self.gw, ANALYTICS, "tools/list")["result"]["tools"], [])


class CallTests(unittest.TestCase):
    def setUp(self): self.tmp, self.reg, self.audit, self.gw = new_env()

    def test_successful_call_returns_structured_content(self):
        r = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS))["result"]
        self.assertFalse(r["isError"]); self.assertEqual(r["structuredContent"]["recommendations"][0]["programme_id"], "PRG-HSG-01")
        self.assertEqual(json.loads(r["content"][0]["text"]), r["structuredContent"])

    def test_invalid_input_is_a_tool_error_not_a_crash(self):
        r = rpc(self.gw, PORTAL, "tools/call", CALL(dict(GOOD_ARGS, region="mars", extra=1)))["result"]
        self.assertTrue(r["isError"]); self.assertIn("region", r["content"][0]["text"])

    def test_oversized_request_rejected(self):
        set_limits(self.reg, max_request_bytes=100)
        r = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS))["result"]
        self.assertTrue(r["isError"]); self.assertIn("too large", r["content"][0]["text"])

    def test_manifest_edit_without_reapproval_removes_agent(self):
        self.reg._db["agents"]["service-recommendation-agent@1.0.0"]["manifest"]["limits"]["max_request_bytes"] = 10**9
        self.reg._save()
        self.assertIn("error", rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS)))

    def test_wrong_scope_and_unknown_tool_are_indistinguishable(self):
        a = rpc(self.gw, ANALYTICS, "tools/call", CALL(GOOD_ARGS))["error"]
        b = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS, name="lookup_case_history"))["error"]
        self.assertEqual(a["code"], b["code"])

    def test_rogue_agent_attempting_restricted_tool_is_blocked(self):
        def rogue(request, broker): broker.call("lookup_case_history", client_ref="C-9")
        with mock.patch.object(agent_mod, "recommend", rogue):
            r = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS))["result"]
        self.assertTrue(r["isError"]); self.assertIn("non-approved tool", r["content"][0]["text"])
        self.assertTrue(any(json.loads(l).get("outcome") == "tool_denied" for l in self.audit.path.read_text().splitlines()))

    def test_output_contract_violation_fails_closed(self):
        with mock.patch.object(agent_mod, "recommend", lambda req, broker: {"oops": True}):
            r = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS))["result"]
        self.assertTrue(r["isError"]); self.assertNotIn("oops", json.dumps(r))

    def test_timeout(self):
        import time
        set_limits(self.reg, timeout_seconds=0.05)
        with mock.patch.object(agent_mod, "recommend", lambda req, broker: time.sleep(0.5)):
            r = rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS))["result"]
        self.assertTrue(r["isError"]); self.assertIn("timed out", r["content"][0]["text"])

    def test_rate_limit(self):
        c = CLIENTS.authenticate("demo-token-throttle-demo")
        codes = [rpc(self.gw, c, "tools/call", CALL(GOOD_ARGS)).get("error", {}).get("code") for _ in range(5)]
        self.assertEqual(codes, [None, None, None, -32029, -32029])

    def test_kill_switch_takes_effect_immediately(self):
        self.reg.set_state("service-recommendation-agent", "1.0.0", "SUSPENDED", "dave", "incident")
        self.assertEqual(rpc(self.gw, PORTAL, "tools/list")["result"]["tools"], [])
        self.assertIn("error", rpc(self.gw, PORTAL, "tools/call", CALL(GOOD_ARGS)))

    def test_unapproved_agent_is_invisible(self):
        _, _, _, gw = new_env(approve=False)
        self.assertEqual(rpc(gw, PORTAL, "tools/list")["result"]["tools"], [])


class AuditTests(unittest.TestCase):
    def test_audit_has_no_pii_and_chain_detects_tampering(self):
        tmp, reg, audit, gw = new_env()
        rpc(gw, PORTAL, "tools/call", CALL(dict(GOOD_ARGS, description="eviction notice, mail me at jo@example.com or 91234567")))
        text = audit.path.read_text()
        for secret in ("jo@example.com", "91234567", "eviction"): self.assertNotIn(secret, text)
        self.assertTrue(AuditLog.verify(audit.path)[0])
        lines = text.splitlines(); rec = json.loads(lines[0]); rec["outcome"] = "forged"; lines[0] = json.dumps(rec)
        audit.path.write_text("\n".join(lines) + "\n")
        self.assertFalse(AuditLog.verify(audit.path)[0])


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.reg, cls.audit, cls.gw = new_env()
        cls.srv = make_http_server(cls.gw, CLIENTS, port=0); run_in_thread(cls.srv)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/mcp"

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def test_auth_required(self):
        self.assertEqual(MCPHttpClient(self.url).rpc("tools/list")[0], 401)
        self.assertEqual(MCPHttpClient(self.url, "nope").rpc("tools/list")[0], 401)

    def test_end_to_end_call_and_notification_202(self):
        c = MCPHttpClient(self.url, "demo-token-caseworker-portal")
        self.assertEqual(c.initialize()[0], 200); self.assertEqual(c.notify("notifications/initialized")[0], 202)
        st, body = c.call_tool("recommend_services", GOOD_ARGS)
        self.assertEqual(st, 200); self.assertFalse(body["result"]["isError"])

    def test_browser_origin_rejected(self):
        import urllib.request, urllib.error
        req = urllib.request.Request(self.url, b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                                     {"Content-Type": "application/json", "Origin": "http://evil.example", "Authorization": "Bearer demo-token-caseworker-portal"})
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 403)

    def test_health_and_metrics(self):
        import urllib.request
        base = self.url.rsplit("/mcp", 1)[0]
        self.assertIn('"approved_agents": 1', urllib.request.urlopen(base + "/healthz").read().decode())
        self.assertIn("mcp_tool_calls_total", urllib.request.urlopen(base + "/metrics").read().decode())


class StdioTests(unittest.TestCase):
    def test_stdio_round_trip(self):
        tmp, *_ = new_env()
        env = dict(os.environ, SWDA_VAR_DIR=str(tmp), SWDA_MCP_TOKEN="demo-token-caseworker-portal", PYTHONPATH=str(ROOT))
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": CALL(GOOD_ARGS)}]
        p = subprocess.run([sys.executable, "-m", "swda_mcp.cli", "serve", "--transport", "stdio"], input="\n".join(map(json.dumps, msgs)) + "\n",
                           capture_output=True, text=True, env=env, timeout=20, cwd=ROOT)
        out = [json.loads(l) for l in p.stdout.splitlines()]
        self.assertEqual([o["id"] for o in out], [1, 2]); self.assertFalse(out[1]["result"]["isError"])

    def test_stdio_refuses_without_valid_token(self):
        tmp, *_ = new_env()
        env = dict(os.environ, SWDA_VAR_DIR=str(tmp), SWDA_MCP_TOKEN="bad", PYTHONPATH=str(ROOT))
        p = subprocess.run([sys.executable, "-m", "swda_mcp.cli", "serve", "--transport", "stdio"], input="", capture_output=True, text=True, env=env, timeout=20, cwd=ROOT)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
