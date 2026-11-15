"""Minimal MCP client over HTTP (used by the demo and tests; any MCP-compliant client works too)."""
from __future__ import annotations
import itertools, json, urllib.request, urllib.error


class MCPHttpClient:
    def __init__(self, url: str, token: str | None = None):
        self.url, self.token, self._ids = url, token, itertools.count(1)

    def _post(self, payload: dict) -> tuple[int, dict | None]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, json.dumps(payload).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read()
                return r.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            body = e.read()
            return e.code, (json.loads(body) if body else None)

    def rpc(self, method: str, params: dict | None = None):
        return self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}})

    def notify(self, method: str):
        return self._post({"jsonrpc": "2.0", "method": method})

    def initialize(self):
        st, body = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                           "clientInfo": {"name": "swda-demo-client", "version": "0.1"}})
        self.notify("notifications/initialized")
        return st, body

    def call_tool(self, name: str, arguments: dict):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})
