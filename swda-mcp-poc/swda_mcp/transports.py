"""Transports: stdio (newline-delimited JSON-RPC) and Streamable-HTTP-style POST /mcp (JSON responses)."""
from __future__ import annotations
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .gateway import MCPGateway, E_RATE, _err
from .security import ClientDirectory

MAX_BODY = 64 * 1024


def serve_stdio(gw: MCPGateway, clients: ClientDirectory, stdin=sys.stdin, stdout=sys.stdout):
    """Local trusted-process transport. Identity comes from SWDA_MCP_TOKEN set by the launching host."""
    client = clients.authenticate(os.environ.get("SWDA_MCP_TOKEN"))
    if client is None:
        sys.stderr.write("SWDA_MCP_TOKEN missing or invalid\n")
        sys.exit(2)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = gw.handle(json.loads(line), client)
        except json.JSONDecodeError:
            resp = _err(None, -32700, "Parse error")
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def make_http_server(gw: MCPGateway, clients: ClientDirectory, host="127.0.0.1", port=8808,
                     allowed_origins: frozenset[str] = frozenset()) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "swda-mcp/0.1"

        def log_message(self, *a):  # access logs go through the audit log, not stderr noise
            pass

        def _send(self, status, body: bytes, ctype="application/json", extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj, extra=None):
            self._send(status, json.dumps(obj).encode(), extra=extra)

        def do_GET(self):
            if self.path == "/healthz":
                return self._json(200, {"status": "ok", "approved_agents": len(gw._exposed())})
            if self.path == "/metrics":
                return self._send(200, gw.metrics.render().encode(), "text/plain; version=0.0.4")
            if self.path == "/mcp":
                return self._json(405, {"error": "SSE stream not offered; use POST"}, {"Allow": "POST"})
            self._json(404, {"error": "not found"})

        def do_DELETE(self):
            self._json(405, {"error": "sessions are stateless"}, {"Allow": "POST"})

        def do_POST(self):
            if self.path != "/mcp":
                return self._json(404, {"error": "not found"})
            # DNS-rebinding / browser-origin protection required by the MCP transport spec
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                gw.audit.write("http_rejected", reason="origin_not_allowed")
                return self._json(403, {"error": "origin not allowed"})
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else None
            client = clients.authenticate(token)
            if client is None:
                gw.audit.write("http_rejected", reason="unauthenticated")
                return self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": 'Bearer realm="swda-mcp"'})
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._json(413, _err(None, -32600, "Body missing or too large"))
            try:
                msg = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                return self._json(400, _err(None, -32700, "Parse error"))
            resp = gw.handle(msg, client)
            if resp is None:
                return self._send(202, b"")
            if resp.get("error", {}).get("code") == E_RATE:
                return self._json(429, resp, {"Retry-After": "10"})
            self._json(200, resp)

    return ThreadingHTTPServer((host, port), Handler)


def run_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
