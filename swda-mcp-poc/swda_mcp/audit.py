"""Tamper-evident audit log: append-only JSONL where each record embeds the hash of the previous one.

Production mapping: ship the same records to CloudWatch Logs / Kinesis Firehose -> S3 Object Lock
(WORM) and a Delta table `governance.audit.mcp_invocations`; keep the hash chain as an integrity check.
No raw free-text or PII is ever written: only digests and redacted summaries.
"""
from __future__ import annotations
import json, threading, time
from pathlib import Path
from .security import canonical_json, sha256_hex

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text().strip().splitlines()[-1]
        return json.loads(last)["hash"]

    def write(self, event: str, **fields) -> dict:
        with self._lock:
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields, "prev": self._last}
            rec["hash"] = sha256_hex(canonical_json(rec))
            with self.path.open("a") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._last = rec["hash"]
            return rec

    @staticmethod
    def verify(path: Path) -> tuple[bool, int, str]:
        """Returns (ok, records_checked, message)."""
        prev, n = GENESIS, 0
        for line in Path(path).read_text().splitlines():
            rec = json.loads(line)
            claimed = rec.pop("hash")
            if rec["prev"] != prev or sha256_hex(canonical_json(rec)) != claimed:
                return False, n, f"chain broken at record {n + 1}"
            prev, n = claimed, n + 1
        return True, n, "chain intact"
