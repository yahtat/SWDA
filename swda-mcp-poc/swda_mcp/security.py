"""Authentication, rate limiting and PII redaction primitives."""
from __future__ import annotations
import hashlib, hmac, json, re, threading, time
from dataclasses import dataclass, field
from pathlib import Path

# ---------- PII redaction (applied to anything that reaches logs) ----------
_PII_PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"\b[A-Z]\d{7}[A-Z]\b"), "[NATIONAL_ID]"),   # synthetic national-id shape
    (re.compile(r"(?<!\w)\+?\d[\d\s-]{6,}\d(?!\w)"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pat, repl in _PII_PATTERNS:
        text = pat.sub(repl, text)
    return text


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------- Client identity ----------
@dataclass(frozen=True)
class Client:
    client_id: str
    scopes: frozenset[str]
    rate_limit_per_min: int


class ClientDirectory:
    """Maps bearer tokens to client identities. Only SHA-256 digests are stored.

    Production: replace with OIDC/JWT validation against the enterprise IdP
    (audience-bound tokens, short TTL, mTLS between gateway and clients).
    """

    def __init__(self, path: Path):
        raw = json.loads(Path(path).read_text())
        self._by_hash = {
            c["token_sha256"]: Client(c["client_id"], frozenset(c["scopes"]), c.get("rate_limit_per_min", 60))
            for c in raw["clients"]
        }

    def authenticate(self, token: str | None) -> Client | None:
        if not token:
            return None
        digest = sha256_hex(token)
        for known, client in self._by_hash.items():
            if hmac.compare_digest(known, digest):
                return client
        return None


# ---------- Rate limiting ----------
@dataclass
class _Bucket:
    tokens: float
    updated: float = field(default_factory=time.monotonic)


class RateLimiter:
    """Token bucket per client. Thread-safe."""

    def __init__(self, clock=time.monotonic):
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def allow(self, key: str, per_minute: int) -> bool:
        now = self._clock()
        with self._lock:
            b = self._buckets.setdefault(key, _Bucket(tokens=float(per_minute), updated=now))
            b.tokens = min(per_minute, b.tokens + (now - b.updated) * per_minute / 60.0)
            b.updated = now
            if b.tokens >= 1:
                b.tokens -= 1
                return True
            return False
