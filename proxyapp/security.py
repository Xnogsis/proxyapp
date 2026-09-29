"""Security: credential store (PBKDF2), client ACLs, destination filtering,
connection limits, bandwidth throttling, audit logging."""
from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import is_ip
from .store import _atomic_write, _read_json, data_path

PBKDF2_ITERATIONS = 210_000


# --- users ------------------------------------------------------------------

def _hash_password(password: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations).hex()


class UserStore:
    def __init__(self, path: Path | None = None):
        self.path = path or data_path("users.json")
        self._users: dict[str, dict] = _read_json(self.path, {})

    @property
    def require_auth(self) -> bool:
        return bool(self._users)

    def names(self) -> list[str]:
        return sorted(self._users)

    def add(self, name: str, password: str) -> None:
        if not name or ":" in name:
            raise ValueError("invalid user name")
        if not password:
            raise ValueError("empty password")
        salt = secrets.token_bytes(16)
        self._users[name] = {
            "salt": salt.hex(),
            "hash": _hash_password(password, salt, PBKDF2_ITERATIONS),
            "iterations": PBKDF2_ITERATIONS,
        }
        _atomic_write(self.path, self._users)

    def remove(self, name: str) -> bool:
        if self._users.pop(name, None) is not None:
            _atomic_write(self.path, self._users)
            return True
        return False

    def verify(self, name: str, password: str) -> bool:
        rec = self._users.get(name)
        if rec is None:
            # equalize timing against user-enumeration
            _hash_password(password, b"\x00" * 16, PBKDF2_ITERATIONS)
            return False
        salt = bytes.fromhex(rec["salt"])
        expected = _hash_password(password, salt, rec.get("iterations", PBKDF2_ITERATIONS))
        return hmac.compare_digest(expected, rec["hash"])


# --- client ACL ---------------------------------------------------------------

class ACL:
    """Deny-list checked first; if allow-list is non-empty it must match."""

    def __init__(self, allow: list[str], deny: list[str]):
        self.allow = [ipaddress.ip_network(c, strict=False) for c in allow]
        self.deny = [ipaddress.ip_network(c, strict=False) for c in deny]

    def allowed(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if any(ip in net for net in self.deny):
            return False
        if self.allow:
            return any(ip in net for net in self.allow)
        return True


# --- destination filtering ----------------------------------------------------

def _domain_match(patterns: list[str], host: str) -> bool:
    host = host.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().strip()
        if not pat:
            continue
        if pat.startswith("*."):
            base = pat[2:]
            if host == base or host.endswith("." + base) or fnmatch.fnmatch(host, pat):
                return True
        elif fnmatch.fnmatch(host, pat):
            return True
    return False


class DestFilter:
    """Decides whether a CONNECT target is permitted. Returns a reason string
    when blocked, None when allowed."""

    def __init__(self, cfg: dict):
        self.allow_private = bool(cfg.get("allow_private_dest"))
        self.blocked_ports = set(cfg.get("blocked_ports") or [])
        self.allowed_ports = set(cfg.get("allowed_ports") or [])
        self.deny_domains = list(cfg.get("deny_domains") or [])
        self.allow_domains = list(cfg.get("allow_domains") or [])

    def check(self, host: str, port: int) -> str | None:
        if self.allowed_ports and port not in self.allowed_ports:
            return f"port {port} not in allowed_ports"
        if port in self.blocked_ports:
            return f"port {port} blocked"

        if is_ip(host):
            ip = ipaddress.ip_address(host)
            if not self.allow_private and (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified
            ):
                return f"private/reserved address {ip}"
            return None

        # domain target
        if self.allow_domains and not _domain_match(self.allow_domains, host):
            return f"domain {host} not in allow_domains"
        if _domain_match(self.deny_domains, host):
            return f"domain {host} denied"
        return None


# --- rate limiting ------------------------------------------------------------

class ConnLimiter:
    def __init__(self, per_ip: int, total: int):
        self.per_ip = per_ip
        self.total = total
        self._by_ip: dict[str, int] = {}
        self._total = 0

    def acquire(self, ip: str) -> bool:
        if self._total >= self.total:
            return False
        if self._by_ip.get(ip, 0) >= self.per_ip:
            return False
        self._by_ip[ip] = self._by_ip.get(ip, 0) + 1
        self._total += 1
        return True

    def release(self, ip: str) -> None:
        self._total = max(0, self._total - 1)
        n = self._by_ip.get(ip, 0) - 1
        if n <= 0:
            self._by_ip.pop(ip, None)
        else:
            self._by_ip[ip] = n


class Bucket:
    """Token bucket: caps a connection at `rate` bytes/sec (shared across both
    directions — simple and conservative)."""

    def __init__(self, rate: float):
        self.rate = rate
        self.allowance = rate
        self.ts = time.monotonic()

    async def take(self, n: int) -> None:
        while True:
            now = time.monotonic()
            self.allowance = min(self.rate, self.allowance + (now - self.ts) * self.rate)
            self.ts = now
            if self.allowance >= n:
                self.allowance -= n
                return
            await asyncio.sleep(min(1.0, (n - self.allowance) / self.rate))


# --- audit log -----------------------------------------------------------------

class AuditLog:
    """Append-only JSONL audit trail."""

    def __init__(self, path: Path | None = None):
        self.path = path or data_path("audit.log")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields) -> None:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "event": event, **fields}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def tail(self, n: int = 50) -> list[dict]:
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 256 * 1024))  # read last 256KB max
                lines = f.read().decode("utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
