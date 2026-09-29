"""Persistence: proxy pool, users, config — JSON files under data/ (override
the directory with the PROXYAPP_HOME env var)."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import Proxy

DATA_DIR = Path(os.environ.get("PROXYAPP_HOME", "data"))


def data_path(name: str) -> Path:
    return DATA_DIR / name


def _atomic_write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=1)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _read_json(path: Path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


DEFAULT_CONFIG = {
    "bind_host": "127.0.0.1",
    "bind_port": 1080,
    "strategy": "round-robin",        # round-robin | random | fastest | ordered | sticky
    "connect_timeout": 10.0,          # upstream connect+handshake deadline (s)
    "handshake_timeout": 10.0,        # client greeting/auth/request deadline (s)
    "idle_timeout": 300.0,            # drop tunnels idle this long (s)
    "retries": 3,                     # upstreams to try per client CONNECT
    "max_conn_total": 500,
    "max_conn_per_ip": 50,
    "bandwidth_kbps": 0,              # per-connection cap, 0 = unlimited
    "allow_private_dest": False,      # allow CONNECT to RFC1918/loopback/etc
    "blocked_ports": [25],
    "allowed_ports": [],              # empty = all (minus blocked)
    "deny_domains": [],               # fnmatch patterns, e.g. "*.example.com"
    "allow_domains": [],              # empty = all (minus denied)
    "acl_allow": [],                  # client CIDRs; empty = all clients
    "acl_deny": [],                   # client CIDRs, checked first
    "check_target": "api.ipify.org:80",
    "check_timeout": 8.0,
    "check_concurrency": 100,
    "auto_disable_failures": 10,      # consecutive failures -> auto-disable; 0 = never
    "audit_log": "audit.log",
}


class Store:
    """Proxy pool backed by pool.json. Pass path=None for in-memory use."""

    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else data_path("pool.json")
        self._mtime: float | None = None
        self.proxies: dict[str, Proxy] = {}
        self.reload()

    def reload(self) -> bool:
        """Load from disk if the file changed. Returns True if reloaded."""
        try:
            mtime = self.path.stat().st_mtime
        except (FileNotFoundError, OSError):
            if self.proxies:
                self.proxies = {}
                self._mtime = None
                return True
            return False
        if self._mtime == mtime:
            return False
        items = _read_json(self.path, [])
        self.proxies = {}
        for d in items:
            try:
                p = Proxy.from_dict(d)
                self.proxies[p.key] = p
            except (ValueError, TypeError):
                continue
        self._mtime = mtime
        return True

    def save(self) -> None:
        _atomic_write(self.path, [p.to_dict() for p in self.proxies.values()])
        try:
            self._mtime = self.path.stat().st_mtime
        except OSError:
            pass

    def all(self) -> list[Proxy]:
        return list(self.proxies.values())

    def add(self, p: Proxy) -> bool:
        """Add if not a duplicate. Returns True when added."""
        if p.key in self.proxies:
            return False
        self.proxies[p.key] = p
        return True

    def remove(self, key: str) -> bool:
        return self.proxies.pop(key, None) is not None

    def find(self, ident: str) -> Proxy | None:
        """Resolve a user-supplied id: 'host:port' or 'user@host:port'."""
        ident = ident.strip()
        if ident in self.proxies:
            return self.proxies[ident]
        p = self.proxies.get(f"@{ident.lower()}")
        if p:
            return p
        low = ident.lower()
        for p in self.proxies.values():
            if p.id.lower() == low:
                return p
        # bare 'host:port' should also match an authed proxy
        if "@" not in ident:
            return next((p for p in self.proxies.values()
                         if f"{p.host.lower()}:{p.port}" == low), None)
        return None


class Config:
    def __init__(self, path: Path | None = None):
        self.path = path or data_path("config.json")
        self._data = dict(DEFAULT_CONFIG)
        self._data.update({k: v for k, v in _read_json(self.path, {}).items()
                           if k in DEFAULT_CONFIG})

    def get(self, key: str):
        return self._data[key]

    def set(self, key: str, value) -> None:
        if key not in DEFAULT_CONFIG:
            raise KeyError(f"unknown config key {key!r}")
        self._data[key] = value
        _atomic_write(self.path, self._data)

    def as_dict(self) -> dict:
        return dict(self._data)
