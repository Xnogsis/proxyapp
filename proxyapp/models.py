"""Proxy entry model and proxy-list line parsing.

Accepted line formats:
    socks5://host:port
    socks5://user:pass@host:port        (also socks5h://)
    host:port
    host:port:user:pass
    user:pass@host:port
    [v6addr]:port                       (bare IPv6 must be bracketed or use a scheme)
Blank lines and lines starting with '#' are skipped by parsers that use
parse_proxy (they raise ValueError, callers decide whether to skip).
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, unquote

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)[a-zA-Z0-9*]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_port(s: str) -> int:
    try:
        port = int(s, 10)
    except (TypeError, ValueError):
        raise ValueError(f"bad port {s!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _split_host_port(addr: str):
    addr = addr.strip()
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError(f"missing port in {addr!r}")
        return host, _parse_port(rest[1:])
    host, sep, port = addr.rpartition(":")
    if not sep:
        raise ValueError(f"missing port in {addr!r}")
    if ":" in host:  # unbracketed IPv6
        raise ValueError("IPv6 addresses must be bracketed: [addr]:port")
    return host, _parse_port(port)


def _valid_host(host: str) -> str:
    host = host.strip().strip("[]")
    if not host:
        raise ValueError("empty host")
    if is_ip(host) or HOSTNAME_RE.match(host):
        return host
    raise ValueError(f"invalid host {host!r}")


@dataclass
class Proxy:
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    scheme: str = "socks5"
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    added_at: float = field(default_factory=time.time)
    checked_at: float | None = None
    alive: bool | None = None            # None = never tested
    latency_ms: float | None = None
    exit_ip: str | None = None
    tls_ok: bool | None = None           # False = proxy tampers with TLS (MITM)
    leaks: bool | None = None            # True = exit IP equals your real IP
    country: str | None = None           # 2-letter code of the exit IP
    successes: int = 0
    failures: int = 0
    consec_failures: int = 0
    last_error: str | None = None

    def __post_init__(self):
        self.host = _valid_host(self.host)
        self.port = _parse_port(str(self.port))

    @property
    def key(self) -> str:
        """Unique identity: credentials + endpoint."""
        return f"{self.username or ''}@{self.host.lower()}:{self.port}"

    @property
    def id(self) -> str:
        return f"{self.username}@{self.host}:{self.port}" if self.username else f"{self.host}:{self.port}"

    @property
    def status(self) -> str:
        if self.alive is None:
            return "untested"
        if self.alive and self.leaks:
            return "LEAK"
        if self.alive and self.tls_ok is False:
            return "MITM"
        return "alive" if self.alive else "dead"

    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        return self.successes / total if total else 0.0

    def score(self) -> float:
        """Lower is better: latency penalised by historical failure rate."""
        latency = self.latency_ms if self.latency_ms is not None else 10_000.0
        return latency * (2.0 - self.success_rate)

    def to_uri(self, hide_password: bool = False) -> str:
        auth = ""
        if self.username:
            pw = "***" if hide_password else (self.password or "")
            auth = f"{self.username}:{pw}@"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{auth}{host}:{self.port}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Proxy":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def parse_proxy(line: str) -> Proxy:
    s = line.strip()
    if not s:
        raise ValueError("empty line")
    if s.startswith("#"):
        raise ValueError("comment")

    if "://" in s:
        u = urlsplit(s)
        scheme = u.scheme.lower()
        if scheme not in ("socks5", "socks5h"):
            raise ValueError(f"unsupported scheme {u.scheme!r}")
        if not u.hostname or u.port is None:
            raise ValueError(f"missing host/port in {s!r}")
        return Proxy(
            host=u.hostname, port=u.port, scheme=scheme,
            username=unquote(u.username) if u.username else None,
            password=unquote(u.password) if u.password else None,
        )

    if "@" in s:  # user:pass@host:port
        creds, _, addr = s.rpartition("@")
        host, port = _split_host_port(addr)
        user, _, pw = creds.partition(":")
        return Proxy(host=host, port=port, username=user or None, password=pw or None)

    parts = s.split(":")
    if len(parts) == 2:  # host:port
        host, port = _split_host_port(s)
        return Proxy(host=host, port=port)
    if len(parts) == 4:  # host:port:user:pass (common list format)
        host, port, user, pw = parts
        return Proxy(host=host, port=_parse_port(port), username=user or None, password=pw or None)
    if len(parts) > 4 and is_ip(s.rsplit(":", 1)[0]):
        raise ValueError("bracket IPv6 addresses: [addr]:port")
    raise ValueError(f"unrecognised format {s!r}")


def parse_lines(text: str):
    """Yield (lineno, Proxy|None, error|None) for each non-blank line."""
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        try:
            yield i, parse_proxy(raw), None
        except ValueError as e:
            yield i, None, f"line {i}: {e}"


# --- sorting / grouping -----------------------------------------------------

def sort_key(name: str):
    def ip_key(p: Proxy):
        try:
            ip = ipaddress.ip_address(p.host)
            return (0, ip.version, int(ip))
        except ValueError:
            return (1, 0, p.host.lower())

    keys = {
        "ip": ip_key,
        "host": lambda p: p.host.lower(),
        "port": lambda p: (p.port, p.host.lower()),
        "latency": lambda p: (p.latency_ms is None, p.latency_ms or 0),
        "added": lambda p: p.added_at,
        "score": lambda p: p.score(),
        "success": lambda p: (-p.success_rate, p.latency_ms or 1e9),
        "checked": lambda p: (p.checked_at is None, p.checked_at or 0),
        "country": lambda p: (p.country is None, p.country or ""),
        "status": lambda p: {"alive": 0, "untested": 1, "LEAK": 2, "MITM": 3,
                             "dead": 4}[p.status],
    }
    if name not in keys:
        raise ValueError(f"unknown sort key {name!r}; choose from {', '.join(sorted(keys))}")
    return keys[name]


def group_key(name: str):
    def subnet(p: Proxy) -> str:
        try:
            ip = ipaddress.ip_address(p.host)
            net = ipaddress.ip_network(f"{ip}/{'24' if ip.version == 4 else '64'}", strict=False)
            return str(net)
        except ValueError:
            labels = p.host.lower().split(".")
            return ".".join(labels[-2:]) if len(labels) >= 2 else p.host.lower()

    keys = {
        "subnet": subnet,
        "port": lambda p: str(p.port),
        "status": lambda p: p.status,
        "tag": lambda p: ",".join(sorted(p.tags)) if p.tags else "(untagged)",
        "scheme": lambda p: p.scheme,
        "auth": lambda p: "with-auth" if p.username else "no-auth",
    }
    if name not in keys:
        raise ValueError(f"unknown group key {name!r}; choose from {', '.join(sorted(keys))}")
    return keys[name]
