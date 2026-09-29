r"""proxytui - pick a SOCKS5 proxy, route your traffic through it.

    python proxytui.py [list.txt | folder ...]

With no arguments, every .txt file in the proxys\ subfolder (plus proxies.txt)
is loaded; files without any valid proxy line are skipped. Duplicates merge.

Keys:
  Up/Down      move           Enter   route through selected proxy
  Esc          disconnect (stop routing + restore Windows proxy setting)
  t            detailed test  c       check all  a  auto-connect + system proxy
  e            save working proxies to proxys\working.txt
  w            toggle Windows system proxy (needs a routed proxy)
  k            toggle kill-switch (block all traffic if every proxy dies)
  Tab          proxies/logs view   r  reload proxys\ folder (adds new files/lines)
  l            load file/folder    v  paste list from clipboard
  s            cycle sort     d       delete selected
  x            drop dead/MITM/LEAK  q  quit (stops routing, restores system proxy)

Security: local endpoint binds 127.0.0.1 only and speaks SOCKS5, SOCKS4/4a and
HTTP (CONNECT + absolute-URI GET), never falls back to a direct
connection, blocks CONNECTs to private/LAN addresses, detects proxies that
intercept TLS (fake certs) and refuses to route through them, auto-fails over
to the next alive proxy, and the Windows proxy setting is restored on exit,
on Ctrl+C, and even when the console window is closed.
"""
from __future__ import annotations

import asyncio
import atexit
import ctypes
import ipaddress
import json
import msvcrt
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import winreg
from urllib.parse import urlsplit
from collections import deque
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proxyapp import socks                       # noqa: E402
from proxyapp.checker import check_many, check_proxy, check_tls, _BODY_IP_RE  # noqa: E402
from proxyapp.models import Proxy, parse_lines, sort_key  # noqa: E402
from proxyapp.store import _atomic_write          # noqa: E402

LOCAL_HOST, LOCAL_PORT = "127.0.0.1", 1080
HERE = Path(__file__).resolve().parent
STATE_FILE = HERE / "data" / "tui_state.json"
LOG_FILE = HERE / "data" / "proxytui.log"
LOG_MAX_BYTES = 1_000_000
PROXY_DIR = HERE / "proxys"        # every *.txt in here is loaded at startup / on r
WORKING_FILE = PROXY_DIR / "working.txt"
RESULTS_FILE = HERE / "data" / "tui_results.json"
GEO_URL = "http://ip-api.com/batch?fields=status,countryCode,query"
MAX_LIST_BYTES = 20_000_000
SORTS = ["latency", "ip", "port", "status", "country"]
IP_CHECK_HOST, IP_CHECK_PORT = "api.ipify.org", 80
TLS_CHECK_HOST = "example.com"
NET_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 53))
FAILOVER_AFTER = 3
HELP = ("Enter route  Esc disconnect  a auto-connect  t test  c check all  w sysproxy",
        "k kill-switch  Tab logs  r reload  l load  v paste  s sort  d del  "
        "x drop bad  e save working  q quit")

# --- logging -------------------------------------------------------------------

class Log:
    """Thread-safe timestamped log: file + in-memory tail for the Logs view."""

    def __init__(self, path: Path = LOG_FILE, max_bytes: int = LOG_MAX_BYTES):
        self.path = path
        self.max_bytes = max_bytes
        self.lines: deque = deque(maxlen=1000)
        self.lock = threading.Lock()
        try:
            self.path.parent.mkdir(exist_ok=True)
        except OSError:
            pass

    def write(self, level: str, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.lines.append((ts, level, msg))
            try:
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    self.path.replace(self.path.with_name(self.path.name + ".1"))
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(f"{ts} {level} {msg}\n")
            except OSError:
                pass

    def info(self, msg: str):
        self.write("INFO", msg)

    def warn(self, msg: str):
        self.write("WARN", msg)

    def error(self, msg: str):
        self.write("ERROR", msg)


# --- Windows system proxy ------------------------------------------------------

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_wininet = ctypes.windll.wininet


def _refresh_wininet():
    _wininet.InternetSetOptionW(None, 39, None, 0)  # SETTINGS_CHANGED
    _wininet.InternetSetOptionW(None, 37, None, 0)  # REFRESH


def sysproxy_read() -> dict:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH) as k:
        out = {}
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                out[name] = winreg.QueryValueEx(k, name)[0]
            except FileNotFoundError:
                out[name] = None
        return out


def sysproxy_write(enable: bool, server: str | None = None, override: str | None = None):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        for name, val in (("ProxyServer", server), ("ProxyOverride", override)):
            if val is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
    _refresh_wininet()


SYS_PROXY_OVERRIDE = ("<local>;localhost;127.*;10.*;192.168.*;169.254.*;"
                      "172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;"
                      "172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;"
                      "172.28.*;172.29.*;172.30.*;172.31.*")


class SysProxy:
    """Applies 127.0.0.1:1080 as a plain HTTP proxy system-wide and guarantees
    restore. A 'socks=' value would be interpreted as SOCKS4 by WinINet, so we
    use the HTTP form - the destination hostname still goes to the proxy."""

    def __init__(self):
        self.active = False
        self.saved: dict | None = None
        # crash recovery: restore leftovers from a previous run
        if STATE_FILE.exists():
            try:
                saved = json.loads(STATE_FILE.read_text())
                sysproxy_write(bool(saved["ProxyEnable"]), saved["ProxyServer"],
                               saved["ProxyOverride"])
            except (OSError, KeyError, ValueError):
                pass
            STATE_FILE.unlink(missing_ok=True)

    def enable(self):
        if self.active:
            return
        self.saved = sysproxy_read()
        STATE_FILE.parent.mkdir(exist_ok=True)
        STATE_FILE.write_text(json.dumps(self.saved))
        sysproxy_write(True, f"{LOCAL_HOST}:{LOCAL_PORT}", SYS_PROXY_OVERRIDE)
        self.active = True

    def disable(self):
        if not self.active:
            return
        s = self.saved or {"ProxyEnable": 0, "ProxyServer": None, "ProxyOverride": None}
        sysproxy_write(bool(s["ProxyEnable"]), s["ProxyServer"], s["ProxyOverride"])
        STATE_FILE.unlink(missing_ok=True)
        self.active = False


# --- connectivity probe ---------------------------------------------------------

def internet_ok(timeout: float = 3.0) -> bool:
    """Direct TCP probe (no proxy): True if any well-known host is reachable."""
    for host, port in NET_PROBES:
        try:
            with socket.create_connection((host, port), timeout):
                return True
        except OSError:
            continue
    return False


def geo_lookup(ips: list[str]) -> dict[str, str]:
    """IP -> 2-letter country via ip-api.com batch (max 100/request).
    Only proxy IPs are sent - never any of the user's traffic."""
    req = urllib.request.Request(GEO_URL, data=json.dumps(ips[:100]).encode(),
                                 headers={"Content-Type": "application/json"})
    out = {}
    with urllib.request.urlopen(req, timeout=10) as resp:
        for item in json.loads(resp.read()):
            if item.get("status") == "success" and item.get("countryCode"):
                out[item["query"]] = item["countryCode"]
    return out


def _ago(ts: float | None) -> str:
    if not ts:
        return "?"
    d = max(0, time.time() - ts)
    if d < 60:
        return f"{int(d)}s ago"
    if d < 3600:
        return f"{int(d / 60)}m ago"
    if d < 86400:
        return f"{int(d / 3600)}h ago"
    return f"{int(d / 86400)}d ago"


# --- local forwarder -------------------------------------------------------------

_S4_GRANTED = bytes([0x00, 0x5A, 0, 0, 0, 0, 0, 0])
_S4_REJECTED = bytes([0x00, 0x5B, 0, 0, 0, 0, 0, 0])


def _http_status(code: int, text: str) -> bytes:
    return (f"HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\n"
            f"Connection: close\r\n\r\n").encode()


async def _read_cstr(r: asyncio.StreamReader, limit: int = 255) -> str | None:
    """Read a NUL-terminated string (SOCKS4 userid/domain). None if over limit."""
    buf = bytearray()
    while len(buf) <= limit:
        b = await r.readexactly(1)
        if b == b"\x00":
            return buf.decode("utf-8", "replace")
        buf += b
    return None


class Forwarder:
    """127.0.0.1:1080 multi-protocol endpoint (SOCKS5/SOCKS4a/HTTP) tunnelling
    everything via one upstream."""

    def __init__(self):
        self.upstream: Proxy | None = None
        self.server: asyncio.AbstractServer | None = None
        self.active = 0
        self.total = 0
        self.errors = 0
        self.last_error = ""
        self.fail_count = 0
        self.fail_upstream: Proxy | None = None
        self.on_fail = None          # called with a proxy that failed FAILOVER_AFTERx
        self.on_no_upstream = None   # called when a client arrives with no upstream
        self.log: Log | None = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, LOCAL_HOST, LOCAL_PORT)

    def _log(self, level: str, msg: str):
        if self.log:
            try:
                self.log.write(level, msg)
            except Exception:  # noqa: BLE001
                pass

    # -- dispatch on the first byte --
    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            b = (await asyncio.wait_for(r.readexactly(1), 10))[0]
            if b == socks.VER:
                await self._socks5(r, w)
            elif b == 0x04:
                await self._socks4(r, w)
            elif chr(b).isalpha():
                await self._http(r, w, bytes([b]))
            else:
                self._log("WARN", f"unknown protocol byte {b:#04x}")
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                ConnectionError, OSError):
            pass  # client went away or went idle
        except Exception as e:  # noqa: BLE001
            self._log("WARN", f"handler error {type(e).__name__}: {e}")
        finally:
            try:
                w.close()
            except OSError:
                pass

    # -- shared upstream tunnel --
    async def _tunnel(self, r, w, host, port, proto: str, reply: dict,
                      send_first: bytes = b""):
        """private check -> no-upstream -> upstream open -> failover -> pipe.
        reply = {"ok","private","noups","bad"}: sync writers onto w."""
        if _is_private(host):
            self._log("WARN", f"blocked private destination {host}:{port} ({proto})")
            reply["private"]()
            return
        up = self.upstream
        if up is None:  # no upstream -> refuse, never go direct
            self._log("WARN", f"CONNECT {host}:{port} refused: no upstream ({proto})")
            reply["noups"]()
            if self.on_no_upstream:
                try:
                    self.on_no_upstream()
                except Exception:  # noqa: BLE001
                    pass
            return
        uw = None
        try:
            try:
                ur, uw = await asyncio.wait_for(
                    asyncio.open_connection(up.host, up.port), 10)
                await socks.client_connect(ur, uw, host, port,
                                           up.username, up.password, 10)
            except Exception as e:  # noqa: BLE001
                self.errors += 1
                self.last_error = f"{host}:{port}: {e}"
                if self.fail_upstream is up:
                    self.fail_count += 1
                else:
                    self.fail_upstream, self.fail_count = up, 1
                self._log("INFO", f"CONNECT {host}:{port} via {up.id} "
                                  f"FAILED ({proto}): {e}")
                if self.fail_count >= FAILOVER_AFTER and self.on_fail:
                    try:
                        self.on_fail(up)
                    except Exception:  # noqa: BLE001
                        pass
                reply["bad"]()
                return
            self.fail_count = 0
            self.fail_upstream = None
            if send_first:
                uw.write(send_first)
            reply["ok"]()
            await w.drain()
            await uw.drain()
            self.active += 1
            self.total += 1
            t0 = time.monotonic()
            try:
                n_up, n_down = await asyncio.gather(_pipe(r, uw), _pipe(ur, w))
            finally:
                self.active -= 1
            self._log("INFO", f"CONNECT {host}:{port} via {up.id} ok ({proto}) "
                              f"up={n_up} down={n_down} {time.monotonic() - t0:.1f}s")
        finally:
            if uw is not None:
                try:
                    uw.close()
                except OSError:
                    pass

    # -- SOCKS5 --
    async def _socks5(self, r, w):
        (n,) = await asyncio.wait_for(r.readexactly(1), 10)  # version already read
        methods = list(await asyncio.wait_for(r.readexactly(n), 10))
        if socks.METHOD_NOAUTH not in methods:
            w.write(bytes([socks.VER, socks.METHOD_NONE]))
            return
        w.write(bytes([socks.VER, socks.METHOD_NOAUTH]))
        await w.drain()
        cmd, host, port = await asyncio.wait_for(socks.read_request(r), 10)
        if cmd != socks.CMD_CONNECT:
            w.write(socks.pack_reply(socks.REP_CMD_UNSUPPORTED))
            return
        await self._tunnel(r, w, host, port, "socks5", {
            "ok": lambda: w.write(socks.pack_reply(socks.REP_OK)),
            "private": lambda: w.write(socks.pack_reply(socks.REP_NOT_ALLOWED)),
            "noups": lambda: w.write(socks.pack_reply(socks.REP_NET_UNREACHABLE)),
            "bad": lambda: w.write(socks.pack_reply(socks.REP_HOST_UNREACHABLE)),
        })

    # -- SOCKS4 / 4a --
    async def _socks4(self, r, w):
        # version byte already consumed: CMD(1) DSTPORT(2) DSTIP(4) USERID\0 [DOMAIN\0]
        cmd, port, raw_ip = struct.unpack("!BH4s", await asyncio.wait_for(
            r.readexactly(7), 10))
        if cmd != 1:  # only CONNECT supported (BIND etc. rejected)
            w.write(_S4_REJECTED)
            return
        if await _read_cstr(r) is None:  # USERID over limit -> reject
            w.write(_S4_REJECTED)
            return
        if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:  # SOCKS4a
            host = await _read_cstr(r)
            if host is None:
                w.write(_S4_REJECTED)
                return
        else:
            host = str(ipaddress.IPv4Address(raw_ip))
        await self._tunnel(r, w, host, port, "socks4", {
            "ok": lambda: w.write(_S4_GRANTED),
            "private": lambda: w.write(_S4_REJECTED),
            "noups": lambda: w.write(_S4_REJECTED),
            "bad": lambda: w.write(_S4_REJECTED),
        })

    # -- HTTP proxy --
    async def _http(self, r, w, first: bytes):
        head = first + await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
        try:
            text = head.decode("iso-8859-1")
            reqline, hdrs = text.split("\r\n", 1)
            method, target, ver = reqline.split(" ", 2)
        except ValueError:
            w.write(_http_status(400, "Bad Request"))
            return
        method = method.upper()
        if method == "CONNECT":
            host, _, p = target.rpartition(":")
            host = host.strip("[]")
            if not host or not p.isdigit():
                w.write(_http_status(400, "Bad Request"))
                return
            await self._tunnel(r, w, host, int(p), "http", {
                "ok": lambda: w.write(b"HTTP/1.1 200 Connection established\r\n\r\n"),
                "private": lambda: w.write(_http_status(403, "Forbidden")),
                "noups": lambda: w.write(_http_status(503, "No Upstream")),
                "bad": lambda: w.write(_http_status(502, "Bad Gateway")),
            })
            return
        if not target.lower().startswith("http://"):
            w.write(_http_status(400, "Bad Request"))
            return
        u = urlsplit(target)
        host = u.hostname
        port = u.port or 80
        if not host:
            w.write(_http_status(400, "Bad Request"))
            return
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        drop = {"proxy-connection", "proxy-authorization", "connection"}
        out = [f"{method} {path} {ver}"]
        for line in hdrs.split("\r\n"):
            if not line or ":" not in line:
                continue
            if line.split(":", 1)[0].strip().lower() in drop:
                continue
            out.append(line)
        out.append("Connection: close")
        send_first = ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1")
        await self._tunnel(r, w, host, port, "http", {
            "ok": lambda: None,
            "private": lambda: w.write(_http_status(403, "Forbidden")),
            "noups": lambda: w.write(_http_status(503, "No Upstream")),
            "bad": lambda: w.write(_http_status(502, "Bad Gateway")),
        }, send_first=send_first)


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in ("localhost",) or host.lower().endswith(".local")
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


async def _pipe(r, w) -> int:
    n = 0
    try:
        while data := await r.read(65536):
            n += len(data)
            w.write(data)
            await w.drain()
    except (OSError, ConnectionError):
        pass
    try:
        w.write_eof()
    except (OSError, RuntimeError):
        pass
    return n


# --- console control handler (guaranteed restore on window close) ----------------

_CTRL_HANDLER = None  # module-level reference so the ctypes callback isn't GC'd


def install_ctrl_handler(app) -> "callable":
    """Restore the system proxy on Ctrl+C/Break, window close, logoff, shutdown.
    Returns the underlying Python callable (tests invoke it directly)."""
    global _CTRL_HANDLER
    HANDLER = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

    def _py(event):
        if event in (0, 1, 2, 5, 6):  # C, BREAK, CLOSE, LOGOFF, SHUTDOWN
            try:
                app.sys.disable()
                app.log.info("system proxy restored by console handler")
            except Exception:  # noqa: BLE001
                pass
        if event in (0, 1):
            app.running = False
            return True
        return False

    _CTRL_HANDLER = HANDLER(_py)
    try:
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_CTRL_HANDLER, True)
    except Exception:  # noqa: BLE001
        pass
    return _py


# --- TUI ---------------------------------------------------------------------------

CLR = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
INV = "\x1b[7m"
GREEN, RED, YELLOW, CYAN = "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[36m"

_SNAP_FIELDS = ("alive", "latency_ms", "last_error", "checked_at", "tls_ok",
                "successes", "failures", "consec_failures", "leaks", "country")
# fields persisted in RESULTS_FILE, keyed by Proxy.key
_RES_FIELDS = ("alive", "latency_ms", "exit_ip", "tls_ok", "leaks", "country",
               "checked_at", "last_error", "successes", "failures", "consec_failures")
OFFLINE_MSG = "No internet connection - connect to wifi first; proxies not tested"


def _clipboard() -> str:
    try:
        return subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                              capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


class App:
    def __init__(self, list_path: Path | None):
        self.proxies: list[Proxy] = []
        self.cursor = 0
        self.sort_i = 0
        self.msg = "load a list with l or paste one with v"
        self.checking = False
        self.fwd = Forwarder()
        self.sys = SysProxy()
        self.loop = asyncio.new_event_loop()
        self.running = True
        self.kill_switch = False
        self.online: bool | None = None
        self.view = "proxies"           # or "logs"
        self.log_follow = True          # logs view pinned to the newest entry
        self.log_pos = 0
        self.detail = None              # modal lines while a detailed test shows
        self.stages: dict[str, str] = {}  # proxy key -> current check step
        self._real_ip = None
        self._connecting = False        # auto-connect job running
        self._geo_cache: dict[str, str] = {}
        self.log = Log()
        self.fwd.log = self.log
        self.fwd.on_fail = self.on_fail
        self.fwd.on_no_upstream = self._no_upstream
        atexit.register(self.sys.disable)
        self.log.info("startup")
        if list_path:
            self.load_paths(list_path if isinstance(list_path, list) else [list_path])
            self._apply_results()

    # -- data --
    def load_text(self, text: str, src: str) -> tuple[int, int, int]:
        """Returns (added, duplicates, invalid lines)."""
        seen = {p.key for p in self.proxies}
        n = dup = bad = 0
        for _, p, err in parse_lines(text):
            if err:
                bad += 1
            elif p.key in seen:
                dup += 1
            else:
                seen.add(p.key)
                self.proxies.append(p)
                n += 1
        self.msg = f"loaded {n} from {src}" + (f" ({bad} invalid lines skipped)" if bad else "")
        self.log.info(f"loaded {n} proxies from {src} ({dup} duplicate, {bad} invalid, "
                      f"total {len(self.proxies)})")
        self._apply_results()
        return n, dup, bad

    def load_paths(self, paths: list[Path]):
        """Load .txt files; folders contribute every *.txt inside them.
        Files without a single valid proxy line are skipped."""
        files: list[Path] = []
        for path in paths:
            if path.is_dir():
                files += sorted(f for f in path.iterdir()
                                if f.is_file() and f.suffix.lower() == ".txt")
            elif path.is_file():
                files.append(path)
        added = used = 0
        skipped: list[str] = []
        for f in files:
            try:
                if f.stat().st_size > MAX_LIST_BYTES:
                    raise OSError("file too large")
                text = f.read_text(encoding="utf-8-sig", errors="replace")
            except OSError as e:
                skipped.append(f.name)
                self.log.warn(f"skipped {f}: {e}")
                continue
            if not any(p for _, p, _ in parse_lines(text)):
                skipped.append(f.name)
                self.log.warn(f"skipped {f}: no valid proxy lines")
                continue
            added += self.load_text(text, f.name)[0]
            used += 1
        self.msg = f"loaded {added} new proxies from {used} file(s)"
        if skipped:
            self.msg += f"; skipped (no valid proxies): {', '.join(skipped)}"
        if not files:
            self.msg = f"no .txt files found - put proxy lists in {PROXY_DIR}"
        self._apply_results()

    # -- persisted check results --
    def _apply_results(self):
        """Restore saved check results onto still-untested proxies."""
        try:
            data = json.loads(RESULTS_FILE.read_text())
        except (OSError, ValueError):
            return
        n = newest = 0
        for p in self.proxies:
            d = data.get(p.key)
            if d and p.alive is None:
                for f in _RES_FIELDS:
                    if f in d:
                        setattr(p, f, d[f])
                n += 1
                newest = max(newest, d.get("checked_at") or 0)
        if n:
            self.msg = (f"restored results for {n} proxies "
                        f"(last check {_ago(newest)}) - press c to refresh")

    def _save_results(self):
        """Merge current proxies' results into RESULTS_FILE (atomic)."""
        try:
            try:
                data = json.loads(RESULTS_FILE.read_text())
            except (OSError, ValueError):
                data = {}
            for p in self.proxies:
                data[p.key] = {f: getattr(p, f) for f in _RES_FIELDS}
            _atomic_write(RESULTS_FILE, data)
        except OSError:
            pass

    # -- country lookup --
    async def _geo_missing(self):
        """Fill p.country for alive proxies whose exit/host IP lacks one."""
        ips = []
        for p in self.proxies:
            if not (p.alive and p.country is None):
                continue
            try:
                ip = str(ipaddress.ip_address(p.exit_ip or p.host))
            except ValueError:
                continue
            if ip in self._geo_cache:
                p.country = self._geo_cache[ip]
            elif ip not in ips:
                ips.append(ip)
        if not ips:
            return
        try:
            self._geo_cache.update(await asyncio.to_thread(geo_lookup, ips))
        except Exception as e:  # noqa: BLE001 - geo is best-effort
            self.log.warn(f"geo lookup failed: {e}")
        for p in self.proxies:
            if p.country is None:
                try:
                    ip = str(ipaddress.ip_address(p.exit_ip or p.host))
                except ValueError:
                    continue
                p.country = self._geo_cache.get(ip)

    def sorted(self) -> list[Proxy]:
        return sorted(self.proxies, key=sort_key(SORTS[self.sort_i]))

    # -- async plumbing --
    def run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.fwd.start())
        self.loop.create_task(self._net_monitor())
        self.loop.run_forever()

    async def _net_monitor(self):
        while True:
            ok = await asyncio.to_thread(internet_ok)
            if ok != self.online:
                self.online = ok
                self.log.write("INFO" if ok else "WARN",
                               f"internet {'OK' if ok else 'OFFLINE'}")
            await asyncio.sleep(10)

    async def _check_online(self) -> bool:
        ok = await asyncio.to_thread(internet_ok)
        if ok != self.online:
            self.online = ok
            self.log.write("INFO" if ok else "WARN",
                           f"internet {'OK' if ok else 'OFFLINE'}")
        return ok

    def check_all(self):
        if self.checking or not self.proxies:
            return
        self.checking = True
        self.msg = "checking internet connection before testing proxies"
        total, count = len(self.proxies), {"done": 0}

        def stage(p, text):
            self.stages[p.key] = text
            self.msg = f"checking {p.host}  {text}  [{count['done']}/{total} done]"

        def progress(done, total, p, ok):
            count["done"] = done
            self.stages.pop(p.key, None)
            result = f"OK {p.latency_ms:.0f}ms" if ok else f"FAILED: {p.last_error}"
            self.msg = f"checked {p.host}  {result}  [{done}/{total} done]"

        async def job():
            try:
                if not await self._check_online():
                    self.msg = OFFLINE_MSG
                    self.log.warn("check skipped: no internet")
                    return
                real = await self._fetch_real_ip()
                snap = [(p, tuple(getattr(p, f) for f in _SNAP_FIELDS))
                        for p in self.proxies]
                self.log.info(f"check start: {len(self.proxies)} proxies")
                await check_many(list(self.proxies), timeout=6, concurrency=50,
                                 progress=progress, tls=True, stage=stage)
                alive = sum(1 for p in self.proxies if p.status == "alive")
                mitm = sum(1 for p in self.proxies if p.status == "MITM")
                dead = sum(1 for p in self.proxies if p.status == "dead")
                if alive == 0 and not await self._check_online():
                    for p, vals in snap:
                        for f, v in zip(_SNAP_FIELDS, vals):
                            setattr(p, f, v)
                    self.msg = OFFLINE_MSG
                    self.log.warn("check reverted: connection lost during check")
                    return
                leaks = 0
                for p in self.proxies:
                    if not p.alive:
                        p.leaks = None
                    elif p.exit_ip and real:
                        p.leaks = p.exit_ip == real
                        leaks += bool(p.leaks)
                    else:
                        p.leaks = None
                await self._geo_missing()
                self._save_results()
                alive = sum(1 for p in self.proxies if p.status == "alive")
                self.msg = f"check done: {alive}/{len(self.proxies)} safe"
                if leaks:
                    self.msg += f", {leaks} leak your real IP"
                if mitm:
                    self.msg += f", {mitm} intercept TLS (MITM) - do not use"
                self.log.info(f"check done: {alive} safe, {leaks} leak, "
                              f"{mitm} MITM, {dead} dead")
                if self.fwd.upstream and not self.fwd.upstream.alive:
                    self.msg += "  WARNING: routed proxy is DEAD"
            except Exception as e:  # noqa: BLE001 - surface, don't hang on "checking"
                self.msg = f"check failed: {type(e).__name__}: {e}"
                self.log.error(self.msg)
            finally:
                self.checking = False
                self.stages.clear()
        asyncio.run_coroutine_threadsafe(job(), self.loop)

    # -- failover / kill-switch --
    def on_fail(self, p: Proxy):
        """Forwarder reports FAILOVER_AFTER consecutive upstream failures."""
        p.alive = False
        self._save_results()
        self.log.warn(f"upstream {p.id} failed {FAILOVER_AFTER} connects in a row")
        nxt = min(
            (q for q in self.proxies
             if q is not p and q.status == "alive" and q.tls_ok is not False),
            key=lambda q: q.latency_ms if q.latency_ms is not None else 1e9,
            default=None)
        if nxt is not None:
            self.log.warn(f"failover {p.id} -> {nxt.id}")
            self.fwd.upstream = nxt
            self.msg = f"failover {p.id} -> {nxt.id}"
            return
        self.fwd.upstream = None
        if self.kill_switch:
            self.msg = "all proxies failed - kill-switch blocking traffic"
            self.log.warn("all proxies failed; kill-switch ON, traffic blocked")
        else:
            try:
                self.sys.disable()
            except OSError:
                pass
            self.msg = "all proxies failed - restored direct internet"
            self.log.warn("all proxies failed; system proxy restored to direct")

    def _no_upstream(self):
        """A client connected while nothing is routed."""
        if self.sys.active and not self.kill_switch:
            try:
                self.sys.disable()
                self.log.warn("no upstream; system proxy auto-restored")
            except OSError:
                pass

    # -- detailed test (key t) --
    async def _fetch_real_ip(self) -> str | None:
        if self._real_ip:
            return self._real_ip

        def fetch():
            try:
                url = f"http://{IP_CHECK_HOST}:{IP_CHECK_PORT}"
                data = urllib.request.urlopen(url, timeout=5).read(200)
                m = _BODY_IP_RE.match(data.strip())
                if m:
                    return str(ipaddress.ip_address(m.group(1).decode()))
            except Exception:  # noqa: BLE001
                pass
            return None
        self._real_ip = await asyncio.to_thread(fetch)
        return self._real_ip

    async def _sample(self, p: Proxy, host: str, port: int, timeout=6.0) -> float:
        """One handshake+CONNECT sample; returns ms, raises on failure."""
        t0 = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port), timeout)
        try:
            await socks.client_connect(reader, writer, host, port,
                                       p.username, p.password, timeout)
            return (time.monotonic() - t0) * 1000.0
        finally:
            writer.close()

    async def _detail_job(self, p: Proxy):
        L = self.detail = []
        add = L.append
        try:
            if not await self._check_online():
                self.msg = OFFLINE_MSG
                self.log.warn("detailed test skipped: no internet")
                self.detail = None
                return
            add(f"detailed test: {p.id}")
            add("")

            # a. TCP connect
            reader = writer = None
            try:
                t0 = time.monotonic()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(p.host, p.port), 6)
                add(f"PASS tcp connect {p.id} in {(time.monotonic() - t0) * 1000:.0f}ms")
            except Exception as e:  # noqa: BLE001
                add(f"FAIL tcp connect: {e}")
                p.alive, p.last_error, p.checked_at = False, str(e), time.time()
                self.log.warn(f"test {p.id}: tcp connect failed: {e}")
                return

            # b. SOCKS5 handshake + CONNECT
            try:
                t0 = time.monotonic()
                await socks.client_connect(reader, writer, IP_CHECK_HOST,
                                           IP_CHECK_PORT, p.username, p.password, 6)
                ms = (time.monotonic() - t0) * 1000
                add(f"PASS socks5 CONNECT {IP_CHECK_HOST}:{IP_CHECK_PORT} in {ms:.0f}ms")
                conn_ok = True
            except Exception as e:  # noqa: BLE001
                add(f"FAIL socks5 CONNECT {IP_CHECK_HOST}:{IP_CHECK_PORT}: {e}")
                conn_ok = False
                writer = None
            exit_ip = None

            # c. exit IP vs real IP
            if conn_ok:
                try:
                    writer.write(f"GET / HTTP/1.1\r\nHost: {IP_CHECK_HOST}\r\n"
                                 f"User-Agent: proxytui\r\nConnection: close\r\n\r\n"
                                 .encode())
                    await asyncio.wait_for(writer.drain(), 6)
                    data = await asyncio.wait_for(reader.read(8192), 6)
                    m = _BODY_IP_RE.match(data.split(b"\r\n\r\n", 1)[-1].strip())
                    if m:
                        exit_ip = str(ipaddress.ip_address(m.group(1).decode()))
                except Exception:  # noqa: BLE001
                    pass
                try:
                    writer.close()
                except OSError:
                    pass
            real = await self._fetch_real_ip()
            if exit_ip:
                p.exit_ip = exit_ip
                p.leaks = (exit_ip == real) if real else None
                if p.country is None:
                    await self._geo_missing()
            cc = f" {p.country}" if p.country else ""
            if exit_ip and real:
                if exit_ip == real:
                    add(f"FAIL exit IP {exit_ip}{cc}: NO - exit IP equals your IP")
                else:
                    add(f"PASS exit IP {exit_ip}{cc} (real {real}) - hides your IP: yes")
            elif exit_ip:
                add(f"PASS exit IP {exit_ip}{cc} (real IP unknown)")
            else:
                add("FAIL could not read exit IP through proxy")

            # d. TLS interception
            await check_tls(p, TLS_CHECK_HOST, timeout=6)
            if p.tls_ok is True:
                add(f"PASS TLS to {TLS_CHECK_HOST}: valid certificate")
            elif p.tls_ok is False:
                add(f"FAIL TLS to {TLS_CHECK_HOST}: MITM: {p.last_error}")
            else:
                add(f"FAIL TLS to {TLS_CHECK_HOST}: test inconclusive")

            # e. latency: 3 handshake+CONNECT samples
            samples = []
            for _ in range(3):
                try:
                    samples.append(await self._sample(p, IP_CHECK_HOST, IP_CHECK_PORT))
                except Exception:  # noqa: BLE001
                    pass
            if samples:
                add(f"PASS latency {min(samples):.0f}/"
                    f"{sum(samples) / len(samples):.0f}/{max(samples):.0f} ms "
                    f"(min/avg/max)")
            else:
                add("FAIL latency: no successful samples")

            p.alive = conn_ok or bool(samples)
            if samples:
                p.latency_ms = sum(samples) / len(samples)
            p.checked_at = time.time()
            self.log.info(f"test {p.id}: alive={p.alive} exit={exit_ip or '-'} "
                          f"tls={p.tls_ok} lat={p.latency_ms and f'{p.latency_ms:.0f}ms'}")
        except Exception as e:  # noqa: BLE001
            add(f"FAIL test aborted: {e}")
            self.log.error(f"test {p.id} aborted: {e}")
        finally:
            self._save_results()

    def detail_test(self):
        items = self.sorted()
        if not items:
            return
        p = items[self.cursor]
        self.detail = [f"testing {p.id} ..."]
        asyncio.run_coroutine_threadsafe(self._detail_job(p), self.loop)

    # -- auto-connect (key a) --
    def auto_connect(self):
        if self.checking or self._connecting:
            return
        cands = sorted(
            (p for p in self.proxies
             if p.status == "alive" and p.tls_ok is not False),
            key=lambda p: p.latency_ms if p.latency_ms is not None else 1e9)[:5]
        if not cands:
            self.msg = "no safe proxies yet - press c to check first"
            return
        self._connecting = True
        asyncio.run_coroutine_threadsafe(self._auto_job(cands), self.loop)

    async def _auto_job(self, cands: list[Proxy]):
        try:
            real = await self._fetch_real_ip()
            total = len(cands)
            for i, p in enumerate(cands, 1):
                def stage(pp, t, i=i, p=p):
                    self.msg = f"auto-connect: verifying {p.host} ({i}/{total}) {t}"
                self.msg = f"auto-connect: verifying {p.host} ({i}/{total})"
                ok, lat, exit_ip, err = await check_proxy(
                    p, IP_CHECK_HOST, IP_CHECK_PORT, fetch_ip=True,
                    timeout=6, stage=stage)
                if ok:
                    await check_tls(p, TLS_CHECK_HOST, timeout=6, stage=stage)
                p.checked_at = time.time()
                if ok:
                    p.alive, p.latency_ms = True, lat
                    if exit_ip:
                        p.exit_ip = exit_ip
                        if real:
                            p.leaks = exit_ip == real
                    p.successes += 1
                    p.consec_failures = 0
                else:
                    p.alive, p.last_error = False, err
                    p.failures += 1
                    p.consec_failures += 1
                if ok and p.tls_ok is not False and exit_ip != real:
                    self.fwd.upstream = p
                    try:
                        self.sys.enable()
                    except OSError as e:
                        self.msg = f"system proxy error: {e}"
                        self.log.error(self.msg)
                        return
                    self.msg = (f"connected via {p.id} ({p.latency_ms:.0f}ms"
                                f"{', ' + p.country if p.country else ''})"
                                " - system proxy ON - Esc to disconnect")
                    self.log.info(f"auto-connect: routed via {p.id}, system proxy ON")
                    self._save_results()
                    return
            self.msg = "auto-connect: none of the top 5 passed - press c to re-check"
            self.log.warn("auto-connect: no candidate passed verification")
            self._save_results()
        finally:
            self._connecting = False

    # -- export working proxies (key e) --
    def save_working(self):
        ok = sorted((p for p in self.proxies if p.status == "alive"),
                    key=lambda p: p.latency_ms if p.latency_ms is not None else 1e9)
        if not ok:
            self.msg = "no working proxies - press c first"
            return
        try:
            PROXY_DIR.mkdir(exist_ok=True)
            head = (f"# working proxies saved by proxytui "
                    f"{time.strftime('%Y-%m-%d %H:%M')}\n")
            WORKING_FILE.write_text(
                head + "\n".join(p.to_uri() for p in ok) + "\n",
                encoding="utf-8")
            self.msg = f"saved {len(ok)} working proxies to proxys\\working.txt"
            self.log.info(self.msg)
        except OSError as e:
            self.msg = f"save failed: {e}"
            self.log.error(self.msg)

    # -- drawing --
    def _header(self) -> str:
        up = self.fwd.upstream
        route = f"{GREEN}ROUTING via {up.id}{CLR}" if up else f"{DIM}not routing{CLR}"
        sysp = f"{GREEN}ON{CLR}" if self.sys.active else f"{DIM}off{CLR}"
        if self.online is True:
            net = f"{GREEN}internet OK{CLR}"
        elif self.online is False:
            net = f"{RED}OFFLINE{CLR}"
        else:
            net = f"{DIM}internet ?{CLR}"
        ks = f"{YELLOW}kill-switch ON{CLR}" if self.kill_switch else f"{DIM}kill-switch off{CLR}"
        return (f"{BOLD}proxytui{CLR}  {route}  |  local {LOCAL_HOST}:{LOCAL_PORT}  |  "
                f"system proxy {sysp}  |  {net}  |  {ks}  |  "
                f"conns {self.fwd.active} (total {self.fwd.total})\n")

    def _draw_detail(self, cols: int, rows: int) -> str:
        lines = self.detail or []
        w = min(cols - 4, 84)
        top = max(1, (rows - len(lines) - 4) // 2)
        out = []
        for i, ln in enumerate(lines[:rows - 6]):
            color = GREEN if ln.startswith("PASS") else (
                RED if ln.startswith("FAIL") else CLR)
            out.append(f"\x1b[{top + i};3H{color}{ln[:w]}{CLR}\x1b[K")
        out.append(f"\x1b[{top + len(lines[:rows - 6]) + 1};3H{DIM}press any key to close{CLR}\x1b[K")
        return "".join(out)

    def draw(self):
        cols, rows = os.get_terminal_size()
        out = ["\x1b[H\x1b[J", self._header()]
        if self.view == "logs":
            entries = list(self.log.lines)
            visible = max(1, rows - 5)
            if self.log_follow:
                top = max(0, len(entries) - visible)
            else:
                top = max(0, min(self.log_pos, max(0, len(entries) - visible)))
            colors = {"WARN": YELLOW, "ERROR": RED}
            for ts, level, msg in entries[top:top + visible]:
                c = colors.get(level, "")
                out.append(f"{c}{ts} {level:<5} {msg[:cols - 22]}{CLR}\n" if c
                           else f"{ts} {level:<5} {msg[:cols - 22]}\n")
            out.append(f"{DIM}-- Logs ({len(entries)})  Tab=proxies  arrows/PgUp/PgDn/End/Home scroll --{CLR}")
        else:
            out.append(f"{DIM}{'':2}{'STATUS':<9}{'CC':<5}{'LATENCY':>8}  {'PROXY':<34}"
                       f"{'EXIT IP':<16}sort:{SORTS[self.sort_i]}{CLR}\n")
            items = self.sorted()
            visible = max(1, rows - 6)
            top = max(0, min(self.cursor - visible + 1, len(items) - visible)) \
                if self.cursor >= visible else 0
            up = self.fwd.upstream
            for i, p in enumerate(items[top:top + visible], top):
                color = {"alive": GREEN, "dead": RED, "untested": YELLOW,
                         "LEAK": BOLD + RED, "MITM": BOLD + RED}[p.status]
                lat = f"{p.latency_ms:.0f}ms" if p.latency_ms is not None else "-"
                mark = ">" if up is p else " "
                step = self.stages.get(p.key)
                status, note, ncol = (("checking", step, YELLOW) if step else
                                      (p.status, p.last_error or "", DIM))
                if step:
                    color = YELLOW
                line = (f"{mark} {color}{status:<9}{CLR}{(p.country or '-'):<5}"
                        f"{lat:>8}  {p.id:<34}{(p.exit_ip or '-'):<16}"
                        f"{ncol}{note[:max(0, cols - 77)]}{CLR}")
                if i == self.cursor:
                    line = f"{INV}{line.replace(CLR, CLR + INV)}{CLR}"
                out.append(line + "\n")
            if not items:
                out.append(f"\n  {YELLOW}No proxies loaded.{CLR}  Press {BOLD}l{CLR} to load a file "
                           f"or {BOLD}v{CLR} to paste a list from the clipboard.\n")
            if self.detail is not None:
                out.append(self._draw_detail(cols, rows))
        out.append(f"\x1b[{rows - 2};1H\x1b[K{DIM}{HELP[0][:cols - 1]}{CLR}")
        out.append(f"\x1b[{rows - 1};1H\x1b[K{DIM}{HELP[1][:cols - 1]}{CLR}")
        out.append(f"\x1b[{rows};1H\x1b[K{CYAN}{self.msg[:cols - 1]}{CLR}")
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    def prompt(self, label: str) -> str:
        rows = os.get_terminal_size().lines
        sys.stdout.write(f"\x1b[{rows};1H\x1b[K{label}\x1b[?25h")
        sys.stdout.flush()
        buf = ""
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                break
            if ch == "\x1b":
                buf = ""
                break
            if ch == "\x08":
                buf = buf[:-1]
            elif ch.isprintable():
                buf += ch
            sys.stdout.write(f"\x1b[{rows};1H\x1b[K{label}{buf}")
            sys.stdout.flush()
        sys.stdout.write("\x1b[?25l")
        return buf.strip().strip('"')

    # -- actions --
    def route(self):
        items = self.sorted()
        if not items:
            return
        p = items[self.cursor]
        if self.fwd.upstream is p:
            self.fwd.upstream = None
            self.msg = "stopped routing"
            self.log.info(f"route off ({p.id})")
        elif p.leaks:
            self.msg = f"REFUSED: {p.id} leaks your real IP (exit {p.exit_ip}) - it does not hide you"
            self.log.warn(f"route refused: {p.id} leaks real IP")
        elif p.tls_ok is False:
            self.msg = f"REFUSED: {p.id} intercepts TLS (fake certificates) - it can read your traffic"
            self.log.warn(f"route refused: {p.id} intercepts TLS")
        else:
            self.fwd.upstream = p
            self.msg = f"routing via {p.id}  (set apps to SOCKS5 {LOCAL_HOST}:{LOCAL_PORT}, or press w)"
            self.log.info(f"route on via {p.id}")

    def toggle_sys(self):
        try:
            if self.sys.active:
                self.sys.disable()
                self.msg = "Windows system proxy restored"
                self.log.info("system proxy off (restored)")
            else:
                if not self.fwd.upstream:
                    self.msg = "select a proxy and press Enter first"
                    return
                self.sys.enable()
                self.msg = f"Windows system proxy -> http {LOCAL_HOST}:{LOCAL_PORT}"
                self.log.info("system proxy ON")
        except OSError as e:
            self.msg = f"system proxy error: {e}"
            self.log.error(f"system proxy error: {e}")

    def disconnect(self):
        """Stop routing and restore the original Windows proxy setting."""
        was = self.fwd.upstream
        if was is None and not self.sys.active:
            self.msg = "not connected"
            return
        self.fwd.upstream = None
        try:
            self.sys.disable()
        except OSError as e:
            self.log.error(f"system proxy restore failed: {e}")
        self.msg = "disconnected - direct internet restored"
        self.log.info(f"disconnected ({was.id if was else 'no upstream'}); system proxy restored")

    def toggle_kill(self):
        self.kill_switch = not self.kill_switch
        self.msg = f"kill-switch {'ON - traffic blocked if all proxies fail' if self.kill_switch else 'off'}"
        self.log.info(f"kill-switch {'ON' if self.kill_switch else 'off'}")

    def handle_key(self, ch: str):
        if ch in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            ch = {"H": "up", "P": "down", "I": "pgup", "Q": "pgdn",
                  "G": "home", "O": "end"}.get(code, "")
        if ch in ("q", "\x03"):  # q or Ctrl+C read by getwch
            self.running = False
            return
        if self.detail is not None:
            self.detail = None
            return
        if self.view == "logs":
            n = len(self.log.lines)
            try:
                page = max(1, os.get_terminal_size().lines - 4)
            except OSError:
                page = 20
            if ch == "up":
                self.log_follow = False
                self.log_pos = max(0, min(self.log_pos, n - 1) - 1) if n else 0
            elif ch == "down":
                self.log_pos += 1
                if self.log_pos >= max(0, n - page):
                    self.log_follow = True
            elif ch == "pgup":
                self.log_follow = False
                self.log_pos = max(0, self.log_pos - page)
            elif ch == "pgdn":
                self.log_pos = min(max(0, n - 1), self.log_pos + page)
                if self.log_pos >= max(0, n - page):
                    self.log_follow = True
            elif ch == "home":
                self.log_follow, self.log_pos = False, 0
            elif ch == "end":
                self.log_follow = True
            elif ch == "\t":
                self.view = "proxies"
            return
        items = self.sorted()
        if ch == "up" and self.cursor > 0:
            self.cursor -= 1
        elif ch == "down" and self.cursor < len(items) - 1:
            self.cursor += 1
        elif ch == "pgup":
            self.cursor = max(0, self.cursor - 10)
        elif ch == "pgdn":
            self.cursor = min(max(0, len(items) - 1), self.cursor + 10)
        elif ch == "home":
            self.cursor = 0
        elif ch == "end":
            self.cursor = max(0, len(items) - 1)
        elif ch == "\r":
            self.route()
        elif ch == "\x1b":
            self.disconnect()
        elif ch == "t":
            self.detail_test()
        elif ch == "a":
            self.auto_connect()
        elif ch == "e":
            self.save_working()
        elif ch == "c":
            self.check_all()
        elif ch == "w":
            self.toggle_sys()
        elif ch == "k":
            self.toggle_kill()
        elif ch == "\t":
            self.view = "logs"
            self.log_follow = True
        elif ch == "s":
            self.sort_i = (self.sort_i + 1) % len(SORTS)
            self.cursor = 0
        elif ch == "l":
            path = self.prompt("file or folder to load: ")
            if path:
                if Path(path).exists():
                    self.load_paths([Path(path)])
                else:
                    self.msg = f"load failed: {path} not found"
        elif ch == "r":
            self.load_paths([PROXY_DIR])
        elif ch == "v":
            self.load_text(_clipboard(), "clipboard")
        elif ch == "d" and items:
            p = items[self.cursor]
            if self.fwd.upstream is p:
                self.fwd.upstream = None
            self.proxies.remove(p)
            self.cursor = min(self.cursor, max(0, len(self.proxies) - 1))
            self.msg = f"deleted {p.id}"
        elif ch == "x":
            dead = [p for p in self.proxies if p.status in ("dead", "MITM", "LEAK")
                    and p is not self.fwd.upstream]
            for p in dead:
                self.proxies.remove(p)
            self.cursor = min(self.cursor, max(0, len(self.proxies) - 1))
            self.msg = f"dropped {len(dead)} dead/MITM/leaky"
            self.log.info(f"dropped {len(dead)} dead/MITM/leaky proxies")

    def run(self):
        install_ctrl_handler(self)
        threading.Thread(target=self.run_loop, daemon=True).start()
        os.system("")  # enable ANSI on Windows console
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        try:
            last = 0.0
            while self.running:
                if msvcrt.kbhit():
                    self.handle_key(msvcrt.getwch())
                    self.draw()
                    last = time.monotonic()
                elif time.monotonic() - last > 0.5:
                    self.draw()
                    last = time.monotonic()
                else:
                    time.sleep(0.03)
        finally:
            try:
                self._save_results()
                self.sys.disable()
            finally:
                self.log.info("exit")
                sys.stdout.write("\x1b[?25h\x1b[?1049l")
                sys.stdout.flush()
                self.loop.call_soon_threadsafe(self.loop.stop)


def main():
    if len(sys.argv) > 1:
        paths = [Path(a) for a in sys.argv[1:]]
    else:
        PROXY_DIR.mkdir(exist_ok=True)
        paths = [PROXY_DIR, HERE / "proxies.txt"]
    try:
        App(paths).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
