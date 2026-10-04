"""Headless tests for proxytui (no TTY, no real registry, no real network needed).

Run from the project root:  python test_tui.py

NOTE: never touches the real WinINet proxy keys - sysproxy_read/write and
STATE_FILE are monkeypatched everywhere SysProxy is used.
"""
import asyncio
import contextlib
import io
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import proxytui                      # noqa: E402
from proxyapp import socks           # noqa: E402
from proxyapp.models import Proxy    # noqa: E402

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")


# --- fakes / fixtures ------------------------------------------------------------

WRITES = []


def fake_write(enable, server=None, override=None):
    WRITES.append((enable, server, override))


def fake_read():
    return {"ProxyEnable": 0, "ProxyServer": None, "ProxyOverride": None}


@contextlib.contextmanager
def patched(tmp: Path):
    """Monkeypatch registry access + state file + log file for a test."""
    old = (proxytui.sysproxy_write, proxytui.sysproxy_read,
           proxytui.STATE_FILE, proxytui.LOG_FILE, proxytui.RESULTS_FILE,
           proxytui.PROXY_DIR, proxytui.WORKING_FILE)
    proxytui.sysproxy_write = fake_write
    proxytui.sysproxy_read = fake_read
    proxytui.STATE_FILE = tmp / "tui_state.json"
    proxytui.LOG_FILE = tmp / "proxytui.log"
    proxytui.RESULTS_FILE = tmp / "tui_results.json"
    proxytui.PROXY_DIR = tmp / "proxys"
    proxytui.WORKING_FILE = proxytui.PROXY_DIR / "working.txt"
    # Log() default binds the original path; route App's log to the temp file
    old_log = proxytui.Log
    real_log = old_log
    proxytui.Log = lambda path=None, **kw: real_log(path or tmp / "proxytui.log", **kw)
    try:
        yield
    finally:
        (proxytui.sysproxy_write, proxytui.sysproxy_read,
         proxytui.STATE_FILE, proxytui.LOG_FILE, proxytui.RESULTS_FILE,
         proxytui.PROXY_DIR, proxytui.WORKING_FILE) = old
        proxytui.Log = old_log
        WRITES.clear()


def free_port() -> int:
    import socket as _s
    s = _s.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_app_loop(app) -> int:
    """Run the app's event loop + forwarder on a spare local port."""
    port = free_port()
    old_port = proxytui.LOCAL_PORT
    proxytui.LOCAL_PORT = port
    t = threading.Thread(target=app.run_loop, daemon=True)
    t.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        if app.fwd.server is not None:
            break
        time.sleep(0.05)
    return port, old_port


def stop_app_loop(app, old_port):
    app.loop.call_soon_threadsafe(app.loop.stop)
    proxytui.LOCAL_PORT = old_port


async def echo_server(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(b"echo:" + data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


def make_upstream(echo_port):
    """Dummy SOCKS5 upstream that connects to the local echo server
    regardless of the requested destination."""
    async def handler(r, w):
        try:
            await socks.read_greeting(r)
            w.write(bytes([socks.VER, socks.METHOD_NOAUTH]))
            await w.drain()
            await socks.read_request(r)
            er, ew = await asyncio.open_connection("127.0.0.1", echo_port)
            w.write(socks.pack_reply(socks.REP_OK))
            await w.drain()

            async def pipe(rd, wr):
                try:
                    while data := await rd.read(65536):
                        wr.write(data)
                        await wr.drain()
                except OSError:
                    pass
                try:
                    wr.close()
                except OSError:
                    pass
            await asyncio.gather(pipe(r, ew), pipe(er, w), return_exceptions=True)
        except Exception:
            pass
    return handler


async def client_connect(port, dest_host="example.org", dest_port=80):
    """SOCKS5 client to the forwarder; returns (reader, writer, rep)."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(bytes([5, 1, 0]))
    await w.drain()
    await r.readexactly(2)
    w.write(bytes([5, 1, 0]) + socks.pack_addr(dest_host)
            + struct.pack("!H", dest_port))
    await w.drain()
    hdr = await r.readexactly(4)
    if hdr[1] == 0:
        await socks.read_addr(r, hdr[3])
    return r, w, hdr[1]


def wait_for(cond, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return False


async def real_upstream(r, w):
    """Dummy SOCKS5 upstream that connects to the real requested destination."""
    try:
        await socks.read_greeting(r)
        w.write(bytes([socks.VER, socks.METHOD_NOAUTH]))
        await w.drain()
        cmd, host, port = await socks.read_request(r)
        er, ew = await asyncio.open_connection(host, port)
        w.write(socks.pack_reply(socks.REP_OK))
        await w.drain()

        async def pipe(rd, wr):
            try:
                while data := await rd.read(65536):
                    wr.write(data)
                    await wr.drain()
            except OSError:
                pass
            try:
                wr.close()
            except OSError:
                pass
        await asyncio.gather(pipe(r, ew), pipe(er, w), return_exceptions=True)
    except Exception:
        pass


ORIGIN_SEEN = {}


async def http_origin(r, w):
    """Tiny HTTP origin: fixed body, records request line + headers."""
    try:
        head = await r.readuntil(b"\r\n\r\n")
        ORIGIN_SEEN["head"] = head.decode("iso-8859-1")
        body = b"hello-origin"
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        await w.drain()
    except Exception:
        pass
    finally:
        w.close()


async def socks4_connect(port, ip=None, domain=None, dest_port=80, cmd=1):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    ipb = ipaddress.IPv4Address(ip).packed if ip else b"\x00\x00\x00\x01"
    tail = (domain.encode() + b"\x00") if domain else b""
    w.write(bytes([4, cmd]) + struct.pack("!H", dest_port) + ipb + b"\x00" + tail)
    await w.drain()
    rep = await r.readexactly(8)
    return r, w, rep[1]


async def http_head(r):
    return (await r.readuntil(b"\r\n\r\n")).decode("iso-8859-1")


# --- tests ------------------------------------------------------------------------

def test_ctrl_handler():
    print("ctrl handler:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            handler = proxytui.install_ctrl_handler(app)
            app.sys.active = True
            app.sys.saved = {"ProxyEnable": 0, "ProxyServer": None,
                             "ProxyOverride": None}
            proxytui.STATE_FILE.write_text(json.dumps(app.sys.saved))
            ret = handler(2)  # CTRL_CLOSE_EVENT
            check("close event returns False (let default terminate)", ret is False)
            check("sysproxy restored on close",
                  WRITES[-1] == (False, None, None))
            check("state file removed", not proxytui.STATE_FILE.exists())
            check("sysproxy inactive", app.sys.active is False)
            ret = handler(0)  # CTRL_C
            check("ctrl-C returns True and stops app",
                  ret is True and app.running is False)
            import ctypes
            ctypes.windll.kernel32.SetConsoleCtrlHandler(proxytui._CTRL_HANDLER, False)


def test_w_requires_upstream():
    print("w guard:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            app.handle_key("w")
            check("no upstream -> not enabled", app.sys.active is False)
            check("no writes to registry", not WRITES)
            check("hint shown", "press Enter" in app.msg)


def test_failover():
    print("failover + kill-switch:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            port, old_port = start_app_loop(app)
            try:
                async def body():
                    echo = await asyncio.start_server(echo_server, "127.0.0.1", 0)
                    echo_port = echo.sockets[0].getsockname()[1]
                    ups = await asyncio.start_server(
                        make_upstream(echo_port), "127.0.0.1", 0)
                    ups_port = ups.sockets[0].getsockname()[1]

                    a = Proxy(host="127.0.0.1", port=free_port())  # closed port
                    b = Proxy(host="127.0.0.1", port=ups_port)
                    for p, lat in ((a, 1.0), (b, 50.0)):
                        p.alive, p.tls_ok, p.latency_ms = True, True, lat
                    app.proxies = [a, b]
                    app.fwd.upstream = a

                    for _ in range(3):
                        r, w, rep = await client_connect(port)
                        check("dead upstream refused", rep == socks.REP_HOST_UNREACHABLE)
                        w.close()
                    check("failover to B", app.fwd.upstream is b)
                    check("A marked dead", a.alive is False)

                    r, w, rep = await client_connect(port)
                    check("connect via B ok", rep == socks.REP_OK)
                    w.write(b"ping")
                    await w.drain()
                    data = await asyncio.wait_for(r.readexactly(9), 5)
                    check("echo relay via B", data == b"echo:ping")
                    w.close()

                    # all proxies dead, kill-switch off -> restore direct
                    b.alive = False
                    app.fwd.upstream = a  # a is dead too
                    app.fwd.fail_count = 0
                    app.fwd.fail_upstream = None
                    app.sys.active = True
                    app.sys.saved = {"ProxyEnable": 0, "ProxyServer": None,
                                     "ProxyOverride": None}
                    n0 = len(WRITES)
                    for _ in range(3):
                        r, w, rep = await client_connect(port)
                        w.close()
                    check("upstream cleared", app.fwd.upstream is None)
                    check("kill off: system proxy disabled",
                          len(WRITES) > n0 and WRITES[-1][0] is False)
                    check("kill off msg", "restored direct" in app.msg)

                    # kill-switch on -> keep blocking
                    app.sys.active = True
                    app.kill_switch = True
                    app.fwd.upstream = a
                    app.fwd.fail_count = 0
                    app.fwd.fail_upstream = None
                    n0 = len(WRITES)
                    for _ in range(3):
                        r, w, rep = await client_connect(port)
                        w.close()
                    check("kill on: upstream cleared", app.fwd.upstream is None)
                    check("kill on: system proxy kept",
                          len(WRITES) == n0 and app.sys.active is True)
                    check("kill on msg", "kill-switch" in app.msg)

                    # no upstream + sysproxy on + kill off -> auto restore
                    app.kill_switch = False
                    app.sys.active = True
                    n0 = len(WRITES)
                    r, w, rep = await client_connect(port)
                    check("no upstream refused", rep == socks.REP_NET_UNREACHABLE)
                    w.close()
                    await proxytui._to_thread(wait_for, lambda: not app.sys.active, 2)
                    check("no upstream: auto-restored",
                          len(WRITES) > n0 and app.sys.active is False)

                    echo.close()
                    ups.close()
                asyncio.run(body())
            finally:
                stop_app_loop(app, old_port)


def test_offline_check():
    print("offline check guard:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            p = Proxy(host="127.0.0.1", port=1080)
            p.alive, p.tls_ok = True, True
            app.proxies = [p]
            old = proxytui.internet_ok
            proxytui.internet_ok = lambda *a, **k: False
            port, old_port = start_app_loop(app)
            try:
                app.check_all()
                check("check skipped statuses",
                      wait_for(lambda: not app.checking) and
                      p.alive is True and p.checked_at is None)
                check("offline msg", "No internet" in app.msg)
                check("warn logged", any(lv == "WARN" for _, lv, _ in app.log.lines))
            finally:
                proxytui.internet_ok = old
                stop_app_loop(app, old_port)


def test_detail():
    print("detailed test:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            port, old_port = start_app_loop(app)
            try:
                async def body():
                    echo = await asyncio.start_server(echo_server, "127.0.0.1", 0)
                    echo_port = echo.sockets[0].getsockname()[1]
                    ups = await asyncio.start_server(
                        make_upstream(echo_port), "127.0.0.1", 0)
                    ups_port = ups.sockets[0].getsockname()[1]

                    old = (proxytui.internet_ok, proxytui.IP_CHECK_HOST,
                           proxytui.IP_CHECK_PORT, proxytui.TLS_CHECK_HOST)
                    proxytui.internet_ok = lambda *a, **k: True
                    proxytui.IP_CHECK_HOST = "127.0.0.1"
                    proxytui.IP_CHECK_PORT = echo_port
                    proxytui.TLS_CHECK_HOST = "127.0.0.1"
                    try:
                        p = Proxy(host="127.0.0.1", port=ups_port)
                        app.proxies = [p]
                        app.detail_test()
                        deadline = time.time() + 15
                        while time.time() < deadline and not (
                                app.detail and any("latency" in l
                                                   for l in app.detail)):
                            await asyncio.sleep(0.1)
                        lines = app.detail or []
                        check("produced lines", len(lines) >= 4)
                        check("tcp pass", any(l.startswith("PASS tcp") for l in lines))
                        check("socks pass", any(l.startswith("PASS socks5") for l in lines))
                        check("latency line", any("min/avg/max" in l for l in lines))
                        check("proxy updated", p.alive is True and
                              p.latency_ms is not None)
                        # modal closes on any key
                        app.handle_key(" ")
                        check("modal closed", app.detail is None)
                    finally:
                        (proxytui.internet_ok, proxytui.IP_CHECK_HOST,
                         proxytui.IP_CHECK_PORT, proxytui.TLS_CHECK_HOST) = old
                        echo.close()
                        ups.close()
                asyncio.run(body())
            finally:
                stop_app_loop(app, old_port)


def test_log_and_views():
    print("log + views:")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        with patched(tmp):
            app = proxytui.App(None)
            app.handle_key("\t")
            check("tab -> logs", app.view == "logs")
            app.handle_key("\t")
            check("tab -> proxies", app.view == "proxies")

            # draw both views with fake terminal size
            old_ts = os.get_terminal_size
            os.get_terminal_size = lambda: os.terminal_size((100, 20))
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    app.draw()
                check("draw proxies", "proxytui" in buf.getvalue())
                app.view = "logs"
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    app.draw()
                check("draw logs", "Logs" in buf.getvalue())
            finally:
                os.get_terminal_size = old_ts

            # rotation
            lg = proxytui.Log(tmp / "r.log", max_bytes=100)
            lg.info("x" * 200)
            lg.info("after rotate")
            check("rotated .1 exists", (tmp / "r.log.1").exists())
            check("new file has latest",
                  "after rotate" in (tmp / "r.log").read_text())
            check("in-memory lines", len(lg.lines) == 2)


def test_protocols():
    print("multi-protocol forwarder:")
    real_private = proxytui._is_private
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            port, old_port = start_app_loop(app)
            try:
                async def body():
                    echo = await asyncio.start_server(echo_server, "127.0.0.1", 0)
                    echo_port = echo.sockets[0].getsockname()[1]
                    ups = await asyncio.start_server(real_upstream, "127.0.0.1", 0)
                    ups_port = ups.sockets[0].getsockname()[1]
                    origin = await asyncio.start_server(http_origin, "127.0.0.1", 0)
                    origin_port = origin.sockets[0].getsockname()[1]

                    proxytui._is_private = lambda h: False  # allow 127.0.0.1 targets
                    p = Proxy(host="127.0.0.1", port=ups_port)
                    app.fwd.upstream = p
                    try:
                        # SOCKS4 with IPv4 dest -> echo relay
                        r, w, rep = await socks4_connect(
                            port, ip="127.0.0.1", dest_port=echo_port)
                        check("socks4 granted", rep == 0x5A)
                        w.write(b"s4"); await w.drain()
                        check("socks4 relay",
                              await r.readexactly(7) == b"echo:s4")
                        w.close()

                        # SOCKS4a with domain -> upstream "resolves" it
                        r, w, rep = await socks4_connect(
                            port, domain="localhost", dest_port=echo_port)
                        check("socks4a granted", rep == 0x5A)
                        w.write(b"s4a"); await w.drain()
                        check("socks4a relay",
                              await r.readexactly(8) == b"echo:s4a")
                        w.close()

                        # SOCKS4 BIND rejected
                        r, w, rep = await socks4_connect(
                            port, ip="127.0.0.1", dest_port=echo_port, cmd=2)
                        check("socks4 BIND rejected", rep == 0x5B)
                        w.close()

                        # HTTP CONNECT -> 200 + relay
                        r, w = await asyncio.open_connection("127.0.0.1", port)
                        w.write(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode())
                        await w.drain()
                        head = await http_head(r)
                        check("http CONNECT 200", head.startswith("HTTP/1.1 200"))
                        w.write(b"hc"); await w.drain()
                        check("http CONNECT relay",
                              await r.readexactly(7) == b"echo:hc")
                        w.close()

                        # HTTP absolute-form GET -> origin-form at origin
                        ORIGIN_SEEN.clear()
                        r, w = await asyncio.open_connection("127.0.0.1", port)
                        w.write((f"GET http://127.0.0.1:{origin_port}/p?q=1 HTTP/1.1\r\n"
                                 f"Host: 127.0.0.1:{origin_port}\r\n"
                                 f"Proxy-Connection: keep-alive\r\n"
                                 f"X-Test: yes\r\n\r\n").encode())
                        await w.drain()
                        resp = await asyncio.wait_for(r.read(8192), 5)
                        seen = ORIGIN_SEEN.get("head", "")
                        check("GET body", b"hello-origin" in resp)
                        check("origin-form request line",
                              seen.startswith("GET /p?q=1 HTTP/1.1"))
                        check("proxy headers stripped",
                              "proxy-connection" not in seen.lower() and
                              "Connection: close" in seen)
                        check("other headers kept", "X-Test: yes" in seen)
                        w.close()

                        # curl end-to-end for each protocol flag
                        for flag in (["--socks4"], ["--socks4a"],
                                     ["--socks5-hostname"], ["-x", "http://"]):
                            args = ["curl.exe", "-s", "--max-time", "15"]
                            if flag == ["-x", "http://"]:
                                args += ["-x", f"http://127.0.0.1:{port}"]
                            else:
                                args += [flag[0], f"127.0.0.1:{port}"]
                            args.append(f"http://127.0.0.1:{origin_port}/curl")
                            res = await proxytui._to_thread(
                                lambda: subprocess.run(
                                    args, capture_output=True,
                                    text=True, timeout=20))
                            name = " ".join(flag)
                            check(f"curl {name}",
                                  res.returncode == 0 and
                                  "hello-origin" in res.stdout)

                        # failure matrix: no upstream
                        app.fwd.upstream = None
                        r, w = await asyncio.open_connection("127.0.0.1", port)
                        w.write(b"CONNECT x.test:80 HTTP/1.1\r\n\r\n")
                        await w.drain()
                        check("http no upstream 503",
                              (await http_head(r)).startswith("HTTP/1.1 503"))
                        w.close()
                        r, w, rep = await socks4_connect(port, ip="1.2.3.4")
                        check("socks4 no upstream 0x5B", rep == 0x5B)
                        w.close()
                        r, w, rep = await client_connect(port)
                        check("socks5 no upstream",
                              rep == socks.REP_NET_UNREACHABLE)
                        w.close()

                        # private destination -> 403 (real _is_private)
                        app.fwd.upstream = p
                        proxytui._is_private = real_private
                        r, w = await asyncio.open_connection("127.0.0.1", port)
                        w.write(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n")
                        await w.drain()
                        check("http private 403",
                              (await http_head(r)).startswith("HTTP/1.1 403"))
                        w.close()
                    finally:
                        proxytui._is_private = real_private
                        echo.close()
                        ups.close()
                        origin.close()
                asyncio.run(body())
            finally:
                stop_app_loop(app, old_port)


def test_persist_and_geo():
    print("persist results + geo:")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        with patched(tmp):
            old = (proxytui.internet_ok, proxytui.geo_lookup, proxytui.check_many)
            proxytui.internet_ok = lambda *a, **k: True
            proxytui.geo_lookup = lambda ips: {ip: "DE" for ip in ips}

            async def fake_many(proxies, **kw):
                for p in proxies:
                    p.alive, p.latency_ms = True, 42.0
                    p.exit_ip, p.tls_ok = "9.9.9.9", True
                    p.checked_at = time.time()
            proxytui.check_many = fake_many
            try:
                app = proxytui.App(None)
                app._real_ip = "5.5.5.5"
                port, old_port = start_app_loop(app)
                try:
                    app.load_text("socks5://1.2.3.4:1080\n", "t")
                    app.check_all()
                    check("check finished", wait_for(lambda: not app.checking, 10))
                    p = app.proxies[0]
                    check("country filled", p.country == "DE")
                    check("leaks false", p.leaks is False)
                    data = json.loads(proxytui.RESULTS_FILE.read_text())
                    check("results saved", data[p.key]["alive"] is True and
                          data[p.key]["country"] == "DE")

                    # merge keeps entries for proxies not currently loaded
                    data["zz@8.8.8.8:9"] = {"alive": True, "latency_ms": 1}
                    proxytui.RESULTS_FILE.write_text(json.dumps(data))
                    app._save_results()
                    data = json.loads(proxytui.RESULTS_FILE.read_text())
                    check("merge keeps foreign entry", "zz@8.8.8.8:9" in data)
                finally:
                    stop_app_loop(app, old_port)

                # a fresh app restores results for untested proxies
                app2 = proxytui.App(None)
                app2.load_text("socks5://1.2.3.4:1080\n", "t")
                p2 = app2.proxies[0]
                check("restored alive/latency",
                      p2.alive is True and p2.latency_ms == 42.0)
                check("restored tls/leaks/country",
                      p2.tls_ok is True and p2.leaks is False and p2.country == "DE")
                check("restored msg", "restored" in app2.msg)
            finally:
                (proxytui.internet_ok, proxytui.geo_lookup,
                 proxytui.check_many) = old


def test_leak():
    print("leak detection:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            old = (proxytui.internet_ok, proxytui.geo_lookup, proxytui.check_many)
            proxytui.internet_ok = lambda *a, **k: True
            proxytui.geo_lookup = lambda ips: (_ for _ in ()).throw(
                RuntimeError("geo down"))  # must not break check_all
            real_ip = "5.5.5.5"

            async def fake_many(proxies, **kw):
                for p in proxies:
                    p.alive, p.tls_ok = True, True
                    p.latency_ms, p.checked_at = 10.0, time.time()
                    # p1 exits with the user's own IP -> leak
                    p.exit_ip = real_ip if p.host == "1.1.1.1" else "9.9.9.9"
            proxytui.check_many = fake_many
            try:
                app = proxytui.App(None)
                app._real_ip = real_ip
                port, old_port = start_app_loop(app)
                try:
                    app.load_text("socks5://1.1.1.1:1\nsocks5://2.2.2.2:2\n", "t")
                    app.check_all()
                    check("check finished despite geo error",
                          wait_for(lambda: not app.checking, 10))
                    p1, p2 = app.proxies
                    check("leaker flagged", p1.status == "LEAK")
                    check("clean proxy alive", p2.status == "alive" and p2.leaks is False)
                    check("msg mentions leak", "leak" in app.msg)
                    check("check done msg", app.msg.startswith("check done"))
                    # route() refuses the leaker
                    app.cursor = app.sorted().index(p1)
                    app.route()
                    check("route refuses leak",
                          app.fwd.upstream is None and "REFUSED" in app.msg)
                    # x drops dead/MITM/LEAK
                    app.handle_key("x")
                    check("x drops leak", p1 not in app.proxies and p2 in app.proxies)
                finally:
                    stop_app_loop(app, old_port)
            finally:
                (proxytui.internet_ok, proxytui.geo_lookup,
                 proxytui.check_many) = old


def test_auto_connect():
    print("auto-connect:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            # no candidates
            app0 = proxytui.App(None)
            app0.auto_connect()
            check("no candidates msg", "no safe proxies" in app0.msg)

            old = (proxytui.check_proxy, proxytui.check_tls)
            try:
                p1 = Proxy(host="1.1.1.1", port=1)
                p2 = Proxy(host="2.2.2.2", port=2)
                p3 = Proxy(host="3.3.3.3", port=3)
                for p, lat in ((p1, 10.0), (p2, 20.0), (p3, 30.0)):
                    p.alive, p.tls_ok, p.latency_ms = True, True, lat

                async def fake_cp(p, *a, **k):
                    if p is p1:
                        return False, None, None, "dead"
                    return True, 5.0, "8.8.4.4", None

                async def fake_ct(p, *a, **k):
                    if p is p2:
                        p.tls_ok = False
                proxytui.check_proxy = fake_cp
                proxytui.check_tls = fake_ct

                app = proxytui.App(None)
                app._real_ip = "5.5.5.5"
                app.proxies = [p1, p2, p3]
                port, old_port = start_app_loop(app)
                try:
                    app.auto_connect()
                    check("connect done",
                          wait_for(lambda: not app._connecting, 10))
                    check("routed via third", app.fwd.upstream is p3)
                    check("sysproxy enabled",
                          app.sys.active and WRITES and WRITES[-1][0] is True)
                    check("msg connected", app.msg.startswith("connected via"))
                    check("p1 marked dead", p1.alive is False)
                    check("p2 MITM", p2.tls_ok is False)
                finally:
                    stop_app_loop(app, old_port)
            finally:
                proxytui.check_proxy, proxytui.check_tls = old


def test_export_and_sort():
    print("export + country sort:")
    with tempfile.TemporaryDirectory() as td:
        with patched(Path(td)):
            app = proxytui.App(None)
            check("export none -> no file",
                  (app.save_working(), not proxytui.WORKING_FILE.exists())[1])
            check("export none msg", "no working proxies" in app.msg)
            a = Proxy(host="1.1.1.1", port=1)
            b = Proxy(host="2.2.2.2", port=2)
            c = Proxy(host="3.3.3.3", port=3)
            a.alive, a.latency_ms, a.country = True, 30.0, "FR"
            b.alive, b.latency_ms, b.country = True, 10.0, "DE"
            c.alive, c.leaks = True, True          # LEAK - not exported
            d = Proxy(host="4.4.4.4", port=4)       # untested
            app.proxies = [a, b, c, d]
            app.save_working()
            txt = proxytui.WORKING_FILE.read_text()
            check("export header", txt.startswith("# working proxies"))
            check("export sorted by latency",
                  txt.index("2.2.2.2:2") < txt.index("1.1.1.1:1"))
            check("export excludes LEAK/untested",
                  "3.3.3.3" not in txt and "4.4.4.4" not in txt)
            check("export msg", app.msg.startswith("saved 2"))
            app.sort_i = proxytui.SORTS.index("country")
            check("sort by country", app.sorted()[:2] == [b, a])


def main():
    test_ctrl_handler()
    test_w_requires_upstream()
    test_protocols()
    test_persist_and_geo()
    test_leak()
    test_auto_connect()
    test_export_and_sort()
    test_failover()
    test_offline_check()
    test_detail()
    test_log_and_views()
    failed = [n for n, ok in PASS if not ok]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
