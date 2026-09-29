"""End-to-end selftest (no network needed):

  echo server  <-  dummy upstream SOCKS5  <-  proxyapp server  <-  client

Verifies: parsing formats, auth enforcement, ACL deny, destination filtering,
upstream relay of real bytes, and audit logging.
Run from the project root:  python selftest.py
"""
import asyncio
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxyapp.models import Proxy, parse_proxy, parse_lines  # noqa: E402
from proxyapp.security import AuditLog, UserStore  # noqa: E402
from proxyapp.server import ProxyServer  # noqa: E402
from proxyapp.store import Store, DEFAULT_CONFIG  # noqa: E402
from proxyapp import socks  # noqa: E402

PASS = []


def check(name, cond):
    PASS.append((name, cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")


def test_parsing():
    print("parsing:")
    p = parse_proxy("socks5://5.255.99.75:1080")
    check("scheme form", p.host == "5.255.99.75" and p.port == 1080 and p.username is None)
    p = parse_proxy("socks5://u:p@1.2.3.4:1080")
    check("uri auth", p.username == "u" and p.password == "p")
    p = parse_proxy("1.2.3.4:4145")
    check("bare host:port", p.port == 4145)
    p = parse_proxy("1.2.3.4:1080:user:pw")
    check("host:port:user:pass", p.username == "user" and p.password == "pw")
    p = parse_proxy("user:pw@1.2.3.4:1080")
    check("user:pass@host:port", p.username == "user" and p.port == 1080)
    p = parse_proxy("socks5://[::1]:1080")
    check("ipv6 uri", p.host == "::1" and p.port == 1080)
    for bad in ("http://1.2.3.4:1080", "1.2.3.4:99999", "nonsense", "1.2.3.4"):
        try:
            parse_proxy(bad)
            check(f"reject {bad!r}", False)
        except ValueError:
            check(f"reject {bad!r}", True)
    # dedupe keys
    a, b = parse_proxy("socks5://1.2.3.4:1080"), parse_proxy("1.2.3.4:1080")
    check("dedupe key", a.key == b.key)


async def dummy_upstream(client_reader, client_writer):
    """A minimal 'real' SOCKS5 upstream: no auth, CONNECT only."""
    try:
        methods = await socks.read_greeting(client_reader)
        client_writer.write(bytes([socks.VER, socks.METHOD_NOAUTH]))
        await client_writer.drain()
        cmd, host, port = await socks.read_request(client_reader)
        r, w = await asyncio.open_connection(host, port)
        client_writer.write(socks.pack_reply(socks.REP_OK))
        await client_writer.drain()

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
        await asyncio.gather(pipe(client_reader, w), pipe(r, client_writer),
                             return_exceptions=True)
    except Exception:
        pass


async def echo_server(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(b"echo:" + data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def socks5_client_connect(port, dest_host, dest_port, user=None, pw=None):
    """Minimal SOCKS5 client returning an open relay stream."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    methods = [0x00] + ([0x02] if user else [])
    writer.write(bytes([5, len(methods), *methods]))
    await writer.drain()
    ver, method = await reader.readexactly(2)
    assert ver == 5 and method != 0xFF, f"method rejected: {method}"
    if method == 0x02:
        u, p = user.encode(), (pw or "").encode()
        writer.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        _, status = await reader.readexactly(2)
        assert status == 0, "auth failed"
    writer.write(bytes([5, 1, 0]) + socks.pack_addr(dest_host)
                 + struct.pack("!H", dest_port))
    await writer.drain()
    hdr = await reader.readexactly(4)
    assert hdr[1] == 0, f"connect rep={hdr[1]}"
    await socks.read_addr(reader, hdr[3])
    return reader, writer


async def run_e2e():
    print("end-to-end:")
    with tempfile.TemporaryDirectory() as td:
        # --- infrastructure ---
        echo = await asyncio.start_server(echo_server, "127.0.0.1", 0)
        echo_port = echo.sockets[0].getsockname()[1]

        ups = await asyncio.start_server(dummy_upstream, "127.0.0.1", 0)
        ups_port = ups.sockets[0].getsockname()[1]

        store = Store(Path(td) / "pool.json")
        store.add(Proxy(host="127.0.0.1", port=ups_port))
        store.save()

        users = UserStore(Path(td) / "users.json")
        users.add("alice", "s3cret")

        cfg = dict(DEFAULT_CONFIG)
        cfg.update({"allow_private_dest": True, "strategy": "ordered",
                    "idle_timeout": 5.0, "handshake_timeout": 5.0,
                    "connect_timeout": 5.0, "audit_log": "audit.log"})
        audit = AuditLog(Path(td) / "audit.log")
        server = ProxyServer(store, cfg, users, audit)
        srv = await asyncio.start_server(server.handle, "127.0.0.1", 0)
        srv_port = srv.sockets[0].getsockname()[1]

        # --- 1. unauthenticated client must be rejected (auth required) ---
        r, w = await asyncio.open_connection("127.0.0.1", srv_port)
        w.write(bytes([5, 1, 0x00]))  # offer only no-auth
        await w.drain()
        _, method = await r.readexactly(2)
        check("auth required (0xFF when no userpass offered)", method == 0xFF)
        w.close()

        # --- 2. wrong password rejected ---
        r, w = await asyncio.open_connection("127.0.0.1", srv_port)
        w.write(bytes([5, 1, 0x02]))
        await w.drain()
        await r.readexactly(2)
        u, p = b"alice", b"wrong"
        w.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        _, status = await r.readexactly(2)
        check("bad password rejected", status == 0x01)
        w.close()

        # --- 3. happy path: auth + CONNECT + real bytes through upstream ---
        reader, writer = await socks5_client_connect(
            srv_port, "127.0.0.1", echo_port, "alice", "s3cret")
        writer.write(b"hello")
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(10), 5)
        check("relay bytes through upstream", data == b"echo:hello")
        writer.close()

        # --- 4. destination filter: private blocked when configured ---
        cfg["allow_private_dest"] = False
        server2 = ProxyServer(store, cfg, users, audit)
        srv2 = await asyncio.start_server(server2.handle, "127.0.0.1", 0)
        srv2_port = srv2.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", srv2_port)
        w.write(bytes([5, 1, 0x02]))
        await w.drain()
        await r.readexactly(2)
        u, p = b"alice", b"s3cret"
        w.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        await r.readexactly(2)
        w.write(bytes([5, 1, 0]) + socks.pack_addr("127.0.0.1")
                + struct.pack("!H", echo_port))
        await w.drain()
        hdr = await r.readexactly(4)
        check("private dest blocked (rep=2)", hdr[1] == socks.REP_NOT_ALLOWED)
        w.close()

        # --- 5. blocked port ---
        cfg["allow_private_dest"] = True
        server3 = ProxyServer(store, cfg, users, audit)
        srv3 = await asyncio.start_server(server3.handle, "127.0.0.1", 0)
        srv3_port = srv3.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", srv3_port)
        w.write(bytes([5, 1, 0x02]))
        await w.drain()
        await r.readexactly(2)
        w.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        await r.readexactly(2)
        w.write(bytes([5, 1, 0]) + socks.pack_addr("127.0.0.1")
                + struct.pack("!H", 25))  # SMTP - in default blocked_ports
        await w.drain()
        hdr = await r.readexactly(4)
        check("blocked port 25 (rep=2)", hdr[1] == socks.REP_NOT_ALLOWED)
        w.close()

        # --- 6. ACL deny ---
        cfg["acl_deny"] = ["127.0.0.0/8"]
        server4 = ProxyServer(store, cfg, users, audit)
        srv4 = await asyncio.start_server(server4.handle, "127.0.0.1", 0)
        srv4_port = srv4.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", srv4_port)
        w.write(bytes([5, 1, 0x02]))
        await w.drain()
        try:
            resp = await asyncio.wait_for(r.readexactly(2), 3)
            acl_closed = len(resp) < 2
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            acl_closed = True
        check("ACL deny closes connection", acl_closed)
        w.close()
        cfg["acl_deny"] = []

        # --- 7. audit log has the story ---
        await asyncio.sleep(0.1)
        events = [json.loads(l) for l in
                  Path(td, "audit.log").read_text().splitlines() if l.strip()]
        kinds = {e["event"] for e in events}
        check("audit: auth_failed", "auth_failed" in kinds)
        check("audit: connect", "connect" in kinds)
        check("audit: dest_blocked", "dest_blocked" in kinds)
        check("audit: acl_denied", "acl_denied" in kinds)

        for s in (srv, srv2, srv3, srv4, echo, ups):
            s.close()


def main():
    test_parsing()
    asyncio.run(run_e2e())
    failed = [n for n, ok in PASS if not ok]
    print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
