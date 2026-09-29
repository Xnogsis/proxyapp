"""Local SOCKS5 server: authenticates clients, enforces ACLs/destination
filters/limits, then tunnels traffic through a managed upstream pool."""
from __future__ import annotations

import asyncio
import hashlib
import random
import time

from . import socks
from .models import Proxy
from .security import AuditLog, ACL, Bucket, ConnLimiter, DestFilter, UserStore
from .store import Store

STRATEGIES = ("round-robin", "random", "fastest", "ordered", "sticky")


class ProxyServer:
    def __init__(self, store: Store, config: dict, users: UserStore,
                 audit: AuditLog):
        self.store = store
        self.cfg = config
        self.users = users
        self.audit = audit
        self.acl = ACL(config.get("acl_allow", []), config.get("acl_deny", []))
        self.filter = DestFilter(config)
        self.limiter = ConnLimiter(
            int(config.get("max_conn_per_ip", 50)),
            int(config.get("max_conn_total", 500)))
        self.strategy = config.get("strategy", "round-robin")
        self._rr = 0
        self._dirty_since: float | None = None
        self._server: asyncio.AbstractServer | None = None

    # -- upstream selection ---------------------------------------------------

    def _candidates(self, exclude: set[str]) -> list[Proxy]:
        self.store.reload()  # pick up external edits (check/import) by mtime
        cand = [p for p in self.store.all() if p.enabled and p.key not in exclude]
        alive = [p for p in cand if p.alive]
        return alive or cand

    def _pick(self, cand: list[Proxy], client_ip: str) -> Proxy | None:
        if not cand:
            return None
        if self.strategy == "random":
            return random.choice(cand)
        if self.strategy == "fastest":
            return min(cand, key=lambda p: p.latency_ms or 1e9)
        if self.strategy == "sticky":
            ordered = sorted(cand, key=lambda p: p.key)
            idx = int(hashlib.sha256(client_ip.encode()).hexdigest(), 16)
            return ordered[idx % len(ordered)]
        if self.strategy == "round-robin":
            self._rr = (self._rr + 1) % len(cand)
            return cand[self._rr]
        return cand[0]  # ordered

    def _mark_failure(self, p: Proxy) -> None:
        p.failures += 1
        p.consec_failures += 1
        p.checked_at = time.time()
        if p.consec_failures >= int(self.cfg.get("auto_disable_failures", 0) or 10**9):
            p.enabled = False
            p.alive = False
            self.audit.log("upstream_disabled", proxy=p.id,
                           reason=f"{p.consec_failures} consecutive failures")
        if self._dirty_since is None:
            self._dirty_since = time.time()

    def _mark_success(self, p: Proxy) -> None:
        p.successes += 1
        p.consec_failures = 0
        if self._dirty_since is None:
            self._dirty_since = time.time()

    async def _periodic_save(self):
        while True:
            await asyncio.sleep(60)
            if self._dirty_since is not None:
                self.store.save()
                self._dirty_since = None

    # -- connection handling ----------------------------------------------------

    async def _open_upstream(self, p: Proxy, host: str, port: int):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port),
            self.cfg.get("connect_timeout", 10.0))
        try:
            await socks.client_connect(reader, writer, host, port,
                                       p.username, p.password,
                                       self.cfg.get("connect_timeout", 10.0))
        except Exception:
            writer.close()
            raise
        return reader, writer

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "?"
        user = None
        upstream = None
        up_writer = None
        start = time.monotonic()
        hs_timeout = float(self.cfg.get("handshake_timeout", 10.0))
        idle = float(self.cfg.get("idle_timeout", 300.0))
        kbps = int(self.cfg.get("bandwidth_kbps", 0))
        bucket = Bucket(kbps * 1024.0) if kbps > 0 else None

        async def reply(rep: int):
            writer.write(socks.pack_reply(rep))
            await writer.drain()

        try:
            if not self.acl.allowed(client_ip):
                self.audit.log("acl_denied", client=client_ip)
                return
            if not self.limiter.acquire(client_ip):
                self.audit.log("rate_limited", client=client_ip)
                return
            try:
                methods = await asyncio.wait_for(
                    socks.read_greeting(reader), hs_timeout)

                # --- auth negotiation ---
                if self.users.require_auth:
                    if socks.METHOD_USERPASS not in methods:
                        writer.write(bytes([socks.VER, socks.METHOD_NONE]))
                        await writer.drain()
                        self.audit.log("auth_failed", client=client_ip,
                                       reason="no userpass method offered")
                        return
                    writer.write(bytes([socks.VER, socks.METHOD_USERPASS]))
                    await writer.drain()
                    user, pw = await asyncio.wait_for(
                        socks.read_auth(reader), hs_timeout)
                    if not self.users.verify(user, pw):
                        writer.write(b"\x01\x01")
                        await writer.drain()
                        self.audit.log("auth_failed", client=client_ip, user=user)
                        return
                    writer.write(b"\x01\x00")
                    await writer.drain()
                else:
                    if socks.METHOD_NOAUTH not in methods:
                        writer.write(bytes([socks.VER, socks.METHOD_NONE]))
                        await writer.drain()
                        return
                    writer.write(bytes([socks.VER, socks.METHOD_NOAUTH]))
                    await writer.drain()

                # --- request ---
                cmd, host, port = await asyncio.wait_for(
                    socks.read_request(reader), hs_timeout)
                dest = f"{host}:{port}"
                if cmd != socks.CMD_CONNECT:
                    await reply(socks.REP_CMD_UNSUPPORTED)
                    self.audit.log("bad_command", client=client_ip, user=user,
                                   cmd=cmd, dest=dest)
                    return

                reason = self.filter.check(host, port)
                if reason:
                    await reply(socks.REP_NOT_ALLOWED)
                    self.audit.log("dest_blocked", client=client_ip, user=user,
                                   dest=dest, reason=reason)
                    return

                # --- connect via upstream pool ---
                tried: set[str] = set()
                last_err = "no upstreams available"
                for _ in range(max(1, int(self.cfg.get("retries", 3)))):
                    p = self._pick(self._candidates(tried), client_ip)
                    if p is None:
                        break
                    tried.add(p.key)
                    try:
                        _ur, up_writer = await self._open_upstream(p, host, port)
                        upstream = p
                        self._mark_success(p)
                        break
                    except Exception as e:
                        last_err = f"{type(e).__name__}: {e}"
                        self._mark_failure(p)
                        up_writer = None

                if upstream is None or up_writer is None:
                    await reply(socks.REP_HOST_UNREACHABLE)
                    self.audit.log("connect_failed", client=client_ip, user=user,
                                   dest=dest, error=last_err, tried=len(tried))
                    return

                await reply(socks.REP_OK)
                self.audit.log("connect", client=client_ip, user=user, dest=dest,
                               upstream=upstream.id)

                up_reader = _ur
                n_up, n_down = await self._relay(
                    reader, writer, up_reader, up_writer, idle, bucket)
                self.audit.log(
                    "closed", client=client_ip, user=user, dest=dest,
                    upstream=upstream.id, bytes_up=n_up, bytes_down=n_down,
                    duration_s=round(time.monotonic() - start, 2))
            finally:
                self.limiter.release(client_ip)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, TimeoutError):
            pass
        except Exception as e:  # noqa: BLE001 - audit, never kill the listener
            self.audit.log("error", client=client_ip, user=user,
                           error=f"{type(e).__name__}: {e}")
        finally:
            if up_writer is not None:
                try:
                    up_writer.close()
                except OSError:
                    pass
            try:
                writer.close()
            except OSError:
                pass

    # -- relay --------------------------------------------------------------------

    async def _relay(self, cr, cw, ur, uw, idle_timeout: float, bucket):
        counters = {"up": 0, "down": 0, "last": time.monotonic()}

        async def pipe(r, w, key):
            try:
                while True:
                    data = await r.read(65536)
                    if not data:
                        break
                    if bucket:
                        await bucket.take(len(data))
                    w.write(data)
                    await w.drain()
                    counters[key] += len(data)
                    counters["last"] = time.monotonic()
            except (OSError, asyncio.IncompleteReadError, ConnectionError):
                pass
            try:
                w.write_eof()
            except (OSError, RuntimeError):
                pass

        tasks = {asyncio.create_task(pipe(cr, uw, "up")),
                 asyncio.create_task(pipe(ur, cw, "down"))}
        while tasks:
            done, tasks = await asyncio.wait(
                tasks, timeout=idle_timeout,
                return_when=asyncio.FIRST_COMPLETED)
            if done:
                break
            if time.monotonic() - counters["last"] > idle_timeout:
                break
        for t in tasks:
            t.cancel()
        return counters["up"], counters["down"]

    # -- lifecycle ------------------------------------------------------------------

    async def run(self, host: str, port: int) -> None:
        self._server = await asyncio.start_server(
            self.handle, host, port, limit=256 * 1024)
        saver = asyncio.create_task(self._periodic_save())
        sockets = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        print(f"SOCKS5 listening on {sockets}  strategy={self.strategy}  "
              f"auth={'required' if self.users.require_auth else 'off'}  "
              f"upstreams={len([p for p in self.store.all() if p.enabled])} enabled")
        try:
            await self._server.serve_forever()
        finally:
            saver.cancel()
            if self._dirty_since is not None:
                self.store.save()
