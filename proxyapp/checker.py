"""Health checks: TCP connect + real SOCKS5 handshake through each upstream,
optionally fetching the exit IP via a plain-HTTP target."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time

from .models import Proxy
from .socks import client_connect, SocksError

_BODY_IP_RE = re.compile(rb"^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s*$")


async def check_proxy(
    p: Proxy,
    target_host: str = "api.ipify.org",
    target_port: int = 80,
    fetch_ip: bool = True,
    timeout: float = 8.0,
    stage=None,
) -> tuple[bool, float | None, str | None, str | None]:
    """Returns (ok, latency_ms, exit_ip, error). `stage(p, text)` is called
    before each step so callers can show live progress."""
    say = (lambda t: stage(p, t)) if stage else (lambda t: None)
    t0 = time.monotonic()
    writer = None
    try:
        say(f"opening TCP connection to {p.host}:{p.port}")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port), timeout)
        say(f"SOCKS5 handshake, asking proxy to connect to {target_host}:{target_port}")
        await client_connect(reader, writer, target_host, target_port,
                             p.username, p.password, timeout)
        latency = (time.monotonic() - t0) * 1000.0
        exit_ip = None
        if fetch_ip and target_port == 80:
            say(f"sending HTTP request through proxy to read exit IP from {target_host}")
            writer.write(
                f"GET / HTTP/1.1\r\nHost: {target_host}\r\n"
                f"User-Agent: proxyapp-check\r\nConnection: close\r\n\r\n"
                .encode())
            await asyncio.wait_for(writer.drain(), timeout)
            data = await asyncio.wait_for(reader.read(8192), timeout)
            body = data.split(b"\r\n\r\n", 1)[-1]
            m = _BODY_IP_RE.match(body)
            if m:
                try:
                    exit_ip = str(ipaddress.ip_address(m.group(1).decode()))
                except ValueError:
                    pass
        return True, latency, exit_ip, None
    except (asyncio.TimeoutError, TimeoutError):
        return False, None, None, "timeout"
    except SocksError as e:
        return False, None, None, str(e)
    except (OSError, asyncio.IncompleteReadError, ConnectionError) as e:
        return False, None, None, f"{type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001 - never let one proxy kill the batch
        return False, None, None, f"{type(e).__name__}: {e}"
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass


async def check_tls(p: Proxy, host: str = "example.com", timeout: float = 8.0,
                    stage=None) -> None:
    """Detect TLS interception: open a TLS session to `host` through the proxy
    and verify the certificate chain against the system trust store.
    Sets p.tls_ok (None if the test couldn't complete)."""
    import ssl
    writer = None
    try:
        if stage:
            stage(p, f"verifying HTTPS certificate of {host}:443 through proxy (MITM check)")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port), timeout)
        await client_connect(reader, writer, host, 443, p.username, p.password, timeout)
        ctx = ssl.create_default_context()
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
        p.tls_ok = True
    except ssl.SSLCertVerificationError as e:
        p.tls_ok = False
        p.last_error = f"TLS interception: {e.verify_message}"
    except Exception:  # noqa: BLE001 - inconclusive, leave tls_ok unchanged
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass


async def check_many(
    proxies: list[Proxy],
    target_host: str = "api.ipify.org",
    target_port: int = 80,
    fetch_ip: bool = True,
    timeout: float = 8.0,
    concurrency: int = 100,
    progress=None,
    tls: bool = False,
    stage=None,
) -> None:
    """Check proxies concurrently, updating each Proxy's stats in place."""
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(p: Proxy):
        nonlocal done
        async with sem:
            ok, latency, exit_ip, err = await check_proxy(
                p, target_host, target_port, fetch_ip, timeout, stage)
            if ok and tls:
                await check_tls(p, timeout=timeout, stage=stage)
        p.checked_at = time.time()
        if ok:
            p.alive, p.latency_ms = True, latency
            if p.tls_ok is not False:
                p.last_error = None
            p.successes += 1
            p.consec_failures = 0
            if exit_ip:
                p.exit_ip = exit_ip
        else:
            p.alive, p.last_error = False, err
            p.failures += 1
            p.consec_failures += 1
        done += 1
        if progress:
            progress(done, len(proxies), p, ok)

    await asyncio.gather(*(one(p) for p in proxies))
