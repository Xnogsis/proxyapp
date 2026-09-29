"""SOCKS5 protocol helpers shared by the local server and the upstream checker.

Implements just enough of RFC 1928/1929: greeting, username/password
subnegotiation, CONNECT request/reply, address (de)serialisation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import struct

VER = 0x05
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
METHOD_NOAUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_NONE = 0xFF

REP_OK = 0x00
REP_GENERAL = 0x01
REP_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_REFUSED = 0x05
REP_CMD_UNSUPPORTED = 0x07
REP_ATYP_UNSUPPORTED = 0x08

REP_NAMES = {
    REP_OK: "ok", REP_GENERAL: "general failure", REP_NOT_ALLOWED: "not allowed",
    REP_NET_UNREACHABLE: "network unreachable", REP_HOST_UNREACHABLE: "host unreachable",
    REP_REFUSED: "connection refused", REP_CMD_UNSUPPORTED: "command unsupported",
    REP_ATYP_UNSUPPORTED: "address type unsupported",
}


class SocksError(Exception):
    """Protocol-level failure with an upstream or a malformed client request."""


def pack_addr(host: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return bytes([ATYP_IPV4]) + ip.packed
        return bytes([ATYP_IPV6]) + ip.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise SocksError("domain name too long")
        return bytes([ATYP_DOMAIN, len(encoded)]) + encoded


async def read_addr(reader: asyncio.StreamReader, atyp: int):
    if atyp == ATYP_IPV4:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif atyp == ATYP_IPV6:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif atyp == ATYP_DOMAIN:
        (n,) = await reader.readexactly(1)
        raw = await reader.readexactly(n)
        try:
            host = raw.decode("idna")
        except UnicodeError:
            host = raw.decode("utf-8", "replace")
    else:
        raise SocksError(f"unsupported atyp {atyp}")
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return host, port


def pack_reply(rep: int, host: str = "0.0.0.0", port: int = 0) -> bytes:
    try:
        addr = pack_addr(host)
    except SocksError:
        addr = pack_addr("0.0.0.0")
    return bytes([VER, rep, 0x00]) + addr + struct.pack("!H", port)


# --- server-side reads ------------------------------------------------------

async def read_greeting(reader: asyncio.StreamReader) -> list[int]:
    ver, nmethods = await reader.readexactly(2)
    if ver != VER:
        raise SocksError(f"bad version {ver}")
    return list(await reader.readexactly(nmethods))


async def read_auth(reader: asyncio.StreamReader):
    ver, ulen = await reader.readexactly(2)
    if ver != 0x01:
        raise SocksError(f"bad auth version {ver}")
    user = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")
    (plen,) = await reader.readexactly(1)
    pw = (await reader.readexactly(plen)).decode("utf-8", errors="replace")
    return user, pw


async def read_request(reader: asyncio.StreamReader):
    ver, cmd, _rsv, atyp = await reader.readexactly(4)
    if ver != VER:
        raise SocksError(f"bad version {ver}")
    host, port = await read_addr(reader, atyp)
    return cmd, host, port


# --- client-side (used against upstreams) -----------------------------------

async def client_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    dest_host: str,
    dest_port: int,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
) -> None:
    """Run a SOCKS5 handshake + CONNECT as a client. Raises SocksError on failure."""

    async def _do():
        methods = [METHOD_NOAUTH] + ([METHOD_USERPASS] if username else [])
        writer.write(bytes([VER, len(methods), *methods]))
        await writer.drain()
        ver, method = await reader.readexactly(2)
        if ver != VER:
            raise SocksError("upstream: bad greeting reply")
        if method == METHOD_NONE:
            raise SocksError("upstream: no acceptable auth method")
        if method == METHOD_USERPASS:
            u = (username or "").encode()
            p = (password or "").encode()
            if not u or len(u) > 255 or len(p) > 255:
                raise SocksError("upstream: bad credentials length")
            writer.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            aver, status = await reader.readexactly(2)
            if aver != 0x01 or status != 0x00:
                raise SocksError("upstream: auth rejected")
        elif method != METHOD_NOAUTH:
            raise SocksError(f"upstream: unsupported method {method:#x}")

        writer.write(bytes([VER, CMD_CONNECT, 0x00]) + pack_addr(dest_host)
                     + struct.pack("!H", dest_port))
        await writer.drain()
        ver, rep, _rsv, atyp = await reader.readexactly(4)
        if ver != VER:
            raise SocksError("upstream: bad reply")
        await read_addr(reader, atyp)  # consume bound addr
        if rep != REP_OK:
            raise SocksError(f"upstream: connect failed ({REP_NAMES.get(rep, rep)})")

    await asyncio.wait_for(_do(), timeout)
