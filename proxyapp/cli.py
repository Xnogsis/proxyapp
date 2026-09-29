"""Command-line interface.

Usage: python -m proxyapp <command> ...

Data lives in ./data/ (override with PROXYAPP_HOME).
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import ipaddress
import json
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

from . import __version__, checker
from .models import Proxy, group_key, parse_lines, parse_proxy, sort_key
from .security import AuditLog, UserStore
from .server import ProxyServer, STRATEGIES
from .store import Config, Store, data_path

SORTS = "ip, host, port, latency, added, score, success, checked, status"
GROUPS = "subnet, port, status, tag, scheme, auth"


# --- helpers ------------------------------------------------------------------

def _eprint(*a):
    print(*a, file=sys.stderr)


def _fetch_text(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "proxyapp/0.1"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    return Path(source).read_text(encoding="utf-8", errors="replace")


def _fmt_latency(p: Proxy) -> str:
    return f"{p.latency_ms:.0f}ms" if p.latency_ms is not None else "-"


def _fmt_row(p: Proxy) -> str:
    tags = ",".join(p.tags) if p.tags else "-"
    exit_ip = p.exit_ip or "-"
    enabled = "" if p.enabled else " [disabled]"
    return (f"{p.id:<42} {p.status:<8} {_fmt_latency(p):>8}  "
            f"{exit_ip:<15} {p.successes}/{p.failures:<5} {tags}{enabled}")


def _filter(proxies: list[Proxy], args) -> list[Proxy]:
    out = proxies
    if getattr(args, "alive", False):
        out = [p for p in out if p.alive is True]
    if getattr(args, "dead", False):
        out = [p for p in out if p.alive is False]
    if getattr(args, "untested", False):
        out = [p for p in out if p.alive is None]
    if getattr(args, "enabled", False):
        out = [p for p in out if p.enabled]
    if getattr(args, "disabled", False):
        out = [p for p in out if not p.enabled]
    if getattr(args, "tag", None):
        out = [p for p in out if args.tag in p.tags]
    return out


def _resolve_ids(store: Store, ids: list[str]) -> tuple[list[Proxy], list[str]]:
    found, missing = [], []
    for ident in ids:
        p = store.find(ident)
        (found if p else missing).append(p or ident)
    return found, missing


def _parse_host_port(s: str, default_port: int = 80):
    if ":" in s:
        host, _, port = s.rpartition(":")
        return host, int(port)
    return s, default_port


# --- commands -----------------------------------------------------------------

def cmd_import(args) -> int:
    store = Store()
    added = dup = bad = 0
    for src in args.sources:
        try:
            text = _fetch_text(src)
        except Exception as e:
            _eprint(f"{src}: {e}")
            continue
        for _ln, p, err in parse_lines(text):
            if err:
                bad += 1
                _eprint(f"{src}: {err}")
                continue
            if args.tag:
                p.tags = sorted(set(p.tags) | {args.tag})
            if store.add(p):
                added += 1
            else:
                dup += 1
    store.save()
    print(f"imported {added}  duplicates {dup}  invalid {bad}  "
          f"pool total {len(store.all())}")
    return 0


def cmd_add(args) -> int:
    store = Store()
    ok = 0
    for spec in args.proxies:
        try:
            p = parse_proxy(spec)
        except ValueError as e:
            _eprint(f"{spec}: {e}")
            continue
        if args.tag:
            p.tags = sorted(set(p.tags) | {args.tag})
        if store.add(p):
            ok += 1
            print(f"+ {p.to_uri(hide_password=True)}")
        else:
            _eprint(f"{spec}: duplicate")
    store.save()
    _eprint(f"{ok} added, pool total {len(store.all())}")
    return 0


def cmd_list(args) -> int:
    store = Store()
    proxies = _filter(store.all(), args)
    proxies.sort(key=sort_key(args.sort))

    if args.uri:
        for p in proxies[: args.limit or None]:
            print(p.to_uri(hide_password=args.hide_passwords))
        return 0

    if args.group:
        gk = group_key(args.group)
        groups: dict[str, list[Proxy]] = {}
        for p in proxies:
            groups.setdefault(gk(p), []).append(p)
        for name in sorted(groups):
            members = groups[name]
            print(f"\n== {name} ({len(members)}) ==")
            for p in members[: args.limit or None]:
                print("  " + _fmt_row(p))
        print(f"\n{len(proxies)} proxies in {len(groups)} groups")
    else:
        for p in proxies[: args.limit or None]:
            print(_fmt_row(p))
        print(f"\n{len(proxies)} proxies")
    return 0


def cmd_check(args) -> int:
    store = Store()
    cfg = Config().as_dict()
    if args.ids:
        proxies, missing = _resolve_ids(store, args.ids)
        for m in missing:
            _eprint(f"not found: {m}")
    else:
        proxies = _filter(store.all(), args)
        proxies = [p for p in proxies if p.enabled]
        if not (args.alive or args.dead or args.untested or args.tag):
            pass  # default: check all enabled
    if not proxies:
        _eprint("nothing to check")
        return 1

    host, port = _parse_host_port(args.target or cfg["check_target"])
    timeout = args.timeout or cfg["check_timeout"]
    conc = args.concurrency or cfg["check_concurrency"]

    def progress(done, total, p, ok):
        mark = "ok  " if ok else "FAIL"
        print(f"\r[{done}/{total}] {mark} {p.id:<40} "
              f"{_fmt_latency(p) if ok else (p.last_error or '')[:50]}",
              end="", flush=True)
        if done == total:
            print()

    asyncio.run(checker.check_many(
        proxies, host, port, fetch_ip=not args.no_ip,
        timeout=timeout, concurrency=conc, progress=progress))
    store.save()
    alive = sum(1 for p in proxies if p.alive)
    print(f"\n{alive}/{len(proxies)} alive")
    return 0


def cmd_remove(args) -> int:
    store = Store()
    doomed: list[Proxy] = []
    if args.ids:
        found, missing = _resolve_ids(store, args.ids)
        doomed.extend(found)
        for m in missing:
            _eprint(f"not found: {m}")
    doomed.extend(_filter(store.all(), args) if not args.ids else [])
    keys = {p.key for p in doomed}
    if not keys:
        _eprint("nothing matched")
        return 1
    for k in keys:
        store.remove(k)
    store.save()
    print(f"removed {len(keys)}; pool total {len(store.all())}")
    return 0


def cmd_set_enabled(args, enabled: bool) -> int:
    store = Store()
    if args.all:
        targets = store.all()
    else:
        targets, missing = _resolve_ids(store, args.ids)
        for m in missing:
            _eprint(f"not found: {m}")
    for p in targets:
        p.enabled = enabled
    store.save()
    print(f"{'enabled' if enabled else 'disabled'} {len(targets)}")
    return 0


def cmd_tag(args) -> int:
    store = Store()
    targets, missing = _resolve_ids(store, args.ids)
    for m in missing:
        _eprint(f"not found: {m}")
    add = {t.lstrip("+") for t in args.tags if not t.startswith("-")}
    rem = {t[1:] for t in args.tags if t.startswith("-")}
    for p in targets:
        p.tags = sorted((set(p.tags) | add) - rem)
        print(f"{p.id}: tags={','.join(p.tags) or '-'}")
    store.save()
    return 0


def cmd_export(args) -> int:
    store = Store()
    proxies = _filter(store.all(), args)
    proxies.sort(key=sort_key("ip"))
    lines = "\n".join(p.to_uri() for p in proxies) + "\n"
    if args.output:
        Path(args.output).write_text(lines, encoding="utf-8")
        print(f"wrote {len(proxies)} -> {args.output}")
    else:
        sys.stdout.write(lines)
    return 0


def cmd_serve(args) -> int:
    cfg = Config()
    store = Store()
    users = UserStore()
    audit = AuditLog(data_path(cfg.get("audit_log")))
    server = ProxyServer(store, cfg.as_dict(), users, audit)
    if args.strategy:
        server.strategy = args.strategy
    host = args.host or cfg.get("bind_host")
    port = args.port or int(cfg.get("bind_port"))
    try:
        asyncio.run(server.run(host, port))
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_user(args) -> int:
    users = UserStore()
    if args.action == "list":
        for n in users.names():
            print(n)
        print(f"{len(users.names())} users; auth {'ON' if users.require_auth else 'OFF'}")
        return 0
    if args.action == "add":
        pw = args.password or getpass.getpass(f"password for {args.name}: ")
        users.add(args.name, pw)
        print(f"added user {args.name}")
        return 0
    if args.action == "remove":
        print("removed" if users.remove(args.name) else "no such user")
        return 0
    return 1


def cmd_acl(args) -> int:
    cfg = Config()
    if args.action == "list":
        print("allow:", ", ".join(cfg.get("acl_allow")) or "(all)")
        print("deny :", ", ".join(cfg.get("acl_deny")) or "(none)")
        return 0
    key = "acl_allow" if args.action == "allow" else "acl_deny"
    lst = list(cfg.get(key))
    if args.action == "remove":
        for k in ("acl_allow", "acl_deny"):
            lst2 = [c for c in cfg.get(k) if c != args.cidr]
            cfg.set(k, lst2)
        print(f"removed {args.cidr}")
        return 0
    try:
        ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        _eprint(f"bad CIDR: {e}")
        return 1
    if args.cidr not in lst:
        lst.append(args.cidr)
    cfg.set(key, lst)
    print(f"{key}: {', '.join(lst)}")
    return 0


def cmd_config(args) -> int:
    cfg = Config()
    if args.action == "set":
        raw = args.value
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = raw
        try:
            cfg.set(args.key, value)
        except KeyError as e:
            _eprint(str(e))
            return 1
        print(f"{args.key} = {cfg.get(args.key)!r}")
        return 0
    for k, v in sorted(cfg.as_dict().items()):
        print(f"{k:<24} {v!r}")
    return 0


def cmd_stats(args) -> int:
    store = Store()
    proxies = store.all()
    by_status = {"alive": 0, "dead": 0, "untested": 0}
    for p in proxies:
        by_status[p.status] += 1
    enabled = sum(1 for p in proxies if p.enabled)
    lat = [p.latency_ms for p in proxies if p.alive and p.latency_ms]
    print(f"pool: {len(proxies)} total, {enabled} enabled")
    print(f"      {by_status['alive']} alive, {by_status['dead']} dead, "
          f"{by_status['untested']} untested")
    if lat:
        print(f"latency: min {min(lat):.0f}ms  avg {sum(lat)/len(lat):.0f}ms  "
              f"max {max(lat):.0f}ms")
    top = sorted((p for p in proxies if p.alive),
                 key=lambda p: p.latency_ms or 1e9)[:5]
    if top:
        print("fastest:")
        for p in top:
            print(f"  {_fmt_latency(p):>8}  {p.id}")
    audit = AuditLog(data_path(Config().get("audit_log")))
    events = audit.tail(args.events)
    if events:
        print(f"\nrecent audit events ({len(events)}):")
        for e in events:
            ts = e.get("ts", "")[5:19].replace("T", " ")
            details = " ".join(f"{k}={v}" for k, v in e.items()
                               if k not in ("ts", "event"))
            print(f"  {ts}  {e.get('event',''):<16} {details}")
    return 0


# --- parser ---------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="proxyapp",
        description="SOCKS5 upstream proxy pool manager + secure local endpoint")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("import", help="import proxies from files/URLs ('-' = stdin)")
    p.add_argument("sources", nargs="+")
    p.add_argument("-t", "--tag", help="tag applied to imported proxies")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("add", help="add proxies from the command line")
    p.add_argument("proxies", nargs="+")
    p.add_argument("-t", "--tag")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("list", help="list pool (sort/group/filter)")
    p.add_argument("-s", "--sort", default="added", help=SORTS)
    p.add_argument("-g", "--group", help=GROUPS)
    p.add_argument("-n", "--limit", type=int)
    p.add_argument("--alive", action="store_true")
    p.add_argument("--dead", action="store_true")
    p.add_argument("--untested", action="store_true")
    p.add_argument("--enabled", action="store_true")
    p.add_argument("--disabled", action="store_true")
    p.add_argument("--tag")
    p.add_argument("--uri", action="store_true", help="print socks5:// URIs")
    p.add_argument("--hide-passwords", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("check", help="health-check proxies via real SOCKS5 handshake")
    p.add_argument("ids", nargs="*", help="specific proxies; default = all enabled")
    p.add_argument("--alive", action="store_true")
    p.add_argument("--dead", action="store_true")
    p.add_argument("--untested", action="store_true")
    p.add_argument("--tag")
    p.add_argument("--target", help="host[:port] test target (default from config)")
    p.add_argument("--timeout", type=float)
    p.add_argument("--concurrency", type=int)
    p.add_argument("--no-ip", action="store_true", help="skip exit-IP fetch")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("remove", help="remove proxies by id or filter")
    p.add_argument("ids", nargs="*")
    p.add_argument("--dead", action="store_true")
    p.add_argument("--untested", action="store_true")
    p.add_argument("--disabled", action="store_true")
    p.add_argument("--alive", action="store_true")
    p.add_argument("--tag")
    p.set_defaults(fn=cmd_remove)

    for name, flag in (("enable", True), ("disable", False)):
        p = sub.add_parser(name, help=f"{name} proxies")
        p.add_argument("ids", nargs="*")
        p.add_argument("--all", action="store_true")
        p.set_defaults(fn=lambda a, f=flag: cmd_set_enabled(a, f))

    p = sub.add_parser("tag", help="edit tags: tag host:port +new -old")
    p.add_argument("ids", nargs="+")
    p.add_argument("tags", nargs="+")
    p.set_defaults(fn=cmd_tag)

    p = sub.add_parser("export", help="print pool as socks5:// URIs")
    p.add_argument("-o", "--output")
    p.add_argument("--alive", action="store_true")
    p.add_argument("--enabled", action="store_true")
    p.add_argument("--tag")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("serve", help="run the local SOCKS5 endpoint")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--strategy", choices=STRATEGIES)
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("user", help="manage local auth users")
    p.add_argument("action", choices=["add", "remove", "list"])
    p.add_argument("name", nargs="?")
    p.add_argument("--password", help="(prefer interactive prompt)")
    p.set_defaults(fn=cmd_user)

    p = sub.add_parser("acl", help="client IP allow/deny lists")
    p.add_argument("action", choices=["list", "allow", "deny", "remove"])
    p.add_argument("cidr", nargs="?")
    p.set_defaults(fn=cmd_acl)

    p = sub.add_parser("config", help="view/set configuration")
    p.add_argument("action", choices=["list", "set"], nargs="?", default="list")
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("stats", help="pool stats + recent audit events")
    p.add_argument("--events", type=int, default=15)
    p.set_defaults(fn=cmd_stats)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd in ("user", "acl") and getattr(args, "name", getattr(args, "cidr", True)) is None \
            and getattr(args, "action", "") != "list":
        _eprint(f"{args.cmd}: missing argument")
        return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
