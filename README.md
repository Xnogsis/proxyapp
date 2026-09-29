# proxytui

A simple terminal app for Windows that lets you load lists of SOCKS5 proxies, test them, and route your traffic through the one you pick, with safety checks built in.

```
proxytui  ROUTING via 123.58.219.171:10808  | local 127.0.0.1:1080 | system proxy ON | internet OK | kill-switch off
  STATUS   CC   LATENCY  PROXY                             EXIT IP         sort:latency
> alive    CN     478ms  123.58.219.171:10808              123.58.219.171
  alive    US     512ms  72.195.34.58:4145                 72.195.34.58
  MITM     US     365ms  199.66.182.243:4145               199.66.182.243  TLS interception: self-signed certificate
  checking  -         -  98.191.0.47:4145                  -               SOCKS5 handshake, asking proxy to connect to api.ipify.org:80
  dead      -         -  5.255.99.75:1080                  -               timeout
```

## Features

- **Load lists easily:** reads every `.txt` file in the `proxys\` folder, and you can also paste a list from the clipboard. Duplicates are merged and invalid lines are skipped.
- **Check all proxies at once:** 50 at a time, with live progress showing which proxy is being tested and at which step.
- **Safety checks** for each proxy:
  - **MITM detection:** flags proxies that fake HTTPS certificates to read your encrypted traffic.
  - **Leak detection:** flags proxies that pass your real IP through.
- **Country, latency and exit IP** for every working proxy, with sorting.
- **One-key auto-connect:** re-tests the fastest safe proxies, then connects to the first one that passes.
- **Windows system proxy toggle:** browsers and most apps follow it. Your original setting is always restored, even if you close the window.
- **Auto-failover:** switches to the next working proxy when the current one dies, or restores direct internet if none are left.
- **Optional kill-switch:** blocks all traffic instead of falling back to a direct connection.
- **Log view:** shows connections, failovers, checks and errors.
- **Saved results:** check results are remembered between runs.

## Requirements

- Windows 10 or 11
- Python 3.10 or newer (tested on 3.14). It uses only the standard library, so there's nothing to `pip install`.

## Quick start

1. Put one or more proxy list files (`.txt`) into the `proxys\` folder.
2. Double-click **`ProxyTUI.bat`**, or run:
   ```powershell
   python proxytui.py
   ```
3. Press **`c`** to check all proxies, then **`a`** to auto-connect.
4. Press **`Esc`** to disconnect, and **`q`** to quit.

To use the proxy in a single app without changing Windows settings, route with `Enter` and point the app at **`127.0.0.1:1080`**. That port accepts SOCKS5, SOCKS4/4a and HTTP proxy connections.

### Supported list formats

One proxy per line. Blank lines and lines starting with `#` are ignored.

```
socks5://1.2.3.4:1080
socks5://user:pass@1.2.3.4:1080
1.2.3.4:1080
1.2.3.4:1080:user:pass
user:pass@1.2.3.4:1080
```

## Keys

| Key | Action |
|---|---|
| `↑` `↓` `PgUp` `PgDn` `Home` `End` | Move |
| `Enter` | Route through the selected proxy (press again to stop) |
| `Esc` | Disconnect: stop routing and restore the Windows proxy setting |
| `a` | Auto-connect: re-test the 5 fastest safe proxies, connect to the first that passes, and turn on the system proxy |
| `c` | Check all proxies |
| `t` | Detailed test of the selected proxy |
| `w` | Toggle the Windows system proxy (needs a routed proxy) |
| `k` | Toggle the kill-switch |
| `e` | Save working proxies to `proxys\working.txt` |
| `Tab` | Switch between the proxy list and the log view |
| `r` | Reload the `proxys\` folder (adds new files and lines) |
| `l` | Load a file or folder |
| `v` | Paste a list from the clipboard |
| `s` | Cycle sort: latency, ip, port, status, country |
| `d` | Delete the selected proxy |
| `x` | Drop all dead, MITM and LEAK proxies |
| `q` | Quit (restores the system proxy) |

## What "check all" does

1. Makes sure **your internet works** first. If you're offline, nothing is tested and no results change.
2. For each proxy (6 seconds per step):
   - opens a **TCP connection** to the proxy
   - does a **SOCKS5 handshake** and asks the proxy to connect to `api.ipify.org:80`. The latency shown is the time for this and the connection step.
   - sends an HTTP request through the proxy to read its **exit IP**
   - opens **HTTPS to `example.com`** through the proxy and verifies the certificate against the Windows trust store. A fake certificate means **MITM**.
3. Compares each exit IP with **your real IP**. A match means **LEAK**.
4. Looks up the **country** of each exit IP.

| Status | Meaning |
|---|---|
| `alive` (green) | Works, HTTPS is untouched, and it hides your IP |
| `MITM` (red) | Intercepts HTTPS with fake certificates. **Can read your traffic. Never use it.** |
| `LEAK` (red) | Passes your real IP through |
| `dead` | Timed out, refused the connection, or failed the handshake. The reason is shown at the end of the row. |
| `untested` | Not checked yet |

The app refuses to route through MITM or LEAK proxies.

## Security notes

- **Treat public proxies as untrusted.** Whoever runs the proxy can see and log unencrypted (HTTP) traffic and which sites you connect to. Only HTTPS content is protected, and only from proxies that aren't MITM. In testing, several proxies from public lists turned out to be MITM.
- The local port listens on `127.0.0.1` only, so other devices can't use it. It never falls back to a direct connection on its own, and it blocks requests to private/LAN addresses.
- The Windows system proxy only covers apps that respect it: browsers and most Windows apps. Some programs, many games, and all UDP traffic ignore it. This is **not a VPN**.
- Country lookups send only the proxies' IP addresses to [ip-api.com](https://ip-api.com), never your traffic.
- `data\proxytui.log` records which sites you connected to. It stays on your machine and is excluded from git.

## Files

| Path | Purpose |
|---|---|
| `proxytui.py` | The app |
| `ProxyTUI.bat` | Double-click launcher |
| `proxys\` | Your proxy lists (ignored by git) |
| `data\` | Logs, saved check results, system-proxy backup (ignored by git) |
| `proxyapp\` | Shared modules: list parsing, SOCKS5 protocol, checker. It also contains an older command-line pool manager (`python -m proxyapp --help`). |
| `test_tui.py`, `selftest.py` | Tests |

## Tests

```powershell
python test_tui.py
python selftest.py
```

The tests use local dummy servers, need no internet, and never touch your real Windows proxy settings.

## Disclaimer

For personal and educational use. Only use proxies you're allowed to use, and follow the laws and terms of service that apply to you.
