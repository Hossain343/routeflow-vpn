# VPN Share Proxy (Rust)

One port, SOCKS5 (TCP + UDP) and HTTP/HTTPS-CONNECT. Iranian destinations leave through the modem,
everything else goes through "ip net" (the Windows system proxy / PAC / a manual proxy / a
system-wide VPN). The settings UI is a web page on 127.0.0.1 (opened automatically).

## Build (Windows)

    rustup default stable          # 1.80 or newer, MSVC toolchain
    cargo build --release
    target\release\vpnshare.exe    # run as Administrator once (firewall rule); needs nothing else

`cargo test` runs the unit tests (parsers, matchers, DNS packets, SNI, HTTP framing, installer rollback).

## Files next to vpnshare.exe

| file | purpose |
|---|---|
| `config.json` | settings (the old Python config.json loads unchanged) |
| `router_divert.json` | domains / IPs / CIDRs that ALWAYS go through the modem |
| `vpn_divert.json` | domains / IPs / CIDRs that ALWAYS go through the VPN |
| `RIPE_IR.json` | Iranian IP ranges (the release has none, see below) |
| `data/iran-hosted-domains/` | every downloaded release file |
| `data/release.json` | manifest: tag, time, size + SHA-256 of each file, verified yes/no |
| `vpnshare.log` | rotating log (5 MB), the UI shows the last 100 lines |

## Routing order (first match wins)

Domains: router_divert, vpn_divert, ads block (optional) -> BLOCK, proxy category (optional) -> VPN,
Iran list -> modem, `*.ir` (optional) -> modem, everything else -> VPN with no lookup at all.
IPs: router_divert, vpn_divert, LAN, Iranian ranges (RIPE_IR.json) -> modem, everything else -> VPN.

## Known limits

* The program has never been compiled or run on Windows by its author's tooling; expect to fix a few compile errors.
* `IP_UNICAST_IF` (forcing a socket out of the modem card while a VPN owns the default route) does not
  help if the VPN installs a firewall kill-switch that blocks non-tunnel traffic.
* PAC files are not executed (no JavaScript engine): the first SOCKS/PROXY literal is used.
* IPv6 names are not looked up through the modem (A records only).
* UDP over an HTTP-only upstream is impossible and is logged, never silently dropped.
