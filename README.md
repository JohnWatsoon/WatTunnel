<div align="center">

<img src="docs/img/banner.jpg" alt="WatTunnel: stay connected, even when only ping gets through" width="100%">

# 🪁 WatTunnel

**Encrypted Iran ↔ Kharej port forwarding that keeps working when the network is filtered, even when only ping gets through.**

[![Release](https://img.shields.io/badge/release-v3.4.2-blue?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64%20%7C%20windows-lightgrey?style=flat-square)
[![Telegram Channel](https://img.shields.io/badge/Channel-@WatxDev-26A5E4?style=flat-square&logo=telegram)](https://t.me/WatxDev)
[![Telegram](https://img.shields.io/badge/Contact-@watxox-26A5E4?style=flat-square&logo=telegram)](https://t.me/watxox)

**English** · [فارسی](README.fa.md)

</div>

---

## Install

You need two Linux servers (amd64 or arm64) with systemd and root. **Set up Kharej first**: it makes the token that
Iran needs.

**1. Install on both servers**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

<details>
<summary>GitHub is blocked on the Iran server? (Offline install &amp; update)</summary>

**Recommended — signed offline bundle (no GitHub needed on Iran):**

1. On **Kharej** (after installing WatTunnel there), build a verified archive:

```bash
wattun bundle amd64          # writes wattun-offline-amd64.tar.gz (or arm64)
scp wattun-offline-amd64.tar.gz root@IRAN_IP:/root/
```

2. On **Iran**, install or update from that file (checked against the pinned RSA release signature):

```bash
# Fresh install:
tar xzf /root/wattun-offline-amd64.tar.gz -C /root && bash /root/wattun-offline-amd64/install.sh

# Update an existing install later:
wattun update --from /root/wattun-offline-amd64.tar.gz
```

**Alternative — mirror or SOCKS5/HTTP proxy:**

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
# or with a local SOCKS5/HTTP proxy:
WAT_CURL_PROXY=socks5h://127.0.0.1:1080 bash install.sh
```

In `wattun` → `s` (Settings) → `p`, you can save a mirror or proxy URL once so future `wattun update` runs use it automatically. You can also download `wattun-linux-amd64`, `install.sh`, `wattun-manager`, `SHA256SUMS` and `SHA256SUMS.sig` from [releases](https://github.com/JohnWatsoon/WatTunnel/releases) into one folder and run `bash install.sh`.
</details>

**2. Kharej.** Run `wattun`, press `n` (new tunnel), choose **Kharej**, and pick **Auto** as the connection type. You
get a token:

```
wat1:aWNtcHwyMDMuMC4xMTMuMTB8a1E3...
```

**3. Iran.** Run `wattun`, press `n`, choose **Iran**, and paste the token. The menu tests every connection type and
offers the fastest that works: press **Enter** to take it. Then enter your ports, for example `443, 8443:443, 53/udp`
(`8443:443` means users connect to Iran port 8443 and reach Kharej port 443).

```
  ✔ Writing key and config
  ✔ Starting wattun@iran
  ✔ CONNECTED (RTT 41.3 ms)

  users ──► Iran :8443 ══ tcp ══► Kharej ──► 127.0.0.1:443
```

Done. Users connect to the Iran server's IP, and Kharej forwards only to its own `127.0.0.1`.

> **Important (avoid Iran IP filtering):** WatTunnel encrypts only **Iran ↔ Kharej**. Your panel inbound on Kharej (the config you give end users) **must also be encrypted** — use **VLESS+Reality**, **VLESS+WS+TLS**, **VLESS Encryption (PQ)**, or **Shadowsocks 2022**. Plain `VLESS + TCP header` is unencrypted between the user and your Iran server, so Iranian ISP DPI detects and blocks the Iran IP.

**Auto uses data.** The manager prints the worst case before it starts: up to 1184 MB for a normal test, and far less on a filtered route (the *+ Extended* test preset adds the 13 shaped carriers, up to 416 MB more). On a traffic-billed server, pick a type yourself:

| Your route | Use |
|---|---|
| Only ping passes | `icmp` |
| UDP passes | `udp` (lowest latency) |
| TCP passes | `tcp`, or `tls` to look like HTTPS |
| Only a CDN gets out, or SNI is filtered | `wss` through Cloudflare ([CDN setup](docs/TECHNICAL.md#cdn-tuning)) |
| Only Kharej can reach Iran | any of the above with [reverse mode](docs/TECHNICAL.md#reverse-mode) |

## Day to day

`wattun` opens the dashboard. Press a tunnel's number for its page (logs, diagnose, speed test, ports, change connection
type with **c**), `u` updates, and `s` holds rollback and auto-heal. Auto-heal restarts an Iran tunnel whose link has
been down for 3 minutes.

```bash
wattun status          # one line per tunnel
wattun test NAME       # connection doctor + speed test
wattun ports NAME      # edit port mappings (applied live)
wattun bundle          # build a signed offline archive on Kharej for Iran
wattun update          # update the binary and the menu (or: wattun update --from FILE.tar.gz)
```

| Status | Meaning |
|---|---|
| `up` | The link works (including when an auto tunnel connects over a background carrier) |
| `partial` | The link works but a bond leg is down; the tunnel page shows how many |
| `waiting` / `down` | No link (`waiting` on Kharej, `down` on Iran) |
| `unknown` | The tunnel's stats did not answer, so the state is not known |
| `stopped` | The service is not running |

**Always-open Auto & random ports.** An auto Kharej tunnel appears as one unified entry and keeps all test carriers
open automatically in the background on verified-free random high ports (`10000..32767`, never taking `443`, `80`,
`8080`, or `8443` unless you ask or pass `--cdn-domain`), so Iran can re-test (`wattun auto-test NAME`), bond, or
auto-heal failover at any time without port conflicts or manual carrier toggles. Existing 3.3.3–3.3.7 narrowed or
finalized tunnels reopen automatically on update.

## Scepter: pair once, manage from Iran

3.5.0 adds an optional pairing between the two servers (both ends need 3.5.0) and makes it automatic — the
setup has no manual pairing steps: install on Kharej and let the wizard create tunnel 1 (the token it prints
ONCE carries the pairing inside it, and the wizard writes the latch port for you), install on Iran and paste
that token, and the cockpit is live. The token only starts the pairing: the first Iran that connects
receives its own fresh key, and after that the token alone cannot manage Kharej (it still runs the tunnel).
No SSH to Kharej after setup. The tunnel then carries a hidden, encrypted
management channel — a reserved stream inside the session's encryption, with a capability tier on the
credential (`tunnel` < `create` < `manage` < `full`) and every command checked, rate-limited and journaled on
Kharej. If the tunnel dies, revival is automatic: it keeps dialing on its own, and a client config that also
carries the latch port contacts Kharej's **scepter latch** — a shaped wss listener that arms while every unit
of the pair is down — first after 30 seconds, then less often up to every 10 minutes, until the channel is
back; a contact must prove the 32-byte pairing key before anything is served, and the listener closes again
on first contact. Reverse tunnels need no latch: Kharej keeps dialing Iran by itself. The channel never
appears on any dashboard; only the doctor sees it. Rotating the pairing key works from the cockpit or the
Kharej console; revoking stays a Kharej-console action (Pairing: revoke) — the channel must not be able to
revoke itself, that is the trust boundary. A revoked Kharej stays unpaired until its owner picks "Allow a new
Iran to pair" there, which is also the way back after losing the Iran server. Kharej never forwards to its
own SSH, metrics or latch ports, whatever the pairing asks.

What Iran can do over the channel — all of it from the Go manager's `wattun scepter` cockpit (`wattun -scepter-call CMD` is the scriptable one-shot form):

| Area | Commands |
|---|---|
| Read | live state, the tunnel list, per-tunnel stats, logs, events, history |
| Write | create, edit and delete tunnels, start/stop/restart, per-port limits, presets — each is validate → backup → apply → verify, rolled back on failure. A tunnel created from Iran is set up on both servers at once, with no token to copy |
| Remote carrier work | open a probe listener on Kharej and speed-test it from Iran (`test.open`/`test.close`), switch a remote tunnel's carrier with an automatic rollback (`carrier.change`), run and apply the carrier ranking (`auto.test`/`auto.rows`/`auto.apply`) |
| Operations | update Kharej's binary with a rollback watchdog (`update.run`), structured doctor output, a full config backup as a verified tarball, the audit trail |

Details and the full command table:
[TECHNICAL.md](docs/TECHNICAL.md#scepter-the-pairing-and-management-plane-350).

## Web panel (Iran server)

3.6.0 adds an optional browser dashboard on the Iran server: live download and upload per tunnel, a health
gauge, a 24-hour outage watchdog, per-tunnel history and logs, and the paired Kharej servers seen through the
scepter channel. It also manages them: start, stop and restart, ports and limits, speed tests, new tunnels
(on Kharej and here in one go), delete, updates and rollback, backups and restore, 30 days of traffic, alerts,
and its own certificate (your own, a private CA for your phone, or ACME for a domain or the server's IP). It also
shows per-port use and quotas (with reset), rotates or forgets a Kharej pairing, deletes a tunnel on both servers,
moves itself to another port, encrypts backup downloads with a passphrase, previews a restore before it writes
anything, warns about quotas, new releases and speed drops, and can show dates in the Persian calendar. Actions that
show a key or cannot be undone need 2FA plus your password and a fresh code.

The installer asks `Turn on the web panel ...? [Y/n]` when you pick Iran (Enter = yes). Later, or on an
existing server:

```bash
wattun panel on        # prints the address, user and password (shown once) and a QR code
wattun panel 2fa       # optional: authenticator app 2FA from the console (or in the panel's Settings)
wattun panel off       # stop it; --forget also deletes its address and password
```

It listens on a random port behind a random secret path, with its own certificate (Iran servers often cannot
get one from a CA, so the browser warns once: compare the fingerprint the console printed). Anything outside the
secret path looks like a default nginx 404, and 5 wrong passwords ban the address for 15 minutes.
Authenticator-app 2FA with 10 one-time recovery codes is in the panel's Settings.
Details: [TECHNICAL.md](docs/TECHNICAL.md#web-panel-360).

## What it does

WatTunnel connects an **Iran** server (where your users connect) to a **Kharej** server (where your service runs) and
forwards any TCP or UDP port between them. One static binary, no dependencies.

- **Rides what your route lets through:** `icmp`, `udp`, `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc`, `gre`, `ipip`,
  Cloudflare with ECH, reverse mode, or several of them bonded into one tunnel.
- **Hands-on bond control:** give a bond leg one direction only (`carrier: tcp:up+udp:down` — uplink over one
  carrier, downlink over another; each carrier once per bond; both ends need the same release), let `-mtu-adapt`
  shrink the payload while an ISP drops large packets but small ones pass (off by default, set per end, invisible
  to the other side), and `wattun mute NAME PATH` / `wattun unmute NAME PATH` to take one leg out of a bond or put
  it back without a restart.
- **Gets past filters:** fake-SNI desync, `udp-dns`, `udp-hop` (a new UDP source port every few packets, for routes that cut each flow after ~30 packets), `tcp-mimic`, connection rotation with `pool-rotate`, and `wattun matrix NAME` to
  try the combinations and apply the best. `wattun blackout NAME` turns the whole kit on.
- **Hard to classify:** no constant byte in a packet header, idle packets at random sizes, HTTP carriers that answer like
  nginx (or pass probes on to a real site with `decoy`), and 13 shaped carriers such as `vxlan` and `ntp-direct`. Opt-in `shape-data` and `noise` cost bandwidth.
- **Tunes itself:** defaults follow the CPU and RAM, and the auto test tunes sessions and conns on your route.
- **Loss does not slow it down:** pacing follows delay, and `fec: auto` sends parity only while packets are really being lost.
- **Runs itself:** live port changes, per-port stats and quotas (optionally reset every day, week or month), auto-heal, update with rollback.

## Speed

Real servers, unfiltered path. Full tables and how each was measured:
[docs/TECHNICAL.md](docs/TECHNICAL.md#field-numbers).

| Connection type | Download | Upload | Ping under load |
|---|---|---|---|
| **`tcp`, default settings** (3.2.0, 2 vCPU pair, 80 ms, 16 streams) | **224-282 MB/s (272 MB/s = 2.17 Gbit sustained)** | 146 MB/s | - |
| **`tls`** (same pair) | 187-209 MB/s | 140 MB/s | - |
| **TCP / TLS / reverse** (2.5.1, production tunnel with users on it) | 195 MB/s | 276 MB/s | 40-51 ms |
| **ICMP** (only ping passes on the route) | up to ~33 MB/s, the route's maximum | 26 MB/s | 40-45 ms |
| **Cloudflare CDN** (`wss` + ECH, 4 sessions) | 44-48 MB/s | up to 82 MB/s | 109-116 ms (CDN base 86) |

### On filtered routes

On a route that **cuts every direct Iran → Kharej flow within a second** (UDP after 3 datagrams, TCP after 3 KB, on every
port, with every payload), plain tunnels connect for a moment and die. Through that filter (3.0.0, one vCPU per server,
82 ms, one run each, so read these as orders of magnitude):

| Setup | Download | Upload |
|---|---|---|
| Direct `udp-dns`: every datagram looks like DNS on port 53 | **36 MB/s** | **29 MB/s** |
| Direct `tcp` + fake-SNI `rst`, pool-rotate | 28 MB/s | 32 MB/s |
| Reverse `tcp` (Kharej dials Iran), pool-rotate | 28 MB/s | 32 MB/s |
| Reverse `wss` / `tls` / `h2` | 22-25 MB/s | 27-30 MB/s |
| Reverse `udp` (Iran never sends first) | 21 MB/s | 19 MB/s |

On another route, where Cloudflare passes only flows named `www.cloudflare.com`, `wss` with `fake-mode: rst` connected in
2 s at 9-15 MB/s down and 2-5 MB/s up
([field test](docs/TECHNICAL.md#fake-sni-field-test-21012)).

## Compared to other tunnels

Same servers, same filtered route (only ICMP passes), real VLESS traffic through each tunnel:

| Tool | Throughput | Latency p50 | Iran CPU per MB | RAM |
|---|---|---|---|---|
| **WatTunnel** | **up to ~33 MB/s** | **40-45 ms** | **0.026 CPU-s** | **~40 MB** |
| GOST v3 ICMP | 1.6-5.4 MB/s | ~51 ms | 0.15-0.20 CPU-s | 50-70 MB |
| BackPack (tuned) | ~6.1 MB/s | 102 ms | - | - |
| Hans | 1.1-3.8 MB/s | - | - | - |
| WireGuard over pingtunnel | 0.25-2.7 MB/s | - | - | - |
| pingtunnel | ~0.5 MB/s under load | - | CPU saturates | - |
| ptunnel-ng | ~20 KB/s | - | - | - |

| | WatTunnel | GOST | pingtunnel | Hans | ptunnel-ng |
|---|:-:|:-:|:-:|:-:|:-:|
| ICMP carrier | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDP / TCP / TLS / WS / gRPC carriers | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cloudflare/CDN with ECH | ✅ | - | ❌ | ❌ | ❌ |
| Fake-SNI desync, DNS-shaped UDP, masked headers | ✅ | ❌ | ❌ | ❌ | ❌ |
| One token tests every connection type for you | ✅ | ❌ | ❌ | ❌ | ❌ |
| Loss does not slow it down (delay-based pacing) | ✅ | ❌ | ❌ | ❌ | ❌ |
| All ports in one process | ✅ | ✅ | ❌ | ✅ (tun) | ❌ |
| Add or remove ports without a restart | ✅ | ❌ | ❌ | - | ❌ |
| Reverse mode / reverse ICMP | ✅ / ✅ | ✅ / ❌ | ❌ | ❌ | ❌ |
| Per-port traffic stats and quotas | ✅ | ❌ | ❌ | ❌ | ❌ |
| Guided menu, auto-heal, update and rollback | ✅ | ❌ | ❌ | ❌ | ❌ |

On a clean, unfiltered link every tunnel reaches line rate and GOST uses a little less CPU; WatTunnel still halves
small-request latency there (43 ms vs 83 ms) because interactive traffic goes first.

## Resource use

An idle tunnel sends about 2 small packets a second: ~11.5 MB a day on `udp` or `icmp`, 0.1-0.2 % of one CPU core and
10-17 MB of RAM. A busy ICMP tunnel with 250-300 users runs in about 40 MB. Under load the overhead is +0.25 % on `tcp`
and about +5 % on `udp` or `icmp` with `mtu: 1400`.
[Details](docs/TECHNICAL.md#resource-usage-idle-ram-cpu-and-bandwidth).

## Security

- **Encryption:** ChaCha20-Poly1305 with an X25519 exchange on every session, so recorded traffic stays unreadable if a key
  file leaks later.
- **Only the Iran ↔ Kharej leg is protected.** Between your users and Iran, run an end-to-end encrypted protocol such as
  VLESS+Reality, TLS or WireGuard inside the tunnel.
- **The token contains the key.** Treat it like a password and share it only over a private channel.
- **Kharej dials only its own `127.0.0.1`,** and only allowed ports. On a direct carrier, `allow-clients` also limits the key
  to the client IPs you name. Keep `metrics` on `127.0.0.1`.
- **Signed installs:** the installer checks the binary and manager against an RSA-signed `SHA256SUMS` and refuses a bad
  signature. The script itself, fetched through a mirror, is only trust-on-first-use.
- **Still visible to the network:** the server's address, and the volume and timing of packets.

What each anti-censor option hides, and what none of them hides:
[spoofing and shaping](docs/TECHNICAL.md#spoofing-and-shaping-explained). Full
[security model](docs/TECHNICAL.md#security-model).

## More

Everything else is in [docs/TECHNICAL.md](docs/TECHNICAL.md):
[reverse mode](docs/TECHNICAL.md#reverse-mode) ·
[auto mode](docs/TECHNICAL.md#auto-mode) ·
[Cloudflare / CDN](docs/TECHNICAL.md#cdn-tuning) ·
[bonding](docs/TECHNICAL.md#bonding) ·
[managing tunnels](docs/TECHNICAL.md#managing-tunnels) ·
[config file](docs/TECHNICAL.md#config-file) ·
[monitoring](docs/TECHNICAL.md#metrics) ·
[troubleshooting](docs/TECHNICAL.md#troubleshooting) ·
[release history](docs/TECHNICAL.md#release-history) ·
[Windows and building from source](docs/TECHNICAL.md#build-and-test)

- Telegram channel (news and releases): [@WatxDev](https://t.me/WatxDev), developer: [@watxox](https://t.me/watxox)
- Bugs and ideas: [issues](https://github.com/JohnWatsoon/WatTunnel/issues). A change that makes the ICMP path
  slower won't be merged.
- License: [MIT](LICENSE). Uses `golang.org/x/crypto`, `x/net` and `x/sys` (BSD-3-Clause). GOST, Backhaul and
  BackPack were studied for ideas and as benchmarks; no code was copied.
