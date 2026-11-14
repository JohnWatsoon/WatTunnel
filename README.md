<div align="center">

<img src="docs/img/banner.jpg" alt="WatTunnel: stay connected, even when only ping gets through" width="100%">

# 🪁 WatTunnel

**Encrypted Iran ↔ Kharej port forwarding that keeps working when the network is filtered, even when only ping gets through.**

[![Release](https://img.shields.io/badge/release-v3.3.7-blue?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
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
<summary>GitHub is blocked on the server?</summary>

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

The proxy is a third-party mirror. The binary and manager are still checked against the signed release, but the
`install.sh` you fetch through it is not, so prefer the release files or a `git clone` when you can.

Or download `wattun-linux-amd64`, `install.sh` and `wattun-manager` from the
[releases](https://github.com/JohnWatsoon/WatTunnel/releases) page, put the binary in `dist/` next to `install.sh`,
and run `bash install.sh`.
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

**Auto uses data.** The manager prints the worst case before it starts: up to 1184 MB for a normal test, about 416 MB
more if the token was made with `--extended`, and far less on a filtered route. On a traffic-billed server, pick a type
yourself:

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
wattun update          # update the binary and the menu
```

| Status | Meaning |
|---|---|
| `up` | The link works, also when an auto tunnel's link is on its other side |
| `partial` | The link works but a bond leg is down; the tunnel page shows how many |
| `standby` | The side of an auto tunnel that Iran is not using |
| `waiting` / `down` | No link (`waiting` on Kharej, `down` on Iran) |
| `unknown` | The tunnel's stats did not answer, so the state is not known |
| `stopped` | The service is not running |

**After Iran picks a type,** an auto Kharej tunnel closes everything unused about 5 minutes later and restarts the side
that stays open, so its connections drop once. The Kharej main menu shows `carriers open` or `closed` under each auto
tunnel, with the count and the time left. Press `c` there to switch it: what you open stays open until you close it.
On the next check after that close, the type Iran uses becomes the tunnel under the same name, and the test listeners
are deleted. Deleting the auto tunnel before that never deletes the side Iran is connected through.

To change the type or re-test later, open the carriers on Kharej first. If you skip that, the manager reopens by itself
after 3 failed checks (at most once per 10 minutes).

## What it does

WatTunnel connects an **Iran** server (where your users connect) to a **Kharej** server (where your service runs) and
forwards any TCP or UDP port between them. One static binary, no dependencies.

- **Rides what your route lets through:** `icmp`, `udp`, `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc`, `gre`, `ipip`,
  Cloudflare with ECH, reverse mode, or several of them bonded into one tunnel.
- **Gets past filters:** fake-SNI desync, `udp-dns`, `tcp-mimic`, connection rotation with `pool-rotate`, and `wattun matrix NAME` to
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
