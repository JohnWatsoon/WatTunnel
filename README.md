<div align="center">

<img src="docs/img/banner.jpg" alt="WatTunnel: stay connected, even when only ping gets through" width="100%">

# 🪁 WatTunnel

**Encrypted Iran ↔ Kharej port forwarding that keeps working when the network is filtered, even when only ping gets through.**

[![Release](https://img.shields.io/badge/release-v3.1.2-blue?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64%20%7C%20windows-lightgrey?style=flat-square)
[![Telegram Channel](https://img.shields.io/badge/Channel-@WatxDev-26A5E4?style=flat-square&logo=telegram)](https://t.me/WatxDev)
[![Telegram](https://img.shields.io/badge/Contact-@watxox-26A5E4?style=flat-square&logo=telegram)](https://t.me/watxox)

**English** · [فارسی](README.fa.md)

</div>

---

WatTunnel connects an **Iran** server (where your users connect) to a **Kharej** server (where your service runs)
and forwards any TCP or UDP port between them. One static binary, no dependencies, and a menu that sets everything
up from one pasted token.

**3.0.0 is the anti-censorship release.** When the route is filtered, the tunnel does not slow down: it changes shape.
It rides whatever your route lets through (`icmp`, `udp`, `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc`, Cloudflare
with ECH, reverse mode, or several of them bonded into one tunnel), and since 2.6.0 it has learned to get past
permit-lists, flow cutters and traffic classifiers that kill every ordinary tunnel.

## 🔥 Built for the worst days

On a route that **cuts every direct Iran → Kharej flow within a second** (UDP after 3 datagrams, TCP after 3 KB, on every
port, with every payload), a plain tunnel connects for a moment and dies. WatTunnel 3.0.0 was field-tested on exactly
such a pair, and these are the results through that filter:

| Setup on the filtered route | Download | Upload |
|---|---|---|
| **Direct `udp-dns`: every datagram looks like DNS on port 53** (400 MB run) | **36 MB/s** | **29 MB/s** |
| Direct `udp-dns`, 4 sessions | **32 MB/s** | 24 MB/s |
| **Direct `tcp` + fake-SNI `rst`**, pool-rotate | **28 MB/s** | **32 MB/s** |
| Direct `tcp` + fake-SNI `rst`, 4 sessions | 21 MB/s | 29 MB/s |
| **Reverse `tcp`** (Kharej dials Iran), pool-rotate | **28 MB/s** | **32 MB/s** |
| Reverse `wss` / `tls` / `h2` | 22-25 MB/s | 27-30 MB/s |
| Reverse `udp` (Iran never sends first) | 21 MB/s | 19 MB/s |

One vCPU per server, 82 ms round trip, one run each, so read these as orders of magnitude (the pair also passes ICMP, at 7-10 MB/s). Every one of them is a tunnel
that **plain tools cannot bring up at all** on this route. Old and new releases work together. Conditions, failures
and the full list of 92 configurations: [docs/TECHNICAL.md](docs/TECHNICAL.md#field-numbers).

## What changed since 3.0.0

- **Counters stay with their server; the matrix handles bonds (3.1.1).** A config copied to a new VPS starts its
  lifetime traffic counters from zero instead of showing the old server's total (`wattun-manager reset-traffic NAME`
  zeroes them on purpose, and deleting a tunnel removes its saved counters). The anti-censor matrix now tests bonded
  tunnels leg by leg (before it refused them), only offers modes the installed binary really supports (an older binary
  silently ran `synrst` as `seq`), includes `paws`, and re-measures the top 3 variants at 20 MB so the winner is not
  noise. The manager now ships inside the signed release checksums, so `install.sh` verifies it like the binary.
- **Smaller fixes (3.1.1).** The Kharej speed-test button says the test runs on Iran instead of claiming an old
  version. `-ping-every` is validated (0-60 s) and the liveness/idle limits scale with it. A captured packet can no
  longer keep a closed server session alive or open a new one. `-sessions` clones keep their `tcp-mimic` hello, and a
  UDP flow keeps its session while it lives, so a flapping session cannot reorder its datagrams.
- **Defaults follow the machine (3.1.0).** The program reads the CPU count and the RAM it may use (container limits
  included) and picks connections, sessions and window sizes by itself: a small VPS stays light, a 2-vCPU / 2 GB+
  server opens more connections and a second session. The start line shows what it chose; `conns`, `sessions` and the
  new `win-max` override it. On a 2-vCPU pair with 81 ms between them this takes `tcp` to **1.06 Gbit/s down / 0.98 up**.
- **Two bugs that hurt real tunnels (3.1.0).** After the first speed test the server's receive loop could hang for good
  (the tunnel looked up and moved nothing); bonded tunnels sent all bulk traffic over one carrier.
- **A dead pool recovers in seconds (3.0.1).** If every connection of a `tcp`/`tls`/`ws`/`wss`/`h2`/`grpc` pool stalls
  together, it redials after about 5 s instead of waiting about 15 minutes; on the test pair upload was back 8-9 s after
  a total blackhole.
- **Reverse tunnels no longer keep one connection for hours (3.0.2).** `pool-rotate` now works on the side that dials,
  so Kharej recycles its connections (the manager sets `30m` on new reverse tunnels). A 20 s rotation kept every
  connection under 20 s old at 80 MB/s down and 68 MB/s up; the run without it lost all traffic on its 150 s old
  connections. Add `pool-rotate: 30m` to existing reverse tunnels by hand.
- **Auto test with two presets (3.0.2).** The manager asks first: *normal* (2-3 minutes) or *anti-censor* (every desync
  mode, SNI, TLS fragment, fingerprint and ECH variant on every carrier, about 195 variants). `s` skips a variant, `g` a
  carrier, `q` stops and lets you choose from what was measured.
- **Looks more like a web server (3.0.2).** HTTP carriers answer with the stock nginx pages, a random throwaway
  certificate, a Chrome-like WebSocket request, and a random URL path for new tunnels; new `fake-mode: paws`
  (experimental) and `tls-frag: -1` (split inside the SNI).

## What changed since 2.5.0

Everything below is shipped, tested and reachable from the menu (`wattun` → tunnel page → `z` for the anti-censor
presets).

**Looks like nothing a classifier knows (3.0.0)**

- **No constant byte in any packet.** The session id and packet number are masked (`hdr-mask`), so there is no fixed
  prefix and no counter to fingerprint. Idle packets are padded to random sizes and the keepalive interval is
  jittered (`shape`).
- **Reverse `udp`.** The Iran server only listens and never starts a flow towards a foreign address. Kharej sends
  authenticated punches. Previously only the TCP-family carriers had a reverse mode.
- **`udp-dns`.** Every UDP datagram starts like a DNS query (and every answer like a DNS answer) on port 53, with a
  fresh id and name each time. It is the one shape the measured filter let through at full speed.
- **TLS-shaped raw `tcp` (`tcp-mimic`).** The first bytes of a `tcp` tunnel are a Chrome-like 517-byte ClientHello
  carrying the authentication, with masked frame lengths, not a plain pool id.
- **Pick the source address** of the tunnel from the manager (`src-ip`), for servers with several IPs.
- **Lower ping under a download.** Pool queues are capped in bytes and interactive packets get a connection of their
  own, so a ping or a game packet no longer waits behind a bulk transfer.

**Gets past permit-lists and flow cutters (2.6.0 - 2.10.12)**

- **Fake-SNI desync (`fake-sni`).** When a filter lets a flow live only if its TLS name is on a list, the tunnel sends
  a decoy hello that the filter reads and the server ignores. Modes: `seq`, `ttl` (calibrated automatically), `sum`,
  `seqsum`, `rst`, `synrst`, `split`, `hlen0`, `fakeip`, `all`, and `auto`, which tests which mode keeps a real flow alive on your route and picks it (3.0.0).
  Works on `tcp`, `tls`, `ws`, `wss`, `h2`, `grpc`, over IPv4 and IPv6, also from a reverse server. Field result: a
  `wss` tunnel through Cloudflare connected under a Cloudflare-only whitelist with `rst`, while every other mode did not.
- **Churn (`pool-rotate`).** Connections are recycled at random times or byte budgets, so none shows a stable lifetime.
- **ECH, even when DNS is hijacked** (`ech: ladder`): the ECH config is fetched through the tunnel itself.
- **`tls-small-ch`** keeps the ClientHello at about 250 bytes for DPIs that drop large hellos.
- **ICMP volume governor** learns a path's reroute ceiling, so the tunnel stays under it.
- **`wattun blackout NAME`** turns the whole kit on with one command, **`wattun matrix NAME`** tries every
  combination from the Iran server and applies the best one.

**Safer and tougher**

- **Forward secrecy** on every session (X25519 key exchange, 2.10.0): recorded traffic stays unreadable even if a key
  file leaks later.
- **Signed installer**: every download is checked against an RSA-signed checksum list, so a mirror cannot swap the binary.
- **Reliability**: no stall after a short one-way blackout, no hang after a Kharej restart, honest `alive` in `/stats`,
  a header mask that no longer stays off when the client starts before its server, fixed data races and buffer reuse.
- **Manager**: anti-censor toggle with presets (Cloudflare first, `rst-fast`), reverse switch, resilience profiles, DNS-shaped
  option in the Kharej wizard, auto-heal, update with rollback.

[Full release history](docs/TECHNICAL.md#release-history).

## Speed

Measured on real Iran ⇄ Europe servers (2 vCPU each), October 2026, on an unfiltered path. Ping is the round trip
through the tunnel while it is fully loaded; the route's own ping is about 40 ms.

| Connection type | Download | Upload | Ping under load |
|---|---|---|---|
| **TCP / TLS / reverse** (2.5.1, production tunnel with users on it) | **195 MB/s (~1.6 Gbit)** | **276 MB/s (~2.2 Gbit)** | 40-51 ms |
| **ICMP** (only ping passes on the route) | **up to ~33 MB/s**, the route's maximum | 26 MB/s | 40-45 ms |
| **Cloudflare CDN** (`wss` + ECH, 4 sessions) | 44-48 MB/s | up to 82 MB/s | 109-116 ms (CDN base 86) |
| **TCP / TLS / WS** (3.1.0, 2 vCPU pair, 81 ms, 16 streams, raw TCP 1.5 Gbit/s) | **132-143 MB/s (1.06-1.14 Gbit)** | 101-123 MB/s | 94-127 ms down, ~400 up at full load |
| **Same pair, `tcp` / `tls` + fake-SNI** (`rst`, `synrst`, `paws`) | 110-139 MB/s (0.89-1.11 Gbit) | 96-124 MB/s | same as above |

Plain TCP with no tunnel at all reaches 243 MB/s down on the same route with 16 connections. WatTunnel, encrypted,
reaches **80 % of that**. Full tables, every version and how each was measured:
[docs/TECHNICAL.md](docs/TECHNICAL.md#field-numbers).

### On the owner's filtered Iran route (2.10.12 field test)

Same servers, 2026-10-25, on a route where Iran → Kharej directly is cut about a second into every flow, and Iran →
Cloudflare passes only flows whose TLS name is `www.cloudflare.com`.

| Setup | Result |
|---|---|
| Reverse `tcp` (Kharej dials Iran), with or without `fake-sni` | 36-40 MB/s down, 30-36 MB/s up, 38-46 ms idle |
| `wss` through a Cloudflare edge, real name filtered, `fake-mode: rst` | connected in 2 s: 9-15 MB/s down, 2-5 MB/s up, ~125 ms; 100 MB test 13.8 MB/s down, 4.9 MB/s up |

Details and the failures: [docs/TECHNICAL.md](docs/TECHNICAL.md#fake-sni-field-test-21012).

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

That is **about 5x the next best ICMP tunnel, 6-20x GOST at 6-7x less CPU**, and one process carries 250-300 real
users.

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
[Benchmark details](docs/TECHNICAL.md#field-numbers).

## Light when idle

An idle tunnel sends about 2 small packets a second, about 133 bytes/s with headers on `udp` or `icmp`. That is
~11.5 MB a day, or ~345 MB a month. It uses 0.1-0.2 % of one CPU core and 10-17 MB of RAM with no users. A busy ICMP
tunnel with 250-300 users runs in about 40 MB.

Under load, the tunnel adds +0.25 % to the bytes your users move on `tcp` (16 KB packets), and about +5 % on `udp` or
`icmp` with `mtu: 1400`, headers included.

[Idle and bandwidth details](docs/TECHNICAL.md#resource-usage-idle-ram-cpu-and-bandwidth)

## Setup

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

The proxy is a third-party mirror: it sees and could alter the bytes. `install.sh` therefore checks every download
against an RSA-signed checksum list, with the public key baked into the script, and refuses a mismatch (`openssl`
must be installed; it is everywhere).

Or download `wattun-linux-amd64`, `install.sh` and `wattun-manager` from the
[releases](https://github.com/JohnWatsoon/WatTunnel/releases) page, put the binary in `dist/` next to `install.sh`,
and run `bash install.sh`.
</details>

**2. Kharej.** Run `wattun`, press `n` (new tunnel), choose **Kharej**, and pick **Auto** as the connection type. You
get a token:

```
wat1:aWNtcHwyMDMuMC4xMTMuMTB8a1E3...
```

**3. Iran.** Run `wattun`, press `n`, choose **Iran**, and paste the token. The menu tests every connection type
(about 2-3 minutes) and offers the fastest that works: press **Enter** to take it. Then enter your ports, for example
`443, 8443:443, 53/udp` (`8443:443` means users connect to Iran port 8443 and reach Kharej port 443).

```
  ✔ Writing key and config
  ✔ Starting wattun@iran
  ✔ CONNECTED (RTT 41.3 ms)

  users ──► Iran :8443 ══ tcp ══► Kharej ──► 127.0.0.1:443
```

Done. Users connect to the Iran server's IP, and Kharej forwards only to its own `127.0.0.1`.

**Day to day.** `wattun` opens the dashboard: press a tunnel's number for its page (speed test, diagnose, logs,
ports, change connection type with **m**), `u` updates, `s` holds rollback and auto-heal. Auto-heal is on for Iran
tunnels and restarts one whose link has been down for 3 minutes.

```bash
wattun status          # one line per tunnel
wattun test NAME       # connection doctor + speed test
wattun ports NAME      # edit port mappings (applied live)
wattun update          # update the binary and the menu
```

**Auto uses data.** The test on Iran moves up to about 400 MB in total (about 50-150 MB on a filtered route where few types connect). On a traffic-billed server, pick a type yourself. After Iran has picked, run `wattun-manager auto-narrow NAME` on Kharej (or `u` on the tunnel page) to close the carrier ports it does not use.

If you already know what your route allows, you can pick a type yourself in step 2:

| Your route | Use |
|---|---|
| Only ping passes | `icmp` |
| UDP passes | `udp` (lowest latency) |
| TCP passes | `tcp`, or `tls` to look like HTTPS |
| Only a CDN gets out, or SNI is filtered | `wss` through Cloudflare ([CDN setup](docs/TECHNICAL.md#cdn-tuning)) |
| Only Kharej can reach Iran | any of the above with [reverse mode](docs/TECHNICAL.md#reverse-mode) |

## Security

Traffic is encrypted with ChaCha20-Poly1305 under a key derived from the pre-shared key and a random per-session
id; from 2.10.0 the two ends also run an ephemeral X25519 exchange on every session, so traffic recorded before a
later key-file leak stays unreadable. That protects the **Iran ↔ Kharej leg only**: between your users and the Iran
server the traffic is whatever the forwarded service itself provides, so run an end-to-end encrypted protocol
(VLESS+Reality, TLS, WireGuard) inside the tunnel. Kharej dials only its own `127.0.0.1`, and only ports on the
allowlist.
From 3.0.0 no byte of a packet header is constant (the session id and packet number are masked), idle packets are
padded to random sizes with a jittered keepalive, and `udp` has a [reverse mode](docs/TECHNICAL.md#reverse-udp-300): the Iran
server only listens and never starts a flow towards a foreign address. Raw `tcp` opens with a TLS ClientHello-shaped
hello and masked frame lengths instead of a plain pool id (`tcp-mimic`). On a route that cuts every UDP flow after a few
packets but passes DNS, `udp-dns: true` starts each `udp` datagram like a DNS message on port 53
([DNS shape](docs/TECHNICAL.md#dns-shaped-udp-udp-dns-300), [traffic shape](docs/TECHNICAL.md#traffic-shape-what-a-dpi-sees-300)).
The installer verifies the download's signature against a public key baked into it, so a `WAT_PROXY` mirror (or
any tampered copy) cannot slip in a changed binary. The connection token contains the key: treat it like a
password and share it only over a private channel. Keep `metrics` on `127.0.0.1`. What stays visible to the
network: the server's address, and the volume and timing of packets. Details:
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
[security](docs/TECHNICAL.md#security-model) ·
[Windows and building from source](docs/TECHNICAL.md#build-and-test)

- Telegram channel (news and releases): [@WatxDev](https://t.me/WatxDev), developer: [@watxox](https://t.me/watxox)
- Bugs and ideas: [issues](https://github.com/JohnWatsoon/WatTunnel/issues). A change that makes the ICMP path
  slower won't be merged.
- License: [MIT](LICENSE). Uses `golang.org/x/crypto`, `x/net` and `x/sys` (BSD-3-Clause). GOST, Backhaul and
  BackPack were studied for ideas and as benchmarks; no code was copied.
