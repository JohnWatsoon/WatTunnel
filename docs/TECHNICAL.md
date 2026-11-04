# WatTunnel

WatTunnel (`wattun`) is a tunnel. It forwards TCP and UDP ports from one server (Iran) to another (Kharej)
over a link that is filtered. It is one static Go binary, one process, and it needs no other tool.

It speaks over **ICMP echo** (the only thing the Iran filter lets through today) or over ordinary
**UDP, TCP, TLS, WebSocket, HTTP/2 and gRPC** when those work or when you hide behind a CDN.

Version: see `wat/version.go` (`wattun -version`). 

## Contents

1. [Why it exists](#why-it-exists)
   - [Field numbers](#field-numbers)
   - [Resource usage: idle, RAM, CPU and bandwidth](#resource-usage-idle-ram-cpu-and-bandwidth)
2. [Install](#install)
3. [Quick start](#quick-start)
   - [Managing tunnels](#managing-tunnels)
4. [Carriers](#carriers)
   - [Shaped carriers (3.3.0)](#shaped-carriers-330)
5. [Bonding](#bonding)
6. [Traffic shape](#traffic-shape-what-a-dpi-sees-300)
   - [Stream padding and idle noise](#stream-padding-and-idle-noise-330)
7. [Spoofing and shaping, explained](#spoofing-and-shaping-explained)
8. [Reverse mode](#reverse-mode)
   - [Auto mode](#auto-mode)
   - [CDN tuning](#cdn-tuning)
9. [UDP forwarding](#udp-forwarding)
10. [Config file](#config-file)
11. [Command-line flags](#command-line-flags)
12. [Metrics](#metrics)
13. [Handover, drain and rollback](#handover-drain-and-rollback)
14. [Troubleshooting](#troubleshooting)
15. [Security model](#security-model)
16. [Build and test](#build-and-test)
17. [Release history](#release-history)
18. [License and attribution](#license-and-attribution)

## Why it exists

Since October 2026 the Iran to Kharej path cuts TCP, UDP, GRE, IPIP, SCTP and ESP after a few packets. Only ICMP echo
passes: at first only payloads up to about 640 bytes (full 1500-byte packets again since at least 2026-10-12, see
[ICMP path limits](#icmp-path-limits-and-pacing)), about 0.2 to 2 % random loss, about 40 ms. Every ready-made engine we tried
was built for another problem (a TCP stream over a clean link) and failed in a measured way on this path. WatTunnel is
built for it: small datagrams, delay-based pacing (loss is not treated as congestion), selective acks, fast loss
repair, and interactive traffic sent before bulk.

### Production numbers (real path, ICMP, 2026-10-09)

| | WatTunnel | GOST ICMP |
|---|---|---|
| Real xray vless download | about 6 MB/s | 1.6 to 5.4 MB/s |
| Real xray vless upload | about 3.7 MB/s | not measured |
| Parallel TLS requests through it | 120 of 120 ok | - |
| CPU per MB moved (Iran) | 0.05 to 0.06 CPU-s | 0.15 to 0.20 CPU-s |
| Small-request latency, idle | p50 40 to 45 ms | about 51 ms |
| RAM | about 40 MB | 50 to 70 MB |

It carries about 250 to 300 real clients. Port changes and restarts are done as live two-slot handovers: the new
instance proves itself, takes new connections, and the old one drains. Nobody is cut.

### Loopback A/B against GOST (emulated link, 2026-10-09)

Link: 20 ms each way, 0.2 % loss, 100 Mbit. Median of 2 to 3 rounds. Harness:
[`bench/pair.sh`](bench/pair.sh).

| Contender | 1 flow MB/s | 16 x 2 MB MB/s | p50 ms | p95 ms | CPU-s/MB |
|---|---|---|---|---|---|
| direct (no tunnel) | 10.92 | 10.69 | 82 | 94 | 0 |
| wattun udp | 10.57 | 10.62 | 43 | 81 | 0.04 |
| wattun tcp | 10.55 | 10.55 | 43 | 126 | 0.03 |
| wattun tls | 10.59 | 10.25 | 43 | 108 | 0.03 |
| wattun ws | 10.59 | 10.61 | 43 | 117 | 0.03 |
| gost tcp | 10.84 | 10.41 | 83 | 95 | 0.01 |
| gost ws | 10.76 | 10.40 | 124 | 143 | 0.01 |

Read this honestly: on a clean link GOST uses less CPU and WatTunnel's pool carriers match its throughput. The
small-request latency is lower with WatTunnel because it sends interactive streams first. The ICMP numbers above are
where WatTunnel wins, because GOST cannot repair loss as fast. The h2, h2c, wss and grpc carriers are covered by unit
tests but are not in this benchmark. TCP and UDP to Kharej are blocked on the production path, so those carriers are
proven on loopback and simulated links only.

## Field numbers

Everything here was measured on real Iran ⇄ Europe servers (2 vCPU each), except where marked emulated. Run
`wattun test NAME` to measure your own route.

### TCP tunnels (tcp, tls, reverse)

Reverse `tcp` (Kharej dials Iran), October 2026, 200 MB speed tests unless noted.

Ping through the tunnel:

- 2.4.18 and 2.5.0 runs: the route's own 38-43 ms.
- 2.5.1 runs: 40-51 ms.

| Setup | Download | Upload |
|---|---|---|
| Plain TCP, no tunnel, 8 connections | 167 MB/s | |
| Plain TCP, no tunnel, 16 connections (the route's ceiling) | 243 MB/s | 448 MB/s |
| Plain TCP, no tunnel, 32 connections | 314 MB/s | |
| 2.4.17, 8 connections (test tunnel) | ~20-30 MB/s | 12 MB/s |
| 2.4.18, 8 connections | 49-53 MB/s | 47-56 MB/s |
| 2.4.18, 16 connections, 32 streams | 69-74 MB/s | |
| 4 separate 2.4.18 tunnels at once | 136-143 MB/s | 173 MB/s |
| 2.5.0, 16 connections, production tunnel with ~400 users, 16 streams | 53.3 MB/s | 149.7 MB/s |
| 2.5.0, same, 8 streams | 37.9 MB/s | 101.7 MB/s |
| 2.5.0, 16 connections, test tunnel next to production, 16 streams | 53-71 MB/s | |
| 2.5.1, same test tunnel, 16 streams | 65-116 MB/s | |
| 2.5.1, production tunnel, 8 streams | 122.3 MB/s | 140.7 MB/s |
| **2.5.1, production tunnel, 16 streams** | **157.0 MB/s** | **276.1 MB/s** |
| **2.5.1, production tunnel, 16 streams, 2 GB** | **194.6 MB/s** | |

- **2.5.0:** the download was limited by the Iran server's CPU, not the route. The receiving tunnel used 103-117 % of one of its two cores.
- **2.5.1:** removed a large part of that CPU cost (see [Cheaper stream buffers](#cheaper-stream-buffers-251)). Its download reaches 80 % of what plain, unencrypted TCP gets on the same route with 16 connections.

### Fast pair: every carrier and anti-censor variant (3.1.0, 2026-10-27)

Iran 2 vCPU / 1.9 GB, Kharej 2 vCPU / 3.8 GB, 81 ms apart, host buffers raised to 16 MB with BBR, 16 streams, 1024 MB each way,
auto-tuned defaults (Iran standard tier: 16 connections, 2 sessions; Kharej highperf). Raw TCP between the two without a tunnel:
1500 Mbit/s received with 16 and 1509 with 32 streams; delivered UDP about 1280. One run per cell, and this pair's run-to-run spread is
about 20 % (`tcp` download measured 1057, 1177 and 1320 in three runs), so read differences under 20 % as noise.

| Carrier | Down Mbit/s | Up Mbit/s | | Variant (client `fake-sni www.cloudflare.com`) | Down Mbit/s | Up Mbit/s |
|---|---|---|---|---|---|---|
| `tcp` | 1057 | 981 | | `tcp` + `rst` | 1043 | 930 |
| `tls` | 1140 | 805 | | `tcp` + `synrst` | 1088 | 948 |
| `ws` | 1132 | 808 | | `tcp` + `paws` | 1113 | 765 |
| `wss` | 1066 | 676 | | `tls` + `rst` | 885 | 875 |
| `h2c` | 1131 | 547 | | `tls` + `paws` | 1110 | 991 |
| `grpc` | 1027 | 670 | | `wss` + `rst` | 1144 | 658 |
| `udp` | 578 | 542 | | | | |

The desync runs only while a connection is set up, so the variants carry data at their carrier's speed. With the kernel's own buffers
(208 KB receive buffer, cubic, no BBR) the same runs gave `tcp` 1177 / 1127, `tls` 927 / 1018, `ws` 1058 / 657, `wss` 1129 / 601, `h2c` 487 / 730
and `grpc` 340 / 516 (down / up): `h2c` and `grpc` need the raised buffers. Full duplex (one 1 GB transfer each way at the same time): 706 up + 679 down
= 1384 Mbit/s, while raw TCP in both directions at once reached only 268.

Latency during a 512 MB transfer with 16 streams (route alone 81 ms, a `ping` beside it 81-84 ms): downloading 856-1029 Mbit/s the tunnel's
round trip was 94-127 ms and the server used up to 172 % of its 200 % CPU; uploading 669-730 Mbit/s it was 383-414 ms, the client's memory peaked
at 1024 MB and the server's at 641 MB. Below saturation `icmp` (114 Mbit/s) stayed at 81.5-85.4 ms. Capping the window made it slower, not
lighter: `win-max 8` and `4` gave `tcp` 844 / 603 and 757 / 762 Mbit/s here. 2 Gbit/s is not reachable on this pair.

### ICMP (real filtered route, October 2026)

Real VLESS (xray) traffic went through each tunnel, on the same servers and the same route. WatTunnel numbers are
from version 1.8.0.

| | WatTunnel 1.8.0 | GOST v3 ICMP |
|---|---|---|
| Peak throughput | **~33 MB/s**, the route's maximum | 1.6 - 5.4 MB/s |
| Single connection | **~25 MB/s** | 1.0 - 1.6 MB/s |
| Latency p50 (route's raw RTT is ~40 ms) | **40 - 45 ms**, close to zero added | ~51 ms |
| CPU per MB moved (Iran side) | **0.026 CPU-s** | 0.15 - 0.20 CPU-s (**6 - 7x more**) |
| RAM | **~40 MB** | 50 - 70 MB |
| 120 short TLS requests, 24 parallel | **120 / 120 ok** | - |

The route caps at about 50 - 55k ICMP packets per second (~33 MB/s), and WatTunnel fills it. In production, a single
process carries 250 - 300 real clients.

With 1400-byte packets (`mtu: 1400` on both ends, 2026-10-12, same route, 30 MB/s cap), a single speed test gave:

- **27.5 MB/s down, 26 MB/s up.**
- 0.3-0.8 % of packets resent (3-5 % at 640 bytes).
- Ping 41 ms under load.

Before you raise the MTU, check the route:

- `ping -M do -s 1372 PEER_IP` must get replies.
- `ip route get PEER_IP` must not show `mtu lock 680`.

Keep the total of all ICMP tunnels on the route at about 30 MB/s or less (see [ICMP path limits](#icmp-path-limits-and-pacing)).

Against other ICMP tunnels on the same route (WatTunnel 1.8.0):

| Tool | How it works | Throughput measured | Notes |
|---|---|---|---|
| **WatTunnel** | Own ICMP transport, one process, 4 lanes, AEAD, batched I/O | **up to ~33 MB/s** | Every port in one process, ~40 MB RAM |
| GOST v3 ICMP | QUIC over ICMP | 1.6 - 5.4 MB/s | 6 - 7x the CPU per MB |
| BackPack (tuned) | ICMP transport | ~6.1 MB/s | Latency p50 102 ms / p95 198 ms |
| Hans | IP-over-ICMP tun device | 1.1 - 3.8 MB/s | Needs a C++ build on both servers |
| WireGuard over pingtunnel | WireGuard inside one pingtunnel UDP session | 0.25 - 2.7 MB/s | Flat ceiling of a single pingtunnel process |
| pingtunnel | One process per port | ~0.5 MB/s under load | Each process reads every ICMP packet, so the CPU saturates |
| ptunnel-ng | One ICMP proxy per port | ~20 KB/s | Last resort only |

### CDN (Cloudflare)

Iran → Cloudflare → Kharej, `wss` + ECH. The rows come from three sets of runs:

- 2.3.0 and 2.4.0 rows: 2026-10-11, a tunnel with no users.
- 2.4.6 row: production with real users, 2026-10-12.
- 2.4.16 rows: a test tunnel, 2026-10-13.

| Setup | Result |
|---|---|
| 1 session (2.3.0) | ~19 MB/s down |
| 4 sessions (2.3.0) | ~52 MB/s down, ~51 MB/s up |
| 6 sessions (2.3.0) | ~60 MB/s down |
| 8 sessions (2.3.0) | peak 69 MB/s up |
| 6 sessions (2.4.0) | 76.6 MB/s up |
| 4 sessions (2.4.6), production, ~250 user connections | ~41 MB/s down sustained (28-50), 44-48 MB/s down and up to 82 MB/s up in speed tests, ~100 MB RAM per server |
| 4 sessions (2.4.16), speed test | 22.6 and 32.4 MB/s up, round trip steady at 109-116 ms (base 86 ms) |
| 1 connection (2.4.16), 28-32 ms Cloudflare edge | 24.4 MB/s down, 4.41 MB/s up |
| ICMP tunnel on the same path (only ICMP passes directly there) | ~1.1 MB/s down, ~2.1 MB/s up |
| Any CDN variant **without** ECH | did not connect at all |

Competitors' CDN speeds were not measured on this route, so there is only a feature comparison:

| | WatTunnel | Typical manual CDN setup (a ws/grpc proxy behind Cloudflare, configured by hand) |
|---|:-:|:-:|
| Cloudflare carriers (`ws`/`wss`/`grpc`) | ✅ | ✅ |
| ECH against SNI filtering, config fetched automatically | ✅ | ❌ by hand |
| Automatic scan for working Cloudflare IPs | ✅ | ❌ by hand |
| Automatic choice of TLS fingerprint / ECH / fragmentation by speed test | ✅ | ❌ by hand |
| Several sessions per tunnel, spread over several Cloudflare IPs | ✅ (default 4) | ❌ by hand |
| Ports added or removed without a restart | ✅ | depends on the tool |
| Auto-heal re-tests and replaces dead Cloudflare IPs | ✅ | ❌ |

### What usual tools do on a filtered route

| Problem on a filtered route | What usual tools do | What WatTunnel does |
|---|---|---|
| TCP and UDP are cut after a few packets | Tunnel dies or flaps | Rides ICMP, which isn't cut |
| 0.2–2 % random loss | TCP-style congestion control halves the speed on every loss | Delay-based pacing treats loss as noise, not congestion |
| Small MTU (~680 bytes) | Fragmentation and black-holed packets | 640-byte datagrams by default, up to 1400 where the route allows |
| SNI filtering of CDN domains | Blocked right after the handshake | Cloudflare with ECH; edges and TLS settings are found automatically |
| One process per port | Server CPU saturates | One process for all ports, batched syscalls |
| Changing ports | Restart drops every user | `ports:` list is hot-reloaded every 3 s |
| Link silently dies | You find out from your users | Live status, connection doctor, auto-heal |

### Feature comparison

| | WatTunnel | GOST | pingtunnel | Hans | ptunnel-ng |
|---|:-:|:-:|:-:|:-:|:-:|
| ICMP carrier | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDP / TCP / TLS / WS / gRPC carriers | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cloudflare/CDN with ECH | ✅ | - | ❌ | ❌ | ❌ |
| Auto mode: one token tests every variant | ✅ | ❌ | ❌ | ❌ | ❌ |
| Loss-tolerant (delay-based) pacing | ✅ | ❌ | ❌ | ❌ | ❌ |
| All ports in one process | ✅ | ✅ | ❌ | ✅ (tun) | ❌ |
| Add or remove ports without restart | ✅ | ❌ | ❌ | - | ❌ |
| UDP port forwarding | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Built-in encryption | ✅ AEAD | ✅ | ⚠️ | ⚠️ | ❌ |
| Adaptive FEC | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-port traffic stats and quotas | ✅ | ❌ | ❌ | ❌ | ❌ |
| Reverse mode (TCP-based carriers) | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reverse ICMP (Kharej pings, Iran keeps the ports) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Single static binary, no dependencies | ✅ | ✅ | ✅ | ❌ | ❌ |
| Guided manager, token pairing, auto-heal | ✅ | ❌ | ❌ | ❌ | ❌ |

On a clean emulated link (20 ms each way, 0.2 % loss, 100 Mbit):

- Every tunnel reaches line rate.
- GOST uses a little less CPU.
- WatTunnel halves small-request latency (p50 43 ms vs 83 ms), because it sends interactive streams first.

See [Loopback A/B against GOST](#loopback-ab-against-gost-emulated-link-2026-10-09).

### 3.0.0 field test: a pair that cuts every direct flow

2026-10-25, two fresh VPS (Ubuntu 24.04, 1 vCPU, 0.9 GB each), 82 ms round trip, driven over SSH. 92 tunnel
configurations were run. Each one: tunnel up, `/speedtest` down and up (15-40 MB), a 24 MB file through a forwarded
TCP port (sha256 checked), 30 UDP datagrams of 800 B echoed through a forwarded UDP port. One run per configuration
on small VMs; identical runs differed by about 2x, so compare orders of magnitude.

**What the pair does to plain traffic** (measured with raw sockets, no wattun): Iran to Kharej, every UDP flow is cut
after its first 3 datagrams and every TCP flow after about 3 KB, on all ports and with every payload tried (random,
TLS with any SNI, QUIC-shaped). The exceptions: UDP to port 53 when the payload starts like a DNS message, and UDP to
port 123 when it looks like NTP. Kharej to Iran is completely open, and ICMP echo passes both ways.

| Setup | Download | Upload |
|---|---|---|
| ICMP (all four types) | 7-10 MB/s | 7-10 MB/s |
| Direct `udp`, `tcp`, `tls`, `ws`, ... (no switches) | cut within a second | |
| **Direct `udp` + `udp-dns` on port 53** | 21-33 MB/s (`sessions: 4`: 32.6); 400 MB run: 36 | 19-24 MB/s; 400 MB run: 29 |
| **Direct `tcp` + `fake-sni` `rst`** | 14 MB/s; `sessions: 4`: 21.5; `pool-rotate`: 27.8 | 16-32 MB/s |
| Direct `tls` + `fake-sni` `rst`, Chrome fingerprint, small hello | 15 MB/s | 15 MB/s |
| Reverse `tcp` | 22 MB/s; with `pool-rotate` 28 | 26 MB/s; 32 |
| Reverse `wss`, `tls`, `h2`, `ws` | 19-25 MB/s | 27-30 MB/s |
| Reverse `udp` | 21 MB/s | 19 MB/s |
| Bonded `icmp`+`udp`+`tcp` (the direct members are cut) | stays up on the ICMP member | |

Fake-SNI modes other than `rst` and `synrst` do not get through this filter on a direct tunnel; `sum` and `seqsum`
fail here because of the virtual NIC's checksum offload (identically with 2.10.12). With `hdr-mask`, `shape` and
`tcp-mimic` on or off, speeds were the same within noise. Interoperation with 2.10.12 on one end worked on `icmp`,
reverse `tcp` and reverse `tls` in both directions.

On the wire (tcpdump on the Iran box): with the defaults every datagram has a different first 8 bytes (359 of 359
from Kharej, 41 of 41 from Iran), against one repeated session id with `hdr-mask: false`; idle packets use about 40
sizes between 20 and 143 bytes against 20 sizes between 29 and 76; 16 raw-`tcp` connections opened with 16 different
517-byte hellos. The test found one bug, fixed in 3.0.0: a client that started before its server stayed on the plain
header for the whole session.

Not tested on this pair: carriers through a CDN, `ech`, the manager's auto mode, and any real DPI.

## Resource usage: idle, RAM, CPU and bandwidth

### Idle tunnel

These figures are for a connected tunnel with no users and no traffic. They come from a 5-minute run of 2.5.1 on a
local udp pair and a local tcp pair, measured on 2026-10-17. Both pairs showed the same session-level numbers. These local pairs ran on Windows. The engine is the same Go code on
Linux, where an idle Iran tunnel measured 32 MB of RSS after a load test (see RAM in production below).

| | Iran (client) | Kharej (server) |
|---|---|---|
| Packets sent | 0.5 per second | 1.5 per second |
| Tunnel bytes sent | 16 B/s | 61 B/s |
| CPU | 0.15-0.2 % of one core | 0.13 % of one core |
| RAM (working set, no users) | 10-16 MB | 10-17 MB |

The idle traffic comes from three sources:

- **Iran:** a keepalive ping goes out after 2 seconds with nothing else sent.
- **Kharej:** it acknowledges each ping. It also sends a restart marker once a second, so that Iran notices quickly
  when Kharej restarts.
- **Both:** every packet carries 32 bytes of header and authentication tag.

Wire bytes per carrier, computed from the measured packet rate (2 packets per second in total) and each carrier's
own headers:

| Carrier | Extra per packet | Idle traffic, both directions | Per day | Per 30 days |
|---|---|---|---|---|
| `udp` | 28 B (IP + UDP) | ~133 B/s | ~11.5 MB | ~345 MB |
| `icmp` | 28 B (IP + ICMP) | ~133 B/s | ~11.5 MB | ~345 MB |
| `icmp` reverse | same, plus 4 empty knocks every 5 s, and the kernel's answers to them | ~180 B/s | ~16 MB | ~470 MB |
| TCP-based (`tcp`, `tls`, `ws`...) | 2 B frame + TCP/IP headers, plus TCP's own acks and keepalives | a few hundred B/s | under ~35 MB | under ~1 GB |

The TCP-based row is an upper estimate, not a measurement. TCP adds its own packets, and their number depends on
`conns` and the kernel's keepalive settings.

An idle tunnel therefore costs about as much as a few kilobytes of a web page per minute. The 30-second dead-link
timeout and the reconnect logic need no extra traffic.

### RAM in production

| Tunnel | Load | RSS |
|---|---|---|
| ICMP, 1.8.0 | 250-300 real clients | ~40 MB |
| ICMP, 2.4.8, Iran | ~200 connections | 76 MB |
| CDN (`wss`), 2.4.6 | ~250 user connections | Iran 79-100 MB, Kharej 75-103 MB |
| CDN test tunnel, 2.4.17, Iran | 50-connection load, then idle | 33-43 MB, 32 MB after |
| Reverse tcp, 2.5.0, Iran | 455 streams plus a 16-stream download | 113 MB, rising to 280 MB during the download |
| Reverse tcp, 2.5.1, Iran | 16-stream download on a test tunnel | 149-161 MB, flat |

If you set `GOMEMLIMIT`, give it at least twice the tunnel's normal memory. See [Memory with slow readers](#memory-with-slow-readers-243).

### CPU in production

| Tunnel | Load | CPU (percent of one core) |
|---|---|---|
| ICMP, 1.8.0, Iran | per MB moved | 0.026 CPU-s (GOST ICMP: 0.15-0.20) |
| Reverse tcp, 2.5.1 | 195 MB/s download (2 GB run) | Iran 128 %, Kharej 59 % |
| Reverse tcp, 2.5.1 | 276 MB/s upload | Iran 132 %, Kharej 72 % |
| Reverse tcp, 2.5.1 | 122 MB/s download, 8 streams | Iran 94 %, Kharej 44 % |

### Bandwidth overhead under load

This is how many bytes the tunnel adds on top of what your users move. It was measured with 2.5.1 on the same local
pairs: a 512 MB transfer each way, 8 streams, and no loss. Tunnel bytes include the 32-byte header and tag of every
packet and the frame headers.

| Carrier | Packet size | Tunnel bytes per payload byte | Acks back (share of payload) | With the carrier's own headers |
|---|---|---|---|---|
| `udp` | ~1,394 B | +2.95 % | 0.43-0.51 % (one ack per ~7 packets) | ~+5.0 % forward, ~0.8 % back |
| `tcp` (direct pool) | ~16,380 B | +0.25 % | 0.03 % (one ack per ~13 packets) | +0.25 %, plus TCP/IP headers (~3 % at a 1500-byte MTU, the same as any TCP connection) |
| `icmp`, `mtu: 1400` | ~1,400 B | ~+3 % | ~0.5 % | ~+5 % |
| `icmp`, default 640 | 640 B | ~+6.5 % | ~0.5 % | ~+11 % |

- **Measured:** the `udp` and `tcp` rows.
- **Computed:** the `icmp` rows. They use the same ~40 bytes per packet measured on `udp` (32 header and tag, plus the
  frame header) and 28 bytes of IP and ICMP header.

On a lossy route, add the resent packets. `/stats` counts them in `retrans`; at `mtu: 1400` on the Iran ⇄ Europe ICMP
route, Kharej resent 0.3-0.8 % of its packets.

To check your own tunnel, compare `bytes_out` in `/stats` with the user traffic in `/ports`.

## Install

Use the installer and the `wattun` menu described in the main [README](../README.md). Running `wattun` with no
flags (or with a first argument that does not start with `-`, such as `wattun auto-test NAME`, `token NAME`, `update`,
`status` or `auto-ip NAME IP`) hands over to `/usr/local/bin/wattun-manager`, which still works by its own name.
Engine usage (flags starting with `-`) is unchanged.

**Trust model.** `install.sh` checks the release binary, and the `wattun-manager` file when the release ships it,
against the RSA-signed `SHA256SUMS`; the public key is baked into the script, and a missing or invalid signature
aborts the install (a local `dist/` build skips the remote check). The installer script itself, fetched with
`curl | bash` through `WAT_PROXY` (a third-party mirror, untrusted), has no signature to check on that first hop:
that is trust-on-first-use. `wattun-manager update` now downloads the installer from the release assets and verifies
it against the same signed `SHA256SUMS` before running it as root. Unsigned installs are explicit opt-ins:
`WAT_ALLOW_UNSIGNED_MANAGER=1` takes a manager from `raw.githubusercontent.com` when a release does not ship one
(never through `WAT_PROXY`), and `WAT_ALLOW_UNSIGNED_UPDATE=1` runs an unverified installer from `main`. Until a
release ships the new `dist/install.sh` asset (the next release built by the updated `build.sh`), the verified update
path fails closed; the override above is the only escape.

**Windows (2.5.0).** Releases include `wattun-windows-amd64.exe`, the engine alone (no installer, no manager): run it
with `-config FILE` or flags, as a client or a server. Every carrier but ICMP works; `icmp` needs a Linux raw socket
and fails at start. `tcp-cc` is ignored (BBR is set only on Linux). Use Windows paths in the config file.

## Quick start

### By hand, ICMP

Pick a secret and put it in the same key file on both servers.

```bash
# Kharej (server). Needs root or CAP_NET_RAW.
echo 'my-long-secret' > /etc/wattun/key && chmod 600 /etc/wattun/key
cat > /etc/wattun/kharej.yml <<'EOF'
mode: server
key-file: /etc/wattun/key
metrics: 127.0.0.1:19700
ports:
  - 443
EOF
systemctl enable --now wattun@kharej

# Iran (client): public port 443 is forwarded to Kharej's 127.0.0.1:443
cat > /etc/wattun/iran.yml <<'EOF'
mode: client
key-file: /etc/wattun/key
peer: 203.0.113.10
ports:
  - 443
EOF
systemctl enable --now wattun@iran
```

Check: `curl -s 127.0.0.1:19700/stats` on Kharej shows `"alive": true` once Iran connects.
Do not start a second instance on a port that a live one already uses (see [Troubleshooting](#troubleshooting)).

## Managing tunnels

Run `wattun` for the dashboard of all tunnels (`wattun-manager` still works). Keys:

- A tunnel's number: manage that tunnel.
- `n`: new tunnel.
- `m`: live monitor.
- `u`: update.
- `s`: settings (rollback, uninstall, auto-heal).
- `q`: quit.

A tunnel's page has:

- diagnose and speed test
- logs
- the port-mapping editor
- the token
- advanced settings, grouped as Performance / Shaping & DPI / Safety / State & data (speed ceiling,
  sessions/conns/mtu, FEC and its loss band, win-max, loss-ceiling, bind, ICMP type, direction, resilience, state
  files, shaping, admission allowlist)
- change connection type (**c**)
- restart and delete

The tunnel page is a two-column action deck with a status header and the live route above it: **↑/↓** move,
**Tab** or **←/→** switch column, **Enter** opens the highlighted action, and every action keeps its hotkey.
The page explains the highlighted action in one line, so nothing has to be memorized. Its **Spoofing & shaping** page
(the same taxonomy as this document, `shape-data` and `noise` included) is also reachable as `h` in the Anti-censor
page. A fixed connection type — the 3.3.0 shaped carriers included — is set at creation through the unattended
`wattun kharej --carrier ...` path or a token; the interactive Kharej wizard makes Auto tunnels only, and **c** shows
the type in use (Iran changes it by pasting a new token).

Advanced settings validate their values against the engine before writing them and restart the tunnel when you leave
the page: `sessions` 1-16 (and above 1 only for a single udp/pool carrier, not a bond or a reverse tunnel), `conns`
1-64 per pool, `mtu` 256-1400 (up to 16384 when every leg is a pool carrier; a bond keeps the bound of its smallest
leg), `state-dir`/`state-save`, the FEC loss band (`fec-on-loss`/`fec-off-loss`, shown only with `fec: auto`),
`shape-data`, `noise`/`noise-bps`/`noise-window`, and on a Kharej tunnel `allow-clients`/`allow-clients-file`. The page
is grouped into Performance / Shaping & DPI / Safety / State & data; `win-max` (4-64) and `loss-ceiling` are in
Performance. The FEC choice itself stays a one-key `off`/`auto`; answering `a` at that prompt opens the loss-band rows
(3.3.0+). Keys with no UI path (`debug`, `ping-every`, `udp-idle`, `tcp-cc`, `slack-ms`, `hedge`, `lanes`,
`mem-budget`, `plain`, plus `port-offset` and the TLS cert/key paths) are documented as file-only expert keys in
`/etc/wattun/NAME.yml`.

When a link is down, the doctor names the likely cause — and when a direct pool carrier's TCP port is
still reachable but the tunnel cannot connect (the SNI-allowlist tell), it points at `wattun blackout`.

```bash
wattun                 # dashboard
wattun new kharej      # new tunnel (kharej or iran); do Kharej first
wattun status          # one line per tunnel
wattun monitor         # live dashboard
wattun ports NAME      # edit the port mappings of a tunnel
wattun test NAME       # connection doctor + speed test
wattun speedtest NAME  # speed test only (10 MB each way; client side)
wattun reset-traffic NAME  # zero the lifetime traffic counters of a tunnel
wattun logs NAME       # follow the log
wattun token NAME      # print the Kharej token
wattun profile save NAME [tunnel]  # save a tunnel's fake-sni/pool-rotate combination under a name
wattun profile apply NAME [tunnel] # put it back after a reinstall (also: list, show, del NAME)
wattun blackout NAME [SNI]         # one command to turn the resilience kit on when a censor starts blocking
wattun auto-test NAME  # re-run the Auto mode test
wattun cdn-tune NAME   # re-tune a Cloudflare tunnel
wattun auto-ip NAME IP # tell an auto tunnel Iran's IP (on Kharej)
wattun auto-narrow NAME        # close the carrier ports an auto Kharej tunnel no longer needs
wattun auto-widen NAME         # open every carrier of an auto Kharej tunnel again
wattun auto-prune NAME [--keep-open|--auto|--direct|--reverse-only]  # automatic cleanup state of an auto Kharej tunnel
wattun bond-retest NAME        # bonded Iran tunnel: re-test its legs and add one that works again
wattun update | rollback | help
```

**Config.** Each tunnel is `/etc/wattun/NAME.yml`, run by systemd as `wattun@NAME`. The keys are the flag names. Only
the `ports:` list reloads live (within 3 seconds). Any other change needs `systemctl restart wattun@NAME`.

```yaml
# /etc/wattun/iran.yml
mode: client
key-file: /etc/wattun/iran.key
carrier: icmp
peer: 203.0.113.10
metrics: 127.0.0.1:19750
ports:
  - 443          # users connect to Iran :443, delivered to Kharej 127.0.0.1:443
  - 8443:443     # users connect to Iran :8443, delivered to Kharej 127.0.0.1:443
  - 53/udp
  - 5353:53/udp
```

On Kharej, `ports:` is an allowlist of target ports. Leave it out to allow any port. Every key: [Config file](#config-file).

**Auto-heal.** A systemd timer (`wattun-heal`) restarts an Iran tunnel whose link has been down for 3 minutes.

- It turns on automatically for Iran tunnels. To turn it off: `wattun` → `s` → `h`.
- It never restarts a tunnel you stopped yourself.

**Monitoring.** Each tunnel serves a small HTTP API on `127.0.0.1` only. Never expose it.

```bash
curl -s 127.0.0.1:19750/stats       # alive, last_rx_age_ms, srtt_ms, rate_bps, loss_pct, streams, sessions, bytes...
curl -s 127.0.0.1:19750/ports       # traffic per port
curl -s '127.0.0.1:19750/speedtest?dir=down&mb=10'   # built-in speed test (client side)
```

To judge a link's health, use `last_rx_age_ms` rather than ping. Fields: [Metrics](#metrics).

**Choosing a connection type by hand.**

| Your situation | Use | Notes |
|---|---|---|
| Only ping passes | `icmp` | Needs root. `icmp-type` can be `echo` or `timestamp` (Linux does not answer `info`/`mask`). |
| UDP works | `udp` | Lowest latency and CPU. |
| Plain TCP works | `tcp` | A pool of connections. |
| Traffic should look like HTTPS | `tls` | TLS 1.3. Set `tls-pin` to pin the certificate. |
| Through a CDN | `wss` or `grpc` | See [CDN tuning](#cdn-tuning). `ws`/`h2c` are for a CDN on port 80 or a proxy that handles TLS. |
| Iran can't ping Kharej, but Kharej can ping Iran | `icmp` + reverse | Kharej sends the pings, Iran answers. |
| Iran can't reach Kharej's TCP port, but Kharej can reach Iran | TCP-type carrier + reverse | Iran listens, Kharej dials. |
| Don't know | `auto` | See [Auto mode](#auto-mode). |
| Must survive any one carrier being blocked | Bonding, e.g. `carrier: icmp+udp+tcp` | See [Bonding](#bonding). |
| The filter classifies by outer IP protocol number, UDP port or first header | A shaped carrier, e.g. `carrier: vxlan` | Both ends 3.3.0 and the same name; raw tier needs Linux + root. Wattun-internal shape, not the real protocol. See [Shaped carriers](#shaped-carriers-330). |

If the route cuts TCP in both directions, only ICMP (and reverse ICMP) will work.

## Carriers

All carriers carry the same encrypted session. Pick one with `carrier:` (or `-carrier`). Only the raw-socket carriers
need root: `icmp`, `gre`, `ipip` and the shaped raw tier (`sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3`); the
other carriers, including the shaped UDP tier, run as an ordinary user. The shaped carriers are described below.

| Carrier | Use it when | Default datagram size | Needs root | Notes |
|---|---|---|---|---|
| `icmp` | Only ping passes (Iran today). | 640 bytes | yes (raw socket) | 4 lanes by default (`lanes`). Pacing is delay-based. 640 is the safe default. Raise `mtu` (up to 1400) only after checking that the path passes that size, see [ICMP path limits](#icmp-path-limits-and-pacing). |
| `udp` | UDP works and you want the lowest CPU and latency. | 1400 bytes | no | Server listens on `listen`; client dials `peer` as `host:port`. |
| `tcp` | Plain TCP works. | 4096 bytes (up to 16384) | no | A pool of connections (`conns`, default auto: 8, 16 or 24-32 by host since 3.1.0). Reliable underneath, the session still repairs drops. |
| `tls` | A middlebox must see HTTPS. | 4096 | no | The tcp pool inside TLS 1.3. Self-signed certificate if none is given. Pin the fingerprint with `tls-pin`. |
| `ws` | Behind a CDN or reverse proxy, port 80. | 4096 | no | WebSocket on `path`. Other requests get a plain 404. |
| `wss` | Same, with TLS (Cloudflare on 443). | 4096 | no | Set `sni` and `host` to the public name. |
| `h2` | Proxies that prefer HTTP/2. | 4096 | no | One full-duplex POST per pool connection, TLS. |
| `h2c` | HTTP/2 without TLS, behind a TLS-terminating proxy. | 4096 | no | Same as `h2`, cleartext. |
| `grpc` | CDNs that allow gRPC. | 4096 | no | Requests go to `<path>/Tun`. `plain: true` for cleartext behind a proxy. |
| `gre` | UDP is dropped but GRE (IP protocol 47) passes. | 1364 | yes (raw socket) | 3.2.0, both ends. `peer` is a bare IP like icmp. Each packet is GRE (with a key from the PSK) carrying an IPv4/UDP packet; a BPF filter keeps other GRE traffic out. No `-reverse`. |
| `ipip` | Same, for IP-in-IP (protocol 4). | 1372 | yes (raw socket) | 3.2.0, both ends. Like `gre` without the GRE header. |
| `fortress` | Blackout mode: `wattun-manager arm-blackout NAME` writes it. | — | yes (includes icmp) | Not a wire protocol: a manager-written alias expanded to `icmp+tcp+tls+wss+udp` with default listeners 80/tcp, 443/tcp, 8443/tcp and 53/udp. |

Rules for every non-ICMP carrier: the client dials `peer` as `host:port`, and the server listens on `listen`
(default `:4443`). `mtu` is 256 to 1400 for icmp, udp, gre and ipip, and up to 16384 for the pool carriers (a bond
uses its smallest leg's bound). The 3.3.0 shaped carriers have their own, lower ceilings: see "Shaped carriers".

### Shaped carriers (3.3.0)

Thirteen carrier names put a fixed, key-derived header in front of every datagram so a classifier sees the
datagram of a protocol it knows. They are wattun-internal wire shapes between **two 3.3.0 wattun peers**, not
implementations of those protocols: no inner packet is produced or parsed and a real peer of that protocol will not
talk to them. Both ends must run 3.3.0, select the same carrier name and share the key; a datagram whose key-derived
fields do not match is dropped, so a third party speaking the same protocol number cannot inject into the session.

**Raw tier** (`sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3`) — one raw-IP socket per IP protocol, a bare-IP
`peer` like `icmp`/`gre`, no `listen` and no `-listen-NAME`, no `-reverse`, one session (`-sessions` > 1 is
rejected), Linux + CAP_NET_RAW on both ends. The MTU is 1400 minus the shape's header.

| Carrier | Outer IP protocol | Header on the wire |
|---|---|---|
| `sit` | 41 | 40-byte inner IPv6 header (6in4-like) with ULA `fc00::/7` addresses |
| `6to4` | 41 | 40-byte inner IPv6 header with the `2002:V4ADDR::/48` prefix |
| `xfrm-ipsec` | 50 (ESP) | 8-byte ESP header: key-derived SPI + sequence counter |
| `etherip` | 97 | 2-byte EtherIP header + 14-byte Ethernet header |
| `l2tpv3` | 115 | 4-byte L2TPv3-style session header with a key-derived session id |

**UDP tier** — the ordinary `udp` carrier with one fixed header per datagram. The client dials `peer` as
`host[:port]`, the server listens on `listen` (`host[:port]`); a bare host uses the protocol's conventional port
below, and an explicit port in the address wins. `-reverse` and `-sessions` > 1 are rejected.

| Carrier | UDP port | Header on the wire |
|---|---|---|
| `fou-gre` | 5555 | 8-byte GRE header with a key + protocol `0x0800` |
| `gue-ipip` | 6080 | 8-byte GUE-like header (v1, proto `0x0800`, includes a 4-byte key) |
| `vxlan` | 4789 | 8-byte VXLAN header with the I flag + 24-bit VNI |
| `geneve` | 6081 | 8-byte Geneve base header (proto `0x6558`) + 24-bit VNI |
| `dnscrypt-udp` | 443 | 11-byte key magic + version + length, then zero padding to a multiple of 64 (256 B minimum) |
| `ntp-direct` | 123 | 48-byte NTPv4 header (mode 3 from the client, 4 from the server) + key reference id |
| `openvpn-dco` | 1194 | 4-byte OpenVPN P_DATA_V2-like opcode/key id + key-derived 3-byte peer id |
| `srtp-direct` | 5004 | 12-byte RTP header (V2, payload type 96, sequence + timestamp, key-derived SSRC) |

These names are not real protocols and do not add secrecy: they only change the outer bytes a middlebox inspects,
for filters that classify by protocol number, port or first header. In particular they are **not** IPsec, 6in4,
EtherIP, L2TPv3, VXLAN, Geneve, FOu, GUE, DNSCrypt, NTP, OpenVPN DCO or SRTP interoperable. `udp-dns` is ignored on a
shaped carrier (the shape owns the datagram prefix). A shaped carrier is **single-carrier only in 3.3.0**: the engine
refuses a `+` bond that contains one (exit code 2), and the manager refuses the same list, because each shape derives
its own header and the UDP tier its own conventional port. `shape-data` is ignored on bonded tunnels.

**Cost (loopback bench).** Repeated `go test -run xxx -bench 'ShapedUDP' -benchtime 2s ./wat/` runs put the shaped
versions 0.3-4.5 % below plain `udp`; one short run scatters much more (about -13 % to +9 % between runs), so read a
single-row number as noise, not a per-shape ranking. There is no live filtered-pair bench for these carriers yet.

**Manager support (3.3.0).** The manager can create and run these carriers from its unattended Kharej path
(`wattun kharej --carrier NAME ...`, one shaped carrier at a time), from the interactive Kharej picker's **More
transports (advanced)…** branch, and from a shaped token pasted on Iran (the Iran wizard, or **t** New token). Before
writing a config it checks that the local binary is 3.3.0+, refuses the raw tier on a non-Linux host, warns about
root/CAP_NET_RAW and about allowing the raw tier's IP protocols in the cloud firewalls (41 for `sit` and `6to4`, 50
for `xfrm-ipsec`, 97 for `etherip`, 115 for `l2tpv3`), and for the UDP tier writes and opens the conventional port
unless `--listen` gives another. It refuses a `+` bond that contains a shaped carrier, matching the engine. Change
peer takes a bare host for the raw tier and `host:port` for the UDP tier.

**Manager limits.** Where the type is shown (change connection type) the manager repeats the not-real warning but
offers no picker: Kharej fixed the type, and Iran changes it by pasting a new token, which may be shaped. `sessions`
above 1 is refused, the connection test skips the TCP probe for a shaped leg, and Auto mode reaches the shapes only
through the opt-in extended mode (each one gets its own hidden single-carrier Kharej unit; see "Auto mode"). The MTU
ceiling is per shape (1400 minus the header), and an explicit `-mtu` above it is clamped with a log line: raw tier
`sit`/`6to4` 1360, `xfrm-ipsec` 1392, `etherip` 1384, `l2tpv3` 1396; UDP tier `dnscrypt-udp` 1326, `ntp-direct` 1352,
`srtp-direct` 1388, `fou-gre`/`gue-ipip`/`vxlan`/`geneve` 1392, `openvpn-dco` 1396.

### Fake-SNI desync (`fake-sni`, 2.6.0)

For routes where TCP passes but the path filter classifies every flow by the TLS ClientHello SNI and stops
non-allowlisted ones (the 2026 whitelisting). The client completes a normal TCP handshake, then injects one raw
packet: a TLS ClientHello with an allowlisted SNI (`mci.ir` and similar) and a sequence number below the stream
start. A DPI that reassembles flows without checking the TCP window reads that hello and marks the flow
"TLS to an allowed site"; the server's kernel sees an old duplicate and answers with a plain duplicate ACK, so
the relay then carries the session's own encrypted datagrams as if they were that connection's application
data. `fake-mode: ttl` instead gives the marker a TTL that expires at the filtering hop (`fake-ttl`), so it never
leaves Iran's network at all.

Since 2.7.0 the injector watches the wire (AF_PACKET) for every pool connection from the moment dial returns:
it anchors the marker packet to the handshake's final ACK when it observed the SYN/SYN-ACK, to the first outbound data
segment otherwise, and a NAT that rewrites sequence numbers uniformly no longer misfires (the marker follows the
rewrite). Works on the `tcp`, `tls`, `wss`, `h2` and `grpc` carriers. `fake-ttl: 0` (the default) calibrates
itself: the peer's inbound TTL is learned from its SYN-ACK, the marker goes out one hop short of the server.
In 2.10.11, the injector aligns directly with `patterniha/SNI-Spoofing`: `tcpStreamBase` extracts both `SND.NXT` and
`RCV.NXT` directly from the socket via `TCP_REPAIR`, and `Wrap` pauses the real flow until the server's RFC 793
duplicate ACK (`ack == SND.NXT`) confirms that the fake packet has traversed the DPI before the real ClientHello
is transmitted. `FakeClientHello` uses an authentic 517-byte Chrome template with RFC 7685 padding and no ECH GREASE.
Specifying `fake-sni` also automatically enables `tls-small-ch` to avoid 1.5 KB post-quantum ClientHello drops; since
3.0.0 an explicit `tls-small-ch: false` in the config wins. 3.0.0 also sizes the duplicate-ACK wait from the
handshake RTT (two RTTs, 300 ms to 2 s, was a fixed 200 ms, less than one RTT on a 250 ms path) and resends the marker
once if no duplicate ACK came within 1.25 RTT. `WAT_DESYNC_FAIL_CLOSED=1` makes a connection whose marker was never
confirmed fail its dial, so the pool redials instead of running a flow the filter may cut (off by default).
2.10.12 fixes the `TCP_REPAIR` probe, which selected the wrong queues (`TCP_REPAIR_QUEUE` is 1 = receive, 2 = send;
the old code used 0 and 1), so `tcpStreamBase` failed or read the wrong sequence number and the fake fired on only one
of two pool connections. It also lets the dialing side of a `-reverse` tunnel (the Kharej server) run `fake-sni`: the
injector tracks any outgoing handshake, so a reverse server dials with the same desync as a client. `/stats` `alive` and
`filter_profile` are honest again (see the 2.10.12 changelog entry). Only the dialing end needs 2.10.12; the wire is unchanged.

Client-side only, Linux only, needs CAP_NET_RAW (the icmp carrier's requirement); the server needs no change
and no new version. Two caveats from field reports of the same trick in other tools: it died where the ISP's
NAT normalizes sequence numbers before the DPI (some ASNs, not all), and the allowlisted SNI itself must be
reachable from your ISP. If connections stop passing data right after the handshake, your path is one of the
normalizing ones — fall back to `tls` with `sni` set to an allowlisted name and `tls-frag`, or ECH.

## Fake-SNI desync (whitelisting survival)

For the SNI-checked whitelist regime (Iran 2026): the filter forwards TCP to an allowlisted IP only when the
TLS ClientHello on that flow carries an allowlisted SNI, and it does not check TCP sequence numbers. Both facts
together are the desync: the client opens its real pool connection, then injects ONE extra raw packet next to it that
carries an extra ClientHello with an allowlisted SNI (`mci.ir` worked in the field) — crafted so the server never
accepts it, while the DPI, reassembling without window checks, reads it as the flow's first flight. From then on
the session's own encrypted datagrams ride the flow, classified as TLS application data to the allowed site.

- `fake-sni: mci.ir` on the client, `carrier: tls` (or `tcp`, `wss`, `h2`, `grpc` since 2.7.0). Linux +
  CAP_NET_RAW, like the icmp carrier.
- `fake-mode: auto`: the client measures the route once at startup and picks the mode itself. Since 3.0.0 it tries
  `none`, `rst`, `synrst`, `seq` in that order, each on a fresh connection to the real peer port wrapped exactly like a
  pool dial, writes 32 KB of filler shaped like the carrier's first bytes (a never-finished ClientHello carrying the
  carrier's SNI for tls/wss/h2/grpc, an unfinished HTTP request for ws/h2c, a pool hello for tcp), and keeps the
  first mode whose filler the kernel saw acknowledged within 2 s (`TCP_INFO` `bytes_acked`). The filters seen in the
  field let the handshake and a few KB through and then drop the flow, which the 2.9.0 probe (two tiny writes) could
  not see; it picked `seqsum` on a route where only `rst`/`synrst` work. `none` means the route does not filter
  that name, and the tunnel then runs without fake-SNI. No survivor is `route-cut`: the tunnel runs `rst` and keeps
  retrying. `/stats` `filter_profile` has `mode` (what runs) and `verdict`. Costs up to four short connections and
  up to ~18 s at startup, once (no candidate starts after 12 s); without a raw socket or `TCP_INFO` it runs `rst`.
  `none` only proves that the first 32 KB passed: a filter that cuts on volume or after minutes is not seen, so set
  `fake-mode` explicitly if an `auto` tunnel dies later. Only the dialing end needs 3.0.0.
- `fake-mode: seq` (default): the marker's sequence number is `ISN+1-len(marker)`, below the stream start. The
  server's kernel counts it as an old duplicate and answers with a dup-ACK; the DPI still read the SNI. A NAT
  that rewrites sequence numbers uniformly shifts the marker with it (2.7.0), so only non-uniform normalization
  breaks this mode.
- `fake-mode: ttl` + `fake-ttl: N`: the marker expires at the filtering hop and never reaches the server at all. N is
  the hop count of the DPI box minus one: find it with `traceroute` to your server, then test downward.
  `fake-ttl: 0` (2.7.0) auto-calibrates from the server's inbound TTL. Some ISPs normalize TTLs; there `seq`
  works better.
- `fake-mode: sum` (2.7.1): the marker is an in-window duplicate of the first data segment — same sequence and
  ack numbers, valid window — but with a deliberately damaged TCP checksum. The DPI's reassembler reads it
  (it parses before checksumming); every server kernel drops it at checksum validation, so the flow stays
  clean. This holds against filters that DO check TCP sequence numbers, where `seq` fails. Caveats: it needs a real
  data segment to mirror (fires with the first outbound data, not the handshake's final ACK), and it dies
  behind a NAT that validates checksums (Linux routers with `nf_conntrack_checksum=1` plus an INVALID-drop
  rule; ISPs usually pass bad checksums). (2.8.0 fix: the old damage formula `(checksum ^ 1) - 1` collapsed to
  the unchanged value for every even checksum — half the markers shipped valid, and the server would have taken
  their payload as real data. It is now `checksum - 1`, or `- 2` when that would wrap to the valid fold.)
- `fake-mode: seqsum` (2.8.0, experimental): BOTH markers per connection — the below-window seq fake first,
  the in-window bad-checksum mirror about a millisecond later (the GoodbyeDPI wrong-seq + wrong-chksum double
  fake). A filter must discard both correctly to miss the SNI: window-junk dropping alone does not stop the sum
  marker, checksum dropping alone does not stop the seq marker. Inherits sum's caveats (data segment needed,
  checksum-validating NATs) plus seq's (a uniform NAT rewrite is followed, a non-uniform one defeats marker 1).
  Since 3.0.0 `sum` and `seqsum` are refused with `-reverse` (they rely on the server's kernel dropping the damaged
  segment, which checksum offload on the peer may not do; `sum` failed on the field run's reverse tcp); the manager switches them to `rst`.
- `fake-mode: rst` (2.9.0): the marker is an in-window RST|ACK with a damaged TCP checksum, sent instead of a
  ClientHello. A middlebox that tracks flow state clears the flow on the RST and stops inspecting it, while the
  server's kernel drops the corrupted packet before it reads the flags, so the real connection is untouched.
  The marker carries no ClientHello, so no SNI: it is for filters that keep per-flow state and stop
  inspecting a flow once they have classified it. Same caveat as `sum` on checksum-validating
  NATs, and the marker must stay in-window: a low-TTL RST can reach the server after a reroute shortens the path
  and tear the real connection down, which is exactly what this mode exists to avoid.
  `fake-mode: auto` tries it right after `none` (3.0.0). `synrst` adds a marker before the handshake completes.
- The server needs NO changes and no update: it never sees the marker packet. Only the client needs 2.6.0.
- The manager sets none of this up by default: the Iran wizard asks one explicit question (Enter =
  skip), Advanced settings → resilience (`k`) on the tunnel page changes the values of an existing
  tunnel, and `wattun-manager profile save NAME` keeps a working combination for the next install.
  Auto mode never offers these keys, and its type switches keep or strip them per the chosen type.
  When a censor starts blocking a working tunnel, `wattun blackout NAME [SNI]` turns the kit on with
  one command: it asks for an allowlisted name (or takes it as the second argument), writes
  `fake-sni` + `fake-mode: seq` + auto ttl, and restarts the tunnel — fine-tuning stays in Advanced
  settings. Diagnose and the heal timer point at this command when a direct pool carrier's TCP port is
  still reachable but the tunnel cannot connect (the SNI-allowlist tell).
- Combine with the tls carrier's own camouflage: `sni` set to an allowlisted name and `fp: chrome` make the
  REAL ClientHello pass too, for filters that check both directions; `tls-frag` splits it past DPIs that only
  reassemble the first segment.

What it does not survive: a NAT on the route that fully validates checksums and sequence numbers before the DPI
(some ISPs moved to this after the first filtering wave — then no client-side trick helps, only ICMP/CDN routes),
and allowlists enforced purely by destination IP, where no SNI is read at all.

```yaml
# /etc/wattun/iran.yml
mode: client
carrier: tls
peer: kharej.example.com:443
fake-sni: mci.ir
sni: mci.ir
fp: chrome
key-file: /etc/wattun/key
```

### Full restricted routing: the domestic relay chain (no new code)

For the hard restricted-routing scenario (foreign IPs unreachable from Iran, only domestic traffic passes) the recipe is a
two-hop chain of two normal tunnels — no WatTunnel changes needed, both hops are stock wattun since 2.0:

1. **Get a domestic relay**: any Iranian VPS / a friend's server / a cheap "Iran location" cloud instance whose
   IP is reachable from your users' ISPs while foreign IPs are cut. It only needs to be able to reach the
   Kharej server; everything on it is private.
2. **Hop 1 — Kharej side (mode: server)**: run the normal Kharej setup on the REAL server (as always), but
   instead of giving Iran the Kharej token, run a second wattun as a CLIENT on the domestic relay, pointed at
   Kharej over a carrier that still passes from the relay (the relay sits inside Iran and dials out — whatever
   passes from it: `tcp`, `tls`+`sni`, `wss`+CDN, or `icmp` when only ICMP passes).
   `/etc/wattun/relay-out.yml`: `mode: client`, `carrier: tls`, `peer: KHAREJ_IP:443`, the same `key-file` as
   Kharej's config, `ports:` mirroring the services (or `ports: [0]`-style full maps as usual).
3. **Hop 2 — Iran side (mode: server→client flip)**: on the domestic relay also run a wattun SERVER that accepts
   the users' connections, whose `ports:`/forwarding targets point at `127.0.0.1` of the relay's client from
   hop 1. Iran connects to the relay's IP with any carrier that passes Iran→relay (domestic traffic is rarely
   filtered).
4. Iran users now reach Kharej through relay-in (server) → relay-out (client) → Kharej. The relay forwards
   encrypted datagrams twice; it never sees plaintext (both hops are AEAD sessions under your key).

Costs and caveats: the relay's bandwidth caps the chain (double-encryption costs ~nothing CPU-wise on modern
VPSes, but the relay's uplink is the bottleneck); each hop adds its RTT (~relay↔Kharej latency dominates);
and the relay is a single point of failure — keep the direct token as a fallback and re-run `auto-test` on
Iran when the restriction lifts. wattun-manager does not automate this chain yet: set both relay configs up by
hand (or run `wattun-manager` twice on the relay, with `WAT_PREFIX=relay1` / `WAT_PREFIX=relay2` sandboxes so
the two installs do not collide).

## Bonding

`carrier: icmp+udp+tcp` joins several carriers into ONE session. The session keeps working when any one of them
is blocked, and traffic is spread over the carriers that are alive (watch `carriers` in `/stats`). Use any
combination of the carriers above, joined with `+`.

`peer` and `listen` are the defaults for every carrier in the bond. `peer-NAME` and `listen-NAME` override them for
one carrier, where NAME is the carrier name (`peer-udp`, `peer-tcp`, `listen-udp`, `listen-tcp`, ...). They are
config keys and flags like any other. ICMP takes a bare IP, the others `host:port`, so a bond usually needs the
overrides. Both ends must list the same carriers.

```yaml
# Iran (client)
mode: client
key-file: /etc/wattun/iran.key
carrier: icmp+udp+tcp
peer: 203.0.113.10          # icmp uses this (bare IP)
peer-udp: 203.0.113.10:4443
peer-tcp: 203.0.113.10:4444
ports:
  - 443
```

```yaml
# Kharej (server)
mode: server
key-file: /etc/wattun/kharej.key
carrier: icmp+udp+tcp
listen-udp: :4443
listen-tcp: :4444
ports:
  - 443
```

### Bond auto-retest (3.3.0)

A censor can block one leg of a bond for hours and clear it later; the bond keeps working on its remaining legs, so
the blocked leg is only re-dialed forever unless something tries it again. On Iran, a bonded tunnel (`carrier` with
`+`) can re-test its legs on a schedule and add one back when it works again. This is a manager feature, no engine
flag: the tunnel page's **auto-retest** row (bonded Iran tunnels only) writes `/etc/wattun/NAME.bondretest`, never
the YAML (the engine rejects unknown keys).

| Value | Runs |
|---|---|
| `off` (default) | no timer |
| `30m`, `1h`, `6h` | every 30 minutes, 1 hour or 6 hours (systemd timer; first run 5 minutes after boot, ±60 s jitter) |
| `daily-offpeak` | once a day at 04:15, ±5 minutes |

`wattun-manager bond-retest NAME` runs it now. What a run does:

- Probes every leg currently in the bond, every carrier the auto plan left out (an auto token names them), and the
  carriers that failed last time (kept in `/etc/wattun/NAME.bondfail`), with throw-away clients carrying the
  tunnel's key and settings; the live tunnel is untouched until something is added.
- **Never removes a leg.** A leg that fails is reported and stays in the bond. A carrier that works again is added
  only when no leg of the bond works at all, or when it reaches 10 % of the best working leg's throughput, so a
  barely-alive path does not enlarge the bond. Adding one rewrites `carrier:` and restarts the tunnel, so open
  connections drop for a few seconds.
- Moves test traffic: 1 MB each way per probed carrier, budgeted by `bondretest-budget` (`.manager.conf`, MB per
  run, default 20). When more carriers are queued than the budget fits, the rest wait for the next run.
- Writes its decisions to the journal (`logger -t wattun-bondretest`): which leg failed, which works now, what was
  added, and the total traffic spent.

Limits: Iran side only (the side that dials the bond), and not a reverse bond (Kharej is the dialing side there).
Setting the value to `off`, or deleting the tunnel, removes the timer.

### Fake-SNI field test (2.10.12)

Measured on 2026-10-25 between the owner's Iran server (185.84.158.216) and Kharej (185.71.219.227), binary 2.10.12,
test units only (`MemoryMax=300M`, `CPUQuota=60%`), removed afterwards. Iran's ICMP ping: 80.6 ms to the Cloudflare
edge 104.21.20.209, 100 % loss to Kharej; Kharej's ping to Iran: 40.7 ms. Speeds come from the built-in `/speedtest`
(8 streams, 20-100 MB down, 5-30 MB up), ping is the tunnel's `srtt_ms`. About 1.5 GB of Iran's traffic cap was used.

**The route.** Iran → Kharej direct (ports 47150 and 8443) is cut after the first exchange, about a second into every
flow, with or without TLS and with or without a fake. Iran → a Cloudflare edge with real SNI `www.cloudflare.com` passes (HTTP 403); with SNI
`cf.xoamrz.ir` (the real, proxied name) the TCP and TLS handshakes finish and then nothing comes back. So the filter
here is an SNI allowlist for the Cloudflare route, which is the case `fake-sni` is built for.

**Cloudflare edge, `wss`, Kharej origin on port 8443** (client: `peer` 104.21.20.209:8443, `sni`/`host` `cf.xoamrz.ir`,
`path` /wat, `conns` 4, `fake-sni: www.cloudflare.com`):

| `fake-mode` | Tries | Connected | Down / up (MB/s) | Tunnel ping |
|---|---|---|---|---|
| none (control) | 3 | 0 | - | - |
| `seq`, `sum`, `seqsum`, `ttl`, `split`, `hlen0`, `fakeip`, `all`, `ff`, `auto` | 2 each | 0 | - | - |
| **`rst`** | 10 | 6 | 9.3-14.8 / 1.8-4.9 | 122-143 ms |
| **`synrst`** | 4 | 2 | 12.0-13.1 / 3.2 | 136-144 ms |

`rst` (an in-window RST with a damaged checksum) and `synrst` are the only modes that connected, and every connection
that came up connected within 2 s and ran at full speed. They failed together in one stretch of about 40 minutes (five
attempts in a row, after roughly 350 MB of test traffic) and once more with `conns: 16`; why is not known. With 100 MB
transfers: 4 connections 13.8 MB/s down, 4.9 MB/s up; 8 connections 16.6 MB/s down. A pause of 100 or 250 ms between
the fake and the real hello (tried with a build that had one; all 8 such runs connected) was not needed, so there is
no such option. `auto`
picked `seqsum` and failed: its probe tests which marker kills a flow, not whether the real flow then survives;
`wattun-manager` anti-censor matrix (tunnel page `z`, then `m`) tests every mode the installed binary supports,
`rst`, `synrst` and `paws` included, once per pool leg of a bond (3.1.1).

**Reverse `tcp`** (Iran listens on 47151, Kharej dials, 4 connections, 60 MB down / 20 MB up):

| Kharej `fake-mode` | Down | Up | Ping idle / under load |
|---|---|---|---|
| none | 39.8 MB/s | 31.2 MB/s | 46 / 83 ms |
| `seq` | 39.9 MB/s | 36.2 MB/s | 42 / 65 ms |
| `rst` | 38.4 MB/s | 30.2 MB/s | 38 / 68 ms |
| none, 8 connections | 35.9 MB/s | 30.9 MB/s | 39 / 97 ms |

The fake costs no speed, and `raw_send_fails` stayed 0. A packet capture of an earlier reverse run (2 connections,
`seq`) showed the fake at the listening end on both pool connections, 517 bytes below the stream start, with the
duplicate ACK coming back.

## Traffic shape: what a DPI sees (3.0.0)

A tunnel that only forwards ports leaves marks that a flow classifier can learn, whatever carrier it uses. This release
removes the ones that were in our own packets and adds the one structural protection other reverse tunnels rely on.

**What a packet looked like before 3.0.0.** Every packet began with the 8-byte session id (the same in every packet of
a session) and an 8-byte packet number (a counter, with the top bit set for the server's direction), both in clear;
the rest was ciphertext. So on `udp` and `tcp` the first 16 bytes of each datagram or frame were a constant followed by
a counter. An idle tunnel also sent one keepalive every 2 s at one fixed size, and the first exchange of every session
had the same sizes. None of that is encrypted content, so none of it needed to leak.

**What changed.**

1. **Header masking (`hdr-mask`, default on).** The 16 header bytes are XORed with a ChaCha20 keystream, keyed from the
   PSK and seeded by the first 12 bytes of the ciphertext (the idea of QUIC header protection). Every packet header
   then looks random, and consecutive packets share nothing. The receiver cannot read the session id before it removes
   the mask, so the key is per PSK, not per session. The session still authenticates the real header, so masking only
   hides it. Cost: 122 ns per call, no allocation (Go benchmark, i7-11800H); a packet is masked once on send and unmasked
   once on receive (twice on a server, which reads the id first).
2. **Padding (`shape`, default on).** Packets with no stream data (acks, keepalives, the key exchange) get a `frPad`
   frame (type `0x0c`, one length byte, that many zero bytes) of 0-100 random bytes when they are shorter than 192 bytes.
   It is always the last frame, so an older peer stops parsing there and ignores it.
3. **Keepalive jitter (`shape`).** The idle keepalive interval is re-rolled to 60-140 % of `ping-every` after every ping.
4. **Raw tcp hello and masked lengths (`tcp-mimic`, default on).** Raw `tcp` used to open each connection with the plain
   8-byte pool id and frame every packet with a 2-byte length. Now the first bytes are a 517-byte TLS 1.3 ClientHello
   (Chrome cipher list, SNI from `fake-sni`, default `www.cloudflare.com`) whose `random` and `session id` fields carry
   an HMAC of the key, a fresh nonce and the pool id, so no two connections open with the same bytes and the listener
   verifies the hello before it accepts the connection (a wrong key is closed). The 2-byte lengths are XORed with a
   ChaCha20 stream per direction, keyed from the same root. After the hello the stream is the usual encrypted packets;
   it is not a real TLS session and does not pretend to be one (no ServerHello). It defeats "first bytes are not
   TLS" and fixed-structure checks, not a classifier that waits for a real handshake; use `tls`/`wss` for that. Since 3.0.1 the hello is built with utls (Chrome 106 shuffle profile): extension order and GREASE vary per connection, so there is no single JA3/JA4 to match; it parses on 3.0.0 peers too, and falls back to the fixed Chrome template when the SNI is too long for 517 bytes.
5. **Reverse udp.** [Iran starts nothing](#reverse-udp-300).

**Compatibility.** Padding and jitter are invisible to older peers. A masked header is not. A receiver first reads the
header as plain (a session id it knows), then as masked, and answers in the form it was addressed in. A new client that
hears nothing for 3 s switches between the two forms every 3 s until a packet authenticates (and again after 30 s of
silence), so it joins an older server a few seconds late and then stays plain. `hdr-mask: false` skips the wait and
sends the plain header; `shape: false` turns padding and jitter off. A client that went plain only because its server
was not up yet (it flips after 3 s of silence) moves back to the masked form as soon as the server's first padding
frame arrives: that frame's first byte is `1` ("I read masked headers"), which older peers skip. Both ends of a tunnel can be updated in any order.
A new `tcp` client whose hello gets no answer within 6 s falls back to the plain pool id on that connection (and retries
the hello after 30 s); `tcp-mimic: false` sends the plain id at once. A new listener accepts both forms.

**What is not hidden.**

- With `tcp-mimic: false`, or against an older peer, raw `tcp` opens each connection with the plain 8-byte pool id and
  plain 2-byte lengths. `tls`, `wss`, `h2` and `grpc` put both inside TLS.
- Volume and timing under load, long-lived flows and the destination address. Padding only reshapes idle traffic.
- The `icmp` carrier's echo structure.

**Why this release is not "more obfuscation".** The Backhaul tunnel (Musixal/Backhaul), which an operator reported running
without an Iran-only restriction, has no padding, shaping or evasion at all: its README documents none. In the usual
deployment its Iran end is the listener and the foreign end dials in, so an Iran VPS never starts a flow towards a foreign address. That is the
property `reverse` gives here, and 3.0.0 extends it to `udp`, the one carrier that could not do it. If a provider
restricts a VPS after a tunnel starts, first check which address the tunnel leaves from (`src-ip`) and which direction
it runs; a classifier cannot punish a flow that the VPS did not start. On a host with several public IPv4 addresses
the tunnel leaves from the one the routing table picks, which may not be the address the customers use; pin it with
`src-ip`. The manager shows it on the tunnel card ("leaves from") and offers the choice in the Iran wizard.

**What other tunnels do (researched for 3.0.0).** Backhaul and rathole send plain TCP by default (rathole offers
optional TLS or Noise); Backhaul's only protection is that the Iran end listens. GOST dials with a uTLS fingerprint and
offers probe resistance and obfuscation layers. obfs4 pads its handshake to a random length and masks frame lengths.
Iran's national filter is a protocol whitelist (DNS, HTTP/80, HTTPS/443 pass; the rest is dropped) and resets TLS to
blocked SNIs after the ClientHello (FOCI 2020, arXiv 2507.14183). That is why `tcp-mimic` copies the ClientHello shape
and the header mask removes the constant bytes. None of this is proven to be what restricted a given VPS.

### Stream padding and idle noise (3.3.0)

Two opt-in knobs change WatTunnel's own traffic beyond the 3.0.0 defaults. Both are off by default and spend real
bandwidth: they count against the host's traffic bill and the session's `max-mbps` ceiling, and they appear in the
session totals (`bytes_out`, `bytes_out_total`). The per-port counters, rate limits and per-port quotas keep counting
forwarded payload only.

- `shape-data PCT` (0-25, default 0): pads packets that carry stream data to a randomized realistic total size (small
  100-300 B, medium 500-900 B, or near the path MTU), so a size classifier sees a spread instead of the
  request/response pattern. The padding is budgeted as a percent of the stream bytes actually sent, plus a 4 KB bank
  so a small interactive packet can spend the allowance earlier bulk traffic earned; the budget is never exceeded
  (total padding <= the configured percent plus the bank). Bulk traffic is already full and pays almost nothing
  (in-process benchmark: under 0.004 % padded bytes); a small request/response flow pays up to the configured percent.
  The padding is an `frPad2` frame, always the last frame of a packet, so an older peer stops at the unknown type
  byte and loses nothing. Ignored on bonded carriers (a bond sizes every packet for the path it takes).
- `noise MODE` (`off` default; `low` 128 B/s, `med` 1024 B/s, `custom` with `noise-bps` 64-1,000,000 B/s): while the
  session has had no user data in either direction for about two keepalives, sends filler packets of random size
  (64 B up to about the per-second budget) at jittered intervals. `noise-window HH:MM-HH:MM` (local clock, may cross
  midnight; empty = all day) limits it to an off-peak window; `noise-window` without `noise` is ignored with a
  warning. Noise spends pacer tokens, so it cannot burst past the session ceiling, and it is never acked,
  retransmitted or in flight; the keepalive cadence is unchanged. Budget: `low` is about 128 B/s (~11 MB/day),
  `med` about 1 KB/s (~88 MB/day) of real traffic, **per session** (see below).

The noise budget is **per session**, not per tunnel: every session sends its own configured rate, so `-sessions 2`
doubles the daily bytes and a Kharej serving N clients carries N times that rate. A normal 2-vCPU client defaults to
two sessions, i.e. about 22 MB/day on `low` and 176 MB/day on `med` in total. The delivered rate tracks the configured
budget (the pump now wakes at the filler deadline instead of the 100 ms idle tick), and noise alone does not keep the
10-second stats line printing.

Both count in `/stats` as `shape_data_bytes`, `noise_sent` and `noise_bytes` (see Metrics). Older peers ignore both:
`frPad2` is the last frame, an unknown frame type ends their parse, and nothing else in the packet changes.

## Spoofing and shaping, explained

The anti-censor options are often lumped together as "obfuscation". They do different jobs, and none of them hides
everything. Two words separate them here:

- **Spoof** means the censor is shown a second, fake artifact next to the real flow and the peer ignores it
  (`fake-sni`). The fake carries no session data.
- **Shape** means WatTunnel's own packets change their bytes, sizes or timing (everything else in the table below,
  plus the carriers that wrap the session in a real protocol or in a shaped outer header: TLS, WebSocket, HTTP/2,
  gRPC, DNS, ICMP echo, and the 3.3.0 [shaped carriers](#shaped-carriers-330)).
- Neither is encryption: the session is already encrypted, and none of this adds secrecy.

`hdr-mask`, `shape` and `tcp-mimic` are on by default; every other line in the table is opt-in. Per-feature detail
and field caveats stay in the sections each row links to.

| Option (default) | What it actually changes | What it does not hide |
|---|---|---|
| `fake-sni` (off; Linux + CAP_NET_RAW, dialing side) | **Spoof.** Injects one raw TLS ClientHello carrying an allowlisted SNI next to each outgoing pool connection. A DPI that reassembles flows without checking the TCP window reads it and marks the flow "TLS to an allowed site"; the server's tunnel never processes it (`seq`: the kernel drops it as an old duplicate; `sum`/`rst`: a bad TCP checksum; `ttl`: it dies before the server; the other modes pick one of these mechanisms or a variant). No server change or update. | That a connection exists, where it goes, and how much it carries — the flow is still the tunnel once classified. It also fails behind a NAT that normalizes sequence numbers or validates checksums before the DPI, and against an allowlist enforced by destination IP. Modes and caveats: [Fake-SNI desync](#fake-sni-desync-whitelisting-survival). |
| `tcp-mimic` (on; raw `tcp` pool) | **Shape.** Each connection opens with a 517-byte Chrome-shaped TLS 1.3 ClientHello that carries the authentication in its random and session-id fields; the 2-byte frame lengths are XORed with a per-direction ChaCha20 stream. | It is not a TLS session (there is no ServerHello): it defeats "first bytes are not TLS" and fixed-structure checks, not a classifier that waits for a real handshake. The `tls`, `wss`, `h2` and `grpc` carriers already carry everything inside real TLS/HTTP and do not use it. |
| `hdr-mask` (on) | **Shape.** XORs the 16 header bytes (session id and packet number) with a ChaCha20 keystream keyed from the PSK and seeded by the first 12 bytes of the ciphertext, so no header byte is constant and no counter is in clear. | The payload is already ciphertext; the destination address, the volume and the timing are unchanged. A peer older than 3.0.0 is detected and answered in the plain form. |
| `shape` (on) | **Shape.** Packets that carry no stream data (acks, keepalives, key exchange) and are shorter than 192 bytes get a random-size `frPad` padding frame (up to 100 bytes); the idle keepalive interval is re-rolled to 60-140 % of `ping-every`. | Packets that carry stream data are not padded, so sizes and timing under load are unchanged. It reshapes idle and tail traffic only. |
| `shape-data` (0 = off) | **Shape.** Pads packets that carry stream data to randomized realistic total sizes, bounded by a budget of the configured percent of stream bytes (plus a 4 KB bank); 3.3.0, see [Stream padding and idle noise](#stream-padding-and-idle-noise-330). | Packets already near the MTU are not padded, so bulk traffic is essentially unchanged (under 0.004 % padded bytes in the in-process benchmark). It spends bandwidth: up to the configured percent of stream bytes (0-25 %), counted in the session totals but not in the per-port counters or quotas. |
| `noise` (off) | **Shape.** While the session is idle (about two keepalives with no user data), sends random-size filler packets at 128 B/s (`low`), 1024 B/s (`med`) or a custom byte rate, optionally only inside a local-clock window; never acked, retransmitted or in flight. | Nothing beyond idle traffic: it spends real bandwidth (~11 MB/day on `low`, ~88 MB/day on `med`, per session), counts against the session `max-mbps` ceiling and the session totals, and stops while the tunnel is busy. Per-port counters and quotas stay payload-only. |
| `tls-frag` (0 = off; `tls`, `wss`, `h2`, `grpc`) | **Shape.** Writes the TLS ClientHello as N-byte TCP segments with a short gap between them; `-1` cuts directly inside the SNI extension, so no segment carries the complete `server_name`. | A DPI that reassembles the TCP stream before it classifies still reads the whole hello; it defeats per-segment parsing only, and changes nothing else about the flow. |
| `ech` (off; TLS carriers) | **Shape.** Real Encrypted Client Hello (standard TLS): the SNI is hidden under the destination's ECHConfig, fetched over DoH by IP (or through the tunnel's own DNS relay with `ladder`), so an on-path observer sees only the public outer name. | The destination IP, that a TLS/ECH handshake happened, and volume/timing. It needs a destination that publishes ECH (a Cloudflare-proxied domain) and does nothing on carriers that are not TLS (`ws`, `h2c`, `udp`, `icmp`). |
| `udp-dns` (off; `udp` carrier) | **Shape.** Every datagram is prefixed with a DNS header and one fresh random question (the client looks like a recursive query, the server like an empty NOERROR answer), costing 26-37 bytes. | That this is a sustained UDP conversation to one server: a 1400-byte DNS exchange at tens of MB/s is not ordinary DNS. Both ends must enable it, and it helps only where the filter passes DNS-shaped UDP, normally on port 53. See [DNS-shaped udp](#dns-shaped-udp-udp-dns-300). |
| `pool-rotate` (0 = off; dialing side) | **Shape.** Recycles each healthy pool connection on a jittered budget (±40 % in time, ±25 % in bytes, re-rolled on every recycle), so no single flow shows a stable lifetime; the session resends anything in flight, so the cost is one redial at a time. | Aggregate volume and timing, the destination, and how many connections exist over time. It hides only the lifetime of one connection. |
| `fec` (off) | **Robustness, not camouflage.** Adaptive XOR parity over small packets, so one lost packet in a group is rebuilt instead of waiting for a PTO; k adapts from 4 to 16 with the measured loss, and full-size packets are never covered. | Nothing about identity, size or timing: it is for a lossy path, not for a classifier, and it adds packets (under 5 % in bulk) instead of removing a signal. Both ends must set `fec: auto`. |
| `governor` (off; ICMP) | **Pacing, not camouflage.** Learns the highest rate that did not trigger the path's reroute signature (a base-RTT jump) and holds the delay pacer under it. | Nothing: it hides nothing, it keeps the ICMP volume below a limit that would reroute the path. It is an opt-in experiment, not field-validated. See [ICMP path limits](#icmp-path-limits-and-pacing). |

**How to choose.** Match the option to the check that is killing the flows, not to a general idea of "harder":

| What the censor does | What to try |
|---|---|
| Cuts every flow unless the TLS ClientHello carries an allowlisted SNI | `fake-sni` (default `seq` mode; `rst` where a stateful filter clears the flow — the field result), with the carrier's real `sni` set to the same allowed name and `fp: chrome`. |
| Lets the handshake through, then resets or black-holes by SNI | `ech` (`auto`, or `ladder` when DoH is blocked) on `wss`/`grpc` through a Cloudflare-proxied domain. |
| Drops large ClientHellos (the hello stalls in `Send-Q`) | `tls-small-ch: true` (~250 B instead of ~1.5 KB). |
| Flags "first bytes are not TLS" or a fixed header structure | `tcp-mimic` and `hdr-mask` (both on by default), or move to a real-TLS carrier (`tls`/`wss`). |
| Cuts every UDP flow after a few datagrams, but passes DNS on 53 | `udp-dns: true` on both ends, carrier `udp`, server on port 53. |
| Keeps per-flow state and reclassifies or clears it on RST | `fake-mode: rst` or `synrst`; `pool-rotate` for long-lived flows. |
| Watches connection lifetime or bytes per flow | `pool-rotate` and/or `pool-rotate-bytes`. |
| Reroutes or rate-limits sustained ICMP volume | `governor` plus a total `max-mbps` of about 30 or less per ICMP path; raise `mtu` only after proving the path passes it. |
| Loss (not filtering) hurts small request/response traffic | `fec: auto` on both ends. |
| Allowlists by destination IP only | The real destination must still pass the filter: `fake-mode: fakeip` only names a whitelisted CDN IP in the injected marker, and no shipped option changes where the real flow goes. |
| Classifies by outer IP protocol number, UDP port or first header | One of the 3.3.0 [shaped carriers](#shaped-carriers-330) (both ends 3.3.0, same name; the raw tier needs Linux + CAP_NET_RAW). The shape is a wattun-internal envelope, not interoperability with the real protocol. |

If you do not know which check is killing the tunnel, measure instead of guessing: `wattun matrix NAME` tries the
combinations from the Iran server and applies the best one, and `wattun blackout NAME [SNI]` writes the desync preset
(see [Fake-SNI desync](#fake-sni-desync-whitelisting-survival)).

**What none of them hide.** Whatever combination runs, these stay visible; plan for them instead of around them:

- **The destination and the flow's existence.** The server's address, which side started the connection, and the fact
  that a long-lived, high-volume flow to one foreign address exists (`reverse` only changes which side starts it).
- **Volume and timing under load.** Padding reshapes idle packets (and, since 3.3.0, `shape-data` spreads data-packet
  sizes), but masked headers and fragmented hellos do not change how many bytes move or when. A CDN carrier (Cloudflare)
  changes the visibly contacted peer; the options above do not.
- **The `icmp` carrier's echo structure.** No shipped option changes it: on a route where only ping passes, the tunnel
  looks like ping traffic by construction.
- **The forwarded content between your users and the Iran server.** WatTunnel encrypts the Iran ↔ Kharej leg only.
- **That the payload is not what the envelope implies.** Behind the DNS prefix or the TLS-shaped hello the bytes are
  a WatTunnel session, not a DNS message or a real application's traffic; a classifier that can see past the envelope,
  or blacklists traffic by end-to-end behaviour, still sees a tunnel.

**What is not shipped: tunnel-level spoofing.** There is no option that makes WatTunnel look like another tunnel or
tool end to end. There is no VLESS, Shadowsocks, Trojan, Hysteria or WireGuard mimicry, no faked application session,
and no forged handshake that is completed on purpose: the `fake-sni` ClientHello is designed to be dropped by the peer,
and `tcp-mimic` never completes a TLS handshake. The shipped envelopes (ICMP echo, UDP, TCP, real TLS, WebSocket,
HTTP/2, gRPC, DNS-prefixed UDP, and the 3.3.0 shaped raw/UDP tiers) are shapes around WatTunnel's own encrypted
packets, and the HTTP listeners answer a probe with the stock nginx page rather than a tunnel banner. If a filter's
rule is "only a flow that completes a real session to an allowed site passes", or it blacklists by end-to-end
behaviour, no option here satisfies it: use a CDN path with a real protocol inside, or a tool designed for that
requirement.

## Reverse mode

Normally the Kharej server listens and the Iran client dials out. Some networks only allow outbound connections from
Kharej to Iran, or only inbound to Iran. `reverse: true` swaps who listens and who dials. Nothing else changes: Iran
still opens the streams and listens on the public ports.

Works with the pool carriers (`tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc`), since 2.0.0 with `icmp`, and since
3.0.0 with `udp` (see [Reverse udp](#reverse-udp-300)). Put `reverse: true` on both ends.

| Side | Without `reverse` | With `reverse` (pool carriers) | With `reverse` (`icmp`, 2.0.0) |
|---|---|---|---|
| Iran (client) | dials `peer` | listens on `listen` | answers with ICMP replies to `peer` (Kharej's IP) |
| Kharej (server) | listens on `listen` | dials `peer` | sends ICMP requests; `peer` is Iran's IP |

Anyone who connects to the listening side can only occupy a capped slot. Their packets fail authentication and are
dropped, and since 3.2.1 the merged reverse pool also sends only to source addresses that delivered a packet the
session authenticated (up to eight addresses, FIFO, so a peer whose egress address changes keeps working). A stranger
who never holds the key therefore cannot receive the tunnel's packets or hold its slots.

**With the manager.** For a new tunnel, pick reverse in the Kharej wizard's advanced settings: the token carries it.
To switch an existing tunnel, update both servers first. On **Kharej** run `wattun`, open the tunnel, press `o`
(advanced) and `d` (direction), enter Iran's IP and confirm the restart. On **Iran** use the same keys and confirm.
Then run `wattun test NAME` on Kharej.

### Reverse ICMP

Some Iran IPs get a one-way block: Iran's own pings to Kharej are dropped (`ping KHAREJ` from Iran shows 100 % loss),
but `ping IRAN` from Kharej works. The block often comes and goes from day to day. Normal ICMP mode cannot work then,
because the Iran client sends the requests. With `reverse: true` on both ends the ICMP direction is swapped: Kharej
sends the requests (`echo` type 8, or the request type of `icmp-type`) and Iran answers with replies. Which side opens
the streams and which ports are published do not change.

- Both ends need wattun 2.0.0 or newer with `reverse: true`. A 1.9 peer, or one end without `reverse`, never
  connects: the two ends then listen for the same ICMP type.
- On Kharej, set `peer` to Iran's IP. Kharej sends one empty request per lane every 5 s to it (the knock), so a
  stateful firewall on either end, or on the route, sees Iran's replies as answers to requests it has seen. Without
  `peer` Kharej still answers whatever address authenticates, but nothing is knocked.
- Iran keeps `peer` = Kharej's IP, the address its replies go to.
- Iran must receive pings from Kharej: do not block incoming ICMP there.
- **Kernel copies on Iran.** Linux on Iran also answers every tunnel request with its own full-size reply, so Iran
  uploads everything twice. Measured on the real path: `OutEchoReps` = 2 x `InEchos` in `/proc/net/snmp`. Kharej
  drops the copies (they fail authentication), and since 2.0.1 they no longer count as activity from Iran (before
  that, a dead Iran client's session never went idle on Kharej). To stop the copies, rate-limit the kernel's own
  replies on Iran:

  ```
  # /etc/sysctl.d/90-wattun-reverse.conf
  net.ipv4.icmp_ratemask = 22553   # default 6168 + bit 0 (echo reply) + bit 14 (timestamp reply)
  net.ipv4.icmp_ratelimit = 100    # kernel replies: 10 per second per sender (default 1000 ms)
  ```

  wattun's replies are raw-socket sends and are not limited. Ordinary pings to Iran are still answered. Measured
  after the change: 15.9 – 18.2 MB/s each way. Since 2.1.1 the manager applies this by itself, without a question, when reverse is turned on for an Iran
  tunnel and restores the old values when the last one is gone. `icmp_ratelimit` applies to every type in the
  mask, so destination-unreachable and time-exceeded messages also go from 1 to 10 per second per destination.
  `net.ipv4.icmp_echo_ignore_all=1` also works (the tunnel still receives its packets), but then Iran answers no
  ping at all, which breaks monitoring that pings it.
  **Since 3.0.0 the manager does the same on Kharej** for a normal (not reverse) ICMP tunnel with type `echo` or
  `timestamp`, because there Kharej receives the requests and uploads every tunnel packet twice. This is a behaviour
  change on Kharej: ordinary pings are still answered, but at most 10 per second per sender, and Kharej's
  destination-unreachable and time-exceeded messages are limited the same way. The old values come back when the
  last such tunnel is removed.
- **Don't judge Iran by ping from Kharej under load.** The kernel limit is per sender, and in reverse mode every
  tunnel request comes from Kharej's IP, so a plain `ping` from Kharej competes with the tunnel for that budget and
  loses packets while traffic flows (measured 4/6 and 1/3 received during a speed test). Use `last_rx_age_ms` from
  `/stats` instead (see Metrics).
- In `wattun`: Kharej setup → advanced settings → reverse, or for an existing tunnel Advanced settings →
  `d` on both sides. The token carries the flag (field 8), so a fresh Iran setup picks it up.

### Reverse pool carriers

For `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` and `grpc`. Use it when Iran cannot reach a port on Kharej but Kharej can
open connections to Iran. Iran listens on `listen`, Kharej dials Iran's `IP:port` as `peer`. The session roles do not
change: users still connect to Iran, and traffic still goes to Kharej's `127.0.0.1:PORT`. Put `reverse: true` and the
same `key`, `carrier` and `path` on both ends. Needs a port that Iran's firewall allows in; Kharej needs no open port.

The TLS and HTTP flags swap sides along with the roles:

| Key | Set on | Used for |
|---|---|---|
| `listen` | Iran (listener) | Address to accept Kharej on, e.g. `:8443`. |
| `peer` | Kharej (dialer) | Iran's `IP:port`, the same port as Iran's `listen`. |
| `tls-cert`, `tls-key` | Iran (listener) | Certificate to present. Empty = an in-memory self-signed certificate generated at start. |
| `sni`, `host`, `header` | Kharej (dialer) | TLS server name, Host/authority and extra headers of the outgoing connections. |
| `tls-pin` | Kharej (dialer) | Hex sha256 of Iran's certificate. |
| `conns` | Kharej (dialer) | Number of connections dialed to Iran. |
| `plain` | both | grpc without TLS. |
| `path` | both | URL path. Must match. |

**Certificates.** Without `tls-pin` the dialer (Kharej) does not verify Iran's certificate. This is intended: the
pre-shared key (the ChaCha20-Poly1305 session) already stops an impostor, and TLS only shapes the traffic. For strict
checking, give Iran a real certificate (`tls-cert`, `tls-key`) and set `tls-pin` on Kharej to its sha256 fingerprint
(hex).

Example, `wss`:

```yaml
# Iran: listens, still opens the streams and serves the public ports
mode: client
key-file: /etc/wattun/key
carrier: wss
reverse: true
listen: ":8443"
path: /wat
ports:
  - 443
```

```yaml
# Kharej: dials out to Iran
mode: server
key-file: /etc/wattun/key
carrier: wss
reverse: true
peer: 198.51.100.20:8443
path: /wat
sni: example.com      # optional
conns: 8
ports:
  - 443
```

In `wattun`:

- New tunnel: Kharej setup → advanced settings → reverse. It asks for Iran's IPv4, and the carrier port P you chose
  becomes the port Iran listens on. The token carries the flag, so Iran picks it up when you paste it.
- Existing tunnel: open it → `o` (advanced settings) → `d` (direction), on Kharej first, then on Iran.
- On Iran the manager opens P/tcp in the firewall. Kharej needs no open port.
- Diagnose: on Kharej it tests a TCP connection Kharej → Iran on P. On Iran it checks that P is listening.

**When it does not help.** Reverse only changes who dials. If the route cuts TCP in both directions, it does not
matter who opens the connection. Field result on one real Iran-Kharej path (measured 2026-10-10): reverse `tcp`
stalled after 192 B, reverse `tls` was reset before any data, and a plain TCP socket from Kharej to Iran connected,
received 3528 B and then stalled (3 out of 3 tries). That filter cuts TCP both ways, and only reverse ICMP worked
there. If a plain TCP connection from Kharej to Iran's port already stalls, use reverse `icmp` or the normal `icmp`
instead.

Since 2.1.0 the reverse dialers back off up to 30 s between attempts. They log the first failure, then at most one
failure line every 5 minutes, and a `connected` line when a dial succeeds.

### Reverse udp (3.0.0)

With `carrier: udp` and `reverse: true` the Iran client binds `listen` and **never sends first**. The Kharej server sends
it a small authenticated datagram (a "punch": 8 random bytes, a 12-byte HMAC of them under a key derived from the PSK,
and 0-40 random pad bytes, so no byte is constant) from its own bound socket to `peer` (Iran's `IP:port`), about once a
second. The client answers every datagram to the source address of the latest valid punch, so a NAT or a firewall sees
a flow that Kharej started and Iran only answers, and the punches keep its state alive. Datagrams from any other
address are dropped, and the session still authenticates everything. Since 3.0.0 Kharej skips the punch while it has
heard the client within the last two punch intervals, so a busy tunnel sends no extra datagrams.

| Side | Config |
|---|---|
| Iran (client) | `reverse: true`, `listen: ":4443"` (open `4443/udp`), `peer` is not used |
| Kharej (server) | `reverse: true`, `listen: ":4443"` (the source port of the punches and of every reply), `peer: "IRAN_IP:4443"` |

Both ends need 3.0.0. An older peer cannot answer or send a punch, so the link stays down; set the same on both sides
or leave both in the normal direction. The manager does this in the wizard and under Advanced settings, direction (`d`),
with the right `udp` firewall rule.

### DNS-shaped udp (`udp-dns`, 3.0.0)

Some routes cut every UDP flow after its first datagrams, whatever the port and payload, and pass only traffic that
looks like an allowed protocol. Measured on a fresh Iran/Kharej pair (2026-10-25): from Iran, the first 3 datagrams of any
UDP flow pass and the rest are dropped, except UDP to **port 53** whose payload starts like a DNS message. That flow
passes sustained, at full datagram size, in both directions. A tunnel on port 4443 with the same framing is cut; the
filter looks at the port as well as the bytes.

`udp-dns: true` (both ends, carrier `udp`) starts every datagram with a DNS header and one question, and the session
packet follows as if it were the rest of the message. Client datagrams look like recursive queries (flags `0x0100`),
server datagrams like empty NOERROR answers (`0x8180`). The id and the queried name (a random 5 to 14 character label
plus `com`, `net`, `org`, `ir`, `info` or `io`, type A or AAAA) are fresh for every datagram; the cost is 26 to 37
bytes. It composes with `hdr-mask` and `shape`, with `sessions`, `fec`, bonding and `reverse`.

```yaml
# Kharej                                   # Iran
mode: server                               mode: client
carrier: udp                               carrier: udp
udp-dns: true                              udp-dns: true
listen: "KHAREJ_IP:53"                     peer: "KHAREJ_IP:53"
```

Bind the server to its own address, not `:53`: `systemd-resolved` holds `127.0.0.53:53`, and a wildcard bind would
fail. Nothing else on the server may listen on UDP 53. The manager offers it in the Kharej wizard for `udp` (the token
carries `dns` in its path field; the Iran wizard then writes `udp-dns: true`). Unattended: `wattun-manager kharej --carrier udp --udp-dns --name NAME --yes`. Both ends must enable it: a plain peer
cannot read the frame and a framed peer never connects to it. Measured on the pair above (one run, 1 vCPU each, 82 ms):
21 MB/s down, 19 MB/s up; with `sessions: 4`, 32 and 24; a 400 MB transfer held 36 and 29 with no cut. This is
what a DNS-only whitelist lets through; it does not hide that a very busy UDP 53 flow is not ordinary DNS.

### Carrier matrix

| Carrier | Direct | Reverse | Minimum version (both ends) |
|---|---|---|---|
| `icmp` | yes | yes | direct: any; reverse: 2.0.0 |
| `udp` | yes | yes | direct: any; reverse: 3.0.0 |
| `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc` | yes | yes | direct: 1.3.0; reverse: 1.8.0 |
| `gre`, `ipip` | yes | no | 3.2.0 (Linux + root) |
| shaped raw tier (`sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3`) | yes | no | 3.3.0 (Linux + root) |
| shaped UDP tier (`fou-gre`, `gue-ipip`, `vxlan`, `geneve`, `dnscrypt-udp`, `ntp-direct`, `openvpn-dco`, `srtp-direct`) | yes | no | 3.3.0 |

The reverse pool carriers are in the first release of this repository's history (1.8.0). An earlier release may
have had them too; this table says 1.8.0 because that is the oldest one that can be checked. The `gre`/`ipip` and
shaped carriers are direct only: the server answers the source address a session authenticated from.

## Auto mode

The manager only (`wattun`, no engine flag). It needs `wattun` 2.1.0 on Kharej and `systemd-run`. It finds the carrier that
works on a route by testing all of them, so the operator does not have to guess.

**Kharej.** In the new-tunnel wizard the first carrier option is `auto`. It asks for an optional Cloudflare-proxied
domain, used only to test the CDN carriers through Cloudflare. It creates one bonded server tunnel `NAME` that listens
on every carrier, and prints one token.

| Carrier | Listen port |
|---|---|
| `udp`, `tcp` | 4443 |
| `tls` | 8443 |
| `ws` | 2052 |
| `wss` | 2053 |
| `h2` | 2087 |
| `h2c` | 2082 |
| `grpc` | 2083 |
| `icmp`, `gre`, `ipip` | none |

A port that is already taken moves to a free fallback; the real ports are in the token. `gre`/`ipip` arrived in
3.2.0 and are raw-IP carriers with no listen port; the plan carries them as bare names.

**Token.** `wat1:` + base64 of `carrier|peer|key|path|sni|icmp-type|allowed-ports|reverse|plan`. Field 9 (`plan`) looks
like `d=udp:4443,tcp:4443,...,gre,ipip;r=tcp:24431,tls:24432,ws:24433,wss:24434,h2:24435,h2c:24436,grpc:24437`.
`d` is the Kharej listen port per carrier; a raw-IP carrier with no listen port (`icmp`, `gre`, `ipip`, and the raw
shaped carriers) is a bare name in the list. `r` is the port Iran listens on for each reverse test. Tokens with 7 or 8
fields (older managers, non-auto tunnels) still work. An extended token appends `;e=1`, which older managers and
`plan_part` ignore.

**Reverse side.** A transient unit `wattun-autowatch-NAME` (`systemd-run`, 1 hour at most) polls the Kharej tunnel's
`/stats` `clients` list. When Iran's first test client connects, it learns Iran's IP and writes and starts a companion
tunnel `NAME-r`: a reverse server with reverse ICMP and reverse dials to Iran's `r` ports. With a CDN domain set, the IP
is taken only from `icmp`, `udp`, `tcp` and `tls` clients, because CDN clients show the proxy's IP. Manual fallback on
Kharej: `wattun auto-ip NAME IRAN_IP`. `NAME-r` appears on the dashboard as the reverse side of `NAME`, follows
its ports and key, and is deleted with it.

**Iran test.** Pasting an auto token runs the test (re-run later with `wattun auto-test NAME`). Phases: direct,
then CDN (if a domain was given), then reverse. Each variant is a throw-away client that runs its own `/speedtest`
(screening: an 8 MB probe each way with 8 streams, grown to 16 MB when the measured rate would move it in under
1.5 s). Since 2.1.1 the reverse variants are started all at once and get up to 45 s to
connect (Kharej's reverse dialer backoff made most of them fail with "no link in 8 s" before). Nothing is published;
temp files are in `/run/wattun-auto`. Reverse test ports are opened in the
firewall only during their probe. Since 2.1.1 the manager opens ufw/firewalld ports without a confirm, Kharej does not
ask which ports Iran may reach (all are allowed; restrict later in the port editor), and Iran enables auto-heal by
itself (off: `wattun` → `s` → `h`). The table is ranked by download plus upload (ties: lower RTT) and accepts Enter (best), `b` (bond the working carriers), `1`-`N`
(one variant) and `q`. The normal wizard continues at port mapping. The token is saved in `/etc/wattun/NAME.auto`.

**Test presets (3.0.2).** Before the test starts the manager asks what to test. *Normal* (Enter) is the test above, without anti-censor
variants; its worst-case traffic and a rough time are printed before it starts (see "Bandwidth of the test"). *Anti-censor* (`a`) adds, for every direct pool carrier of the plan (tcp, tls, wss, h2, grpc, ws, h2c): all fake-SNI
modes (`rst synrst paws seq seqsum sum ttl split hlen0 fakeip ff all auto`) with the first curated SNI, `rst`/`synrst`/`paws` against the other
curated SNIs and `www.cloudflare.com`, and on the TLS carriers `tls-frag` -1 and 40, the chrome/firefox/safari fingerprints and chrome+ECH when a CDN
domain is set (about 195 variants for a full plan, 30-60 minutes). Reverse tunnels have no anti-censor variants here: the desync runs on the dialing
side, which is Kharej for a reverse tunnel. During the test `s` skips the running variant, `g` (anti-censor preset) skips the rest of that carrier's
anti-censor variants and `q` stops the test; the table then ranks what was measured and the usual choice (Enter, `1`-`N`, `c`, `f`, `q`) follows.
An anti-censor variant has to beat the plain type by 8 % to rank above it, cannot be joined into a bond, and is written with its `fake-sni`,
`fake-mode`, `fp`, `ech` and `tls-frag` lines. Unattended runs (`wattun iran --token ... --yes`, `auto-test NAME --yes`) use `--test normal|anti`
(default normal); `auto-retest` and auto-heal always run normal.

**Auto-heal.** After two failed restart cycles on an auto tunnel, `wattun-manager heal` starts a re-test (a normal
screening run, at most once per 30 minutes). It switches to another working variant only when the current one fails,
and logs `wattun-heal: switched NAME from X to Y`.

**Test methodology (3.3.0).** Measurement is duration-based, not a fixed size, so slow start cannot decide the winner.
Screening runs a throw-away client per variant with 8 streams: the probe starts at 8 MB each way and moves to 16 MB
(the cap) when the measured rate would finish it in under 1.5 s. The top 3 are then measured again with 16 streams
and a sustained run sized to at least 1.5 s each way at their screening rate, clamped to 20-40 MB each way. A
finalist that fails the longer run keeps its screening numbers. The table is ranked by download plus upload.

**Extended transports (3.3.0, opt-in).** The Kharej wizard asks once whether to also test the 13 shaped carriers
(unattended `--extended`); the question and the flag are offered only when the local engine is 3.3.0. Because the
engine refuses a shaped leg inside the auto bond, extended creates one hidden single-carrier server unit per shape
(`NAME-e-<shape>`, shared `NAME.key`, own metrics port; `listen` only for the eight UDP shapes, conventional port or a
free fallback recorded in the plan; the five raw shapes have no listen/peer) and appends the shapes to the plan. Iran
tests them like any other direct variant (a bare peer for the raw tier, `addr:port` for the UDP tier) and can pick one;
an extended plan needs 3.3.0 on **both** ends, and the raw tier needs Linux + root/CAP_NET_RAW plus the cloud firewall
allowing protocols 41/50/97/115. Anti-censor still adds variants only for the direct pool carriers (the shapes have no
desync layer); there are no reverse or count-based tuning variants for them. The extended listeners are hidden from the
tunnel list but follow the parent's life: heal restarts a down one, delete/uninstall remove them, the default
reverse-side prune keeps the shape Iran picked and stops the rest, and `auto-widen` / `auto-prune NAME --direct`
re-enable them for a retest (a normal Auto test can also re-test them). An older Iran ignores their plan entries; their
Kharej ports then stay open until that prune/manual close — that trade is why extended is opt-in.

**Auto tuning (3.3.0).** After the type (or the bond) is chosen, the manager tries the settings that change its speed,
one setting at a time, starting from the engine auto values and keeping a value only when it beats the best so far by
more than 10 % (one run is noisy). Probes are fixed at 20 MB each way, and the grid is reduced to the two knobs with
field evidence:

| What is tuned | Values tried |
|---|---|
| `icmp` | nothing (a raw-IP carrier has no `sessions`/`conns` to tune) |
| `udp` | `sessions` 1/2/4 |
| `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc` | `sessions` 1/2/4/8/16, `conns` 4/8/32/64 |
| reverse | `conns` 4/8/32 |
| bond (datagram or pool legs) | `conns` 4/8/32/64 |

`sessions` is never tuned on a bond or a reverse tunnel (the engine refuses it there), and `max-mbps`/`fec` are not
tuned (`icmp` keeps its 16 MB/s reroute guard, and `fec: auto` must match on Kharej). `mtu`, `win-max`, `batch` and
`loss-ceiling` are no longer probed: their effect on the test pair sat inside the run-to-run noise. A value given on
the command line (`--sessions`, `--conns`, `--mtu`) or in a preset wins over the tuner. The manager reports the
traffic the tuning moved afterwards: 20 MB each way per probe, so up to about 400 MB for the widest (pool) grid,
160 MB for `udp` or a reverse tunnel and 200 MB for a bond. The unattended re-test by auto-heal does not tune.

**Bandwidth of the test.** The Iran test moves real data, and the printed budget now counts all three phases. Screening
starts at 8 MB each way per variant and grows to 16 MB when the rate calls for it, so a normal plan (17 variants: 9
direct + 8 reverse; 19 with a CDN domain) has a worst case of 544 MB (17 × 2 × 16). The 3 finalists add up to 240 MB
(3 × 2 × 40), and tuning adds up to 400 MB (10 probes, baseline included, × 2 × 20 MB). The manager prints that total
before an interactive test: `Budget: up to 1184 MB, about 3 min` for a normal plan (1248 MB with a CDN domain); the
minutes assume a conservative 8 MB/s aggregate, so a fast link finishes sooner and a slow route later, while the MB
figure is the exact cap. A variant that does not connect sends almost nothing, so on a filtered route where few
carriers connect expect far less. The anti-censor preset moves more because it tries about 195 variants. An extended
token adds up to 13 shaped-carrier variants to the screening phase (about 416 MB extra worst case at 16 MB each way);
the printed variant count and budget include them, and an Iran that cannot run them skips them before counting. Re-tests by
auto-heal or the off-peak optimizer run the screening phase (8-16 MB each way per connecting variant; up to 544 MB for
a normal plan if every variant connects); auto-heal runs one at most every 30 minutes and only after the tunnel
failed. If your server is billed by traffic, pick a fixed carrier instead of Auto.

**After Iran has picked.** The Kharej auto tunnel is the real server for the carrier Iran chose, so it is never
deleted. It keeps every carrier port open so that Iran's test and auto-heal can reach any of them — which is attack
surface once Iran has picked. Since 3.3.0 the heal pass closes what is provably unused by itself, and the default
scope is deliberately the **reverse side only**: it stops the stale `wattun-autowatch` helper and, once Iran's pick
has been stable for `autoprune` minutes (`.manager.conf`, default 12, `0` = off), stops `NAME-r` when no reverse
carrier is alive or narrows `NAME-r` to the reverse carriers that are. The direct `carrier:` list is **not** rewritten
by default, because the engine reports one carrier per session and cannot tell a bonded Iran client from a single
leg. Full direct-side narrowing stays available but is opt-in: `.manager.conf autoprune-direct=1`, or
`wattun-manager auto-prune NAME --direct` (the old `auto-narrow`, both sides). A changed pick restarts the window, so
a flapping selection is never pruned. Configs and tokens always stay, and `auto-widen` brings everything back. Hidden
extended listeners follow the same rule: the default pass keeps the shape Iran picked and stops the unused ones;
`auto-widen` / `auto-prune --direct` re-enable them.

The pass runs inside `heal`. The manager installs the heal timer where it is needed: the auto Kharej wizard and
`auto-ip` install it, and any later manager run does the same for an existing auto Kharej tunnel, so a Kharej-only
server is cleaned up without operator action. `wattun-manager heal` triggers one pass by hand.

**Widen safety net (3.3.0).** A pruned tunnel keeps only the carriers Iran used, so if that carrier is blocked there
is nothing left to fail over to. When the heal pass sees a pruned auto tunnel with no working open carrier for 3
consecutive checks, it reopens the full token plan (`auto-widen`) and logs
`wattun-auto: ... reopening the whole plan`. It does so at most once per `autowiden` minutes (`.manager.conf`, default
10; `0` disables the automatic widen), and a reopen starts a fresh stable-selection window, so the tunnel narrows again
after a new stable pick. Manual control is always available: `wattun-manager auto-narrow NAME` closes every unused
carrier now (both sides); `wattun-manager auto-prune NAME --keep-open` opts one tunnel out of both automatic passes (every carrier stays
open), `--auto` turns them back on, `--direct` opts into direct-side narrowing and `--reverse-only` returns to the
default; `wattun-manager auto-widen NAME` opens every carrier of the token's plan again.
`auto-narrow` reads which carriers have a live Iran session (`/stats` `clients` on `NAME`, alive `carriers` on
`NAME-r`). The tunnel card shows "Iran uses ..." and how many carriers are still open.

**Costs and limits.** Several ports are open on Kharej at once until the default reverse-side cleanup (or a manual
`auto-narrow`) closes them. An interactive test prints its worst-case traffic and a rough time before it starts.
Kharej must be
2.1.0 or newer (the `clients` field and the reverse dial backoff). The wire format did not change, so 2.1.0 peers work
with 2.0.x ones for normal tunnels.

## CDN tuning

**Setup.** Use this on routes where only HTTPS to a CDN gets out, or where the filter looks at the SNI.

1. Put a domain on Cloudflare with the proxy on (orange cloud) and SSL mode **Full**. For `grpc`, also turn on gRPC
   in Cloudflare's Network settings, if your plan shows that switch.
2. In the Kharej wizard, choose `wss` (or `grpc`) and enter the domain.
   - `h2` does not work through Cloudflare.
   - Plain `ws` on HTTP ports can hang at the upgrade.
   - Always use the domain, not the server's IP. With the IP, the tunnel skips Cloudflare and works only where
     that IP is reachable. The manager warns about this.
3. On Iran, the manager finds the ECH config by itself and scans Cloudflare edge IPs for ones that work for your
   domain. It then tests the Chrome fingerprint, ECH, plain TLS and ClientHello fragmentation, and writes the
   winner to the config.
4. Use several `sessions` (default 4) to fill the pipe. Re-tune any time with `wattun cdn-tune NAME`. Auto-heal
   replaces dead edges.

Since 2.2.0, client (Iran) side only. Kharej and the wire format are unchanged, so any 2.x Kharej works.

**Why.** Field findings from a real Iran server (October 2026): the filter lets the TLS handshake through and then
black-holes the flow by the SNI of the user's own domain. The edges DNS returns for the Cloudflare zone were
degraded while other edges (for example 162.159.140.220) worked. Domain fronting (another SNI, your Host) gets a 403
from Cloudflare. Plain `ws` on HTTP ports through Cloudflare hung at the Upgrade. So the tuning picks edges and
TLS behaviour, and does not rely on fronting.

**Client keys.**

- `peer: A,B,C` accepts several comma-separated addresses for the pool carriers. Slots spread over them, and a dead
  address fails over at once. `/stats` shows them in `edges`.
- `fp` sets the ClientHello fingerprint (utls). `ech: auto` hides the domain with Encrypted Client Hello and falls
  back to no ECH if the record is missing. `tls-frag: N` splits the ClientHello.
- ALPN: `ws` and `wss` force `http/1.1`; `h2` and `grpc` require `h2`.

**What the manager does.** When Iran sets up a CDN tunnel (`wss`, `h2`, `grpc`, `ws`, `h2c` through a Cloudflare
domain) it runs, without questions:

1. Scan about 22 Cloudflare edge IPs, with the domain's own A records first. One test client dials all the candidate
   edges with a real ECH connection to the domain, and an edge counts only if that connection works. This replaces the
   old curl probe and the `speed.cloudflare.com` ranking, because an edge serving `speed.cloudflare.com` can still fail
   for the zone. IPv6 edges are tried only when the server has an IPv6 route.
2. Keep the best 3 as `peer`.
3. Speed-test, in this order: Chrome fingerprint with ECH first (the test stops early when it works), then the other
   variants (plain, fragmentation) only if it does not. Through Cloudflare only `wss` and `grpc` are tested.
4. Write the winner (`fp`, `ech`, `tls-frag`, `peer`) into the config and restart.

In Auto mode this is part of the CDN phase; the table labels look like `wss · chrome · 3 edges`.
`wattun cdn-tune NAME [full]` repeats the tuning at any time. Auto-heal refreshes dead edges.

**DoH behaviour (2.2.1).** `ech: auto` looks up the domain's HTTPS record by racing all four DoH servers (1.1.1.1,
1.0.0.1, 8.8.8.8, 9.9.9.9) and takes the first answer; from Iran 1.1.1.1 was blocked while 8.8.8.8 worked. The lookup
happens before the dial. If DoH fails, the last good config is kept, and after a rejection the config is refreshed in
the background.

### ECH bootstrap ladder (2.9.0, `ech: ladder`)

When EVERY direct DoH server is unreachable (a full DoH IP block, not just one), `ech: ladder` adds a second
rung, modelled on the speed test's reserved target port: a stream whose 2-byte target header is 53 goes to the
server's built-in DNS relay instead of a local service. The client writes one raw DNS query (length-prefixed),
the relay forwards it as one UDP exchange to a recursive resolver on the Kharej side and writes the answer back.
The ladder in full: direct DoH (the raced public servers) → the tunnel relay → no ECH, retry in 30 s. So a
`wss`+ECH tunnel bootstraps on a route where only the tunnel itself passes and DNS is hijacked.

- Both ends need 2.9.0. An old server treats target 53 as a local dial to `127.0.0.1:53`, which fails and
  resets the stream; the ladder falls back to no ECH exactly as before — the tunnel still comes up.
- The relay answers one query per stream, bounded at 4096-byte queries (RFC 6891 EDNS0 maximum) and 6 s per
  exchange; a query is no more
  sensitive than the tunnel's own handshake. Only the client's `ech: ladder` ever opens port 53; normal
  forwarding is untouched.
- `ech-cache` still applies: a config from before the DoH block is used at once while the ladder refreshes.

**Field result (v2.2.0, real Iran server through Cloudflare).** Only ECH got through; every non-ECH variant failed.
With ECH: `wss` 8.0 MB/s down and 7.5 MB/s up, `grpc` 6.7 MB/s down and 9.9 MB/s up.

**Cloudflare settings.** Use `wss` or `grpc` on a Cloudflare HTTPS port (443, 2053, 2083, 2087, 2096, 8443),
SSL mode Full, ECH on, and enable gRPC in the Cloudflare Network settings for `grpc`. `h2` does not work through
Cloudflare: it speaks HTTP/1.1 to the origin except for gRPC. Avoid plain `ws` on HTTP ports.

**Troubleshooting.**

| Symptom | Cause and fix |
|---|---|
| Connects, then stalls with no data | SNI black-holing. Set `ech: auto`, or try `fp: chrome` and `tls-frag`. Run `wattun cdn-tune NAME full`. |
| Connects, then stalls on tcp/tls with `fake-sni` | Your ISP's NAT normalizes sequence numbers before the DPI, or the allowlisted SNI is not allowed on your ISP. Drop `fake-sni`, use `tls` with `sni` + `tls-frag`/ECH. |
| All edges fail the scan | The domain is blocked even over ECH, or the zone has no ECH. Check `ech` and `tls_mode` in `/stats` and that the domain's HTTPS record exists. |
| `ech: false` although `ech: auto` is set | The domain has no HTTPS DNS record (the zone is not on Cloudflare's ECH), or all four DoH servers are blocked and no earlier config was cached. The tunnel runs without ECH. |
| `h2` never works through Cloudflare | Expected: Cloudflare speaks HTTP/1.1 to the origin except for gRPC. Use `wss` or `grpc`. |
| `grpc` never connects | gRPC is off in Cloudflare Network settings. |
| `ws` hangs at the Upgrade | Plain ws on an HTTP port. Move to `wss` on an HTTPS port. |
| 403 from Cloudflare | A fronted SNI/Host mismatch. Keep `sni` and `host` the same domain. |
| One entry in `edges` has `up: false` | That edge is dead. Auto-heal replaces it, or run `wattun cdn-tune NAME`. |
| Works from some Iran servers or networks, fails on others | `peer` is the Kharej server's own IP, so the tunnel never goes through Cloudflare. It works only where that IP is reachable. Proxy a domain to Kharej (orange cloud), enter the domain as the Kharej address, or run `wattun cdn-tune NAME` to write Cloudflare edges into `peer`. Also check that `sni`/`host` is spelled exactly like the domain. |
| `-fake-sni` connects but the filter still kills the flow | The ISP's NAT validates sequence numbers/checksums before the DPI (seq mode), or normalizes TTL (ttl mode). Try the other `fake-mode`, another allowlisted SNI, or fall back to ICMP / CDN routes. See [Fake-SNI desync](#fake-sni-desync-whitelisting-survival). |
| TLS carrier works on short probes but the tunnel never comes up, and `ss` shows the ClientHello stuck in `Send-Q` | The DPI drops large ClientHellos. Set `tls-small-ch: true` (2.10.4): it drops the post-quantum key share and shrinks the hello from ~1.5 KB to ~250 B. |

**Direct-IP warning (manager).** The `wss`, `grpc` and `h2` carriers dial `peer` and send `sni` as the TLS name, so
with `peer` set to the origin's IP the connection goes straight to Kharej, not through Cloudflare, even when `sni`
is the domain. When an Iran tunnel on one of those carriers is created with a bare IPv4 `peer` (not reverse, not set
up through CDN tuning), the manager warns before creating it and suggests the domain or `cdn-tune`.

## UDP forwarding

Since 1.2.0 WatTunnel also forwards UDP ports (WireGuard, DNS, QUIC, game servers) as unreliable datagrams inside the
same session. Datagrams are not retransmitted and are dropped when a queue is full. That is correct for UDP.

- Config: add `N/udp` to the `ports:` list on both ends. A plain `N` (or `N/tcp`) is TCP.
- Flag: `-udp PORT` or `-udp listenPort:serverPort[@bind][,...]` on the client.
- The server only forwards to UDP ports that are listed as `/udp`. A TCP-only list allows no UDP.
- Idle flows are closed after `udp-idle` (default 60 s).
- Both ends need wattun 1.2.0 or newer.
- Big datagrams (2.5.0): a datagram larger than one tunnel packet (about 1350 bytes on udp, 590 on the default
  icmp) is sent in up to 64 pieces and rebuilt on the other end, so WireGuard's default MTU 1420 works. Both ends
  need 2.5.0; with an older end such datagrams are dropped (`dgram_dropped_size`): set `MTU = 1280` in WireGuard on
  udp or icmp `mtu: 1400`, or about 550 on the default icmp. Losing one piece loses the datagram, so on a lossy path
  a smaller WireGuard MTU still does better.

```yaml
ports:
  - 443          # tcp
  - 51820/udp    # udp
```

## Config file

`-config /etc/wattun/NAME.yml` supplies flags. It is a small YAML subset:

- `key: value` per line. The keys are the flag names.
- `#` starts a comment. Values may be in "double" or 'single' quotes.
- Two lists, `ports:` and `limits:`, both hot-reloaded. `ports:` items are `- PORT`, `- PORT/udp`, `- LISTEN:TARGET`
  or `- LISTEN:TARGET/udp`; `limits:` items are `- TARGET rate=MBPS quota=SIZE` (see "Per-port traffic and limits").
- Unknown keys, duplicate keys and bad values stop the start with a line number. Only `header` may repeat.
- Command-line flags win over the file.
- The `ports:` list is **hot-reloaded** every 3 seconds. On the client it opens and closes listeners. On the server it
  replaces the allowlist. A file that fails to parse is ignored and the old state stays. Changing any other key logs
  `restart needed for KEY`.
- With a `ports:` key on the server, the file replaces `allow-ports` and `allow-file`.

On the client, a plain `N` in `ports:` means: listen on `bind:(N + port-offset)` and forward to server port N. Since
1.9.0 an item `LISTEN:TARGET` listens on `LISTEN` and forwards to server port `TARGET`. Both are 1-65535 and may be
followed by `/tcp` or `/udp`. A listen port may appear only once per protocol. Changing only the target of a listen port
in the file closes and reopens that listener (connections already open keep running).

```yaml
# Iran (client)
ports:
  - 443         # listen 443 -> server 443
  - 8443:443    # listen 8443 -> server 443
  - 5353:53/udp # listen udp 5353 -> server udp 53
```

The server allowlist is the **target** ports, so Kharej's list contains `443` and `53/udp` for the example above (not
`8443` or `5353`). `-map` and `-udp listenPort:serverPort` on the command line behave as before.

### Keys

| Key | Default | Side | Meaning |
|---|---|---|---|
| `mode` | (required) | both | `client` or `server`. |
| `key` | | both | Pre-shared key. Prefer `key-file`. |
| `key-file` | | both | File with the key (whitespace trimmed). Same on both ends. |
| `carrier` | `icmp` | both | One of the carriers above (including the 3.3.0 [shaped carriers](#shaped-carriers-330)), or several joined with `+` (see Bonding). A shaped carrier must be alone: a `+` list that contains one stops startup. |
| `peer-NAME`, `listen-NAME` | = `peer`, `listen` | client / server | Bonded carriers only: per-carrier address (`peer-udp`, `listen-tcp`, ...). A shaped raw-tier carrier has no `listen-NAME`. |
| `peer` | | client (server with `reverse`) | icmp, udp: server IP. Pool carriers: `host:port`. Shaped raw tier: the server's bare IP (`sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3`). Shaped UDP tier: `host[:port]`, a bare host using the protocol's conventional port. Reverse pool carriers: Kharej sets Iran's `IP:port`. Reverse icmp: Kharej sets Iran's IP, Iran keeps Kharej's. |
| `listen` | `:4443` | server (client with `reverse`) | Address for non-ICMP carriers. With `reverse` Iran listens here and Kharej's `peer` must point to it. A shaped UDP-tier carrier defaults to the protocol's conventional port instead of `:4443`; the shaped raw tier has no `listen`. |
| `reverse` | false | both | Swap who listens and who dials. With `icmp` (2.0.0): Kharej sends the requests, Iran replies. With `udp` (3.0.0): Iran binds `listen` and only answers, Kharej punches to `peer`. Not supported on the 3.3.0 shaped carriers (or `gre`/`ipip`). |
| `hdr-mask` | true | both | Mask the session id and packet number at the start of every packet (3.0.0). An older peer is detected and answered plain; `false` sends the plain header. |
| `tcp-mimic` | true | both | tcp carrier: open each connection with a TLS ClientHello-shaped hello (SNI `fake-sni`) that carries the auth, and mask the 2-byte lengths (3.0.0). An older peer is detected after 6 s and answered with the plain pool id; `false` sends the plain id. |
| `udp-dns` | false | both | udp carrier: start every datagram with a DNS header and question (3.0.0), for routes that pass only DNS-looking UDP on port 53. Both ends must set it. Ignored on a shaped carrier (the shape owns the datagram prefix). See "DNS-shaped udp". |
| `shape` | true | both | Pad small packets (acks, keepalives, key exchange) to random sizes and jitter the keepalive interval (3.0.0). Compatible with older peers. |
| `shape-data` | 0 (off) | both (3.3.0) | Pad packets that carry stream data to randomized realistic sizes, spending at most this percent (0-25) of the stream bytes sent (plus a 4 KB bank). Spends real bandwidth; ignored on bonded carriers. See "Stream padding and idle noise". |
| `noise` | off | both (3.3.0) | Idle filler traffic, **per session**: `off`, `low` (128 B/s, ~11 MB/day), `med` (1024 B/s, ~88 MB/day) or `custom` with `noise-bps`. Sent only while the session has no user data for about two keepalives, jittered, never acked. `-sessions 2` doubles it; each Kharej client's session sends its own. See "Stream padding and idle noise". |
| `noise-bps` | 0 | both (3.3.0) | Byte budget in bytes/second for `noise: custom`, 64-1,000,000; an error with any other `noise` mode. |
| `noise-window` | empty (all day) | both (3.3.0) | `HH:MM-HH:MM` local clock, may cross midnight (for example `02:00-06:00`); noise is sent only inside it. Ignored (with a warning) when `noise` is off. |
| `ports` | | both | List of `N`, `N/udp`, `LISTEN:TARGET` and `LISTEN:TARGET/udp`. Client listens on LISTEN, server allows TARGET. Hot-reloaded. |
| `bind` | `0.0.0.0` | client | Address of the public listeners. |
| `src-ip` | | client | Outbound source IP address for carriers (per-carrier `src-ip-NAME` in a bond). Pin it when the host has several public addresses and the routing table picks one the customers do not use. See [Traffic shape](#traffic-shape-what-a-dpi-sees-300). |
| `port-offset` | 0 | client | Added to every listen port. Used by the second slot of a handover. |
| `lanes` | 4 | client | ICMP identifiers to stripe over. |
| `conns` | 0 (auto) | client (server with `reverse`) | Connections in a pool carrier. 0 picks 8 on a lean host, 16 on a standard one, 24-32 on a high-performance one (3.1.0, see "3.1.0: host-aware defaults"); older versions used 8. The engine caps a pool at 64 connections (the manager refuses larger values); with `reverse`, Kharej dials this many to Iran. |
| `pool-rotate` | 0 (off) | client, or the dialing server of a `reverse` tunnel since 3.0.2 (pool carriers: tcp, tls, ws, wss, h2, grpc) | Recycle each healthy pool connection after this long (`30m`, `4h`), so no single flow shows a months-stable lifetime; each connection's actual budget is jittered ±40 % and re-rolled on every recycle, so redials never line up into a detectable period. The session resends anything in flight, so the cost is one redial on one connection at a time. 0 = off. Since 2.8.0. |
| `pool-rotate-bytes` | 0 (off) | client, or the dialing server of a `reverse` tunnel since 3.0.2 (pool carriers: tcp, tls, ws, wss, h2, grpc) | With or instead of `pool-rotate`: also recycle each healthy pool connection after this many bytes handed to its socket (`500MB`, `4G`, `300k`; decimal units, 1 MB = 10^6). Jittered +/-25 % like the time axis; whichever limit hits first recycles, so the byte axis does not betray the time axis's jitter. 0 = off. Since 2.8.1. |
| `mtu` | 0 (carrier default) | both | Datagram size cap, including header and tag. 256-1400 for icmp, udp, gre and ipip; up to 16384 for the pool carriers; a bond uses the smallest bound of its legs. |
| `win-max` | 0 (auto) | both | Cap of the receive window per stream in MB, 4 to 64 (3.0.3). Windows are receiver-driven, so the value bounds what the peer's sender buffers per stream. 0 uses the host tier (4 MB lean, 16 standard, 32 high-performance); the fixed cap before 3.0.3 was 16 MB. |
| `mem-budget` | 0 (eighth of RAM) | both | MB of stream buffers (send data and grown receive windows) the whole process may hold before every stream shrinks to small buffers (3.2.0). See [3.2.0](#320-fast-by-default-bounded-memory-greipip). |
| `max-mbps` | 0 (carrier default) | both | Pacing ceiling, MB/s per direction, per session. 0 = 16 when `icmp` is among the carriers, 1250 (10 Gbit, i.e. no practical cap) for udp, tcp, tls, ws, wss, h2, h2c and grpc since 2.4.18 (200 from 2.3.0; before that 16 for every carrier; the server's value caps the download). See "ICMP path limits and pacing". |
| `tcp-cc` | `bbr` | both | Since 2.4.18, Linux. TCP congestion control set on every pool socket (tcp, tls, ws, wss, h2, h2c, grpc). BBR does not back off on random loss; the kernel default (cubic) halves its window on every lost segment. `system` keeps the kernel default. Each end sets it for what it sends. `tcp_cc` in `/stats` shows what the kernel accepted (falls back to the default if the `tcp_bbr` module is missing). |
| `sessions` | 0 (auto) | client | Independent sessions to the server, 1 to 16 (2.3.0, client only; the server is unchanged). 0 picks 1 on a lean host and 2-4 on a host with 2+ CPUs and enough RAM (3.1.0), and always 1 for `icmp`, bonds and `reverse`; older versions used 1. See "Several sessions". |
| `icmp-type` | `echo` | both | ICMP carrier: `echo` or `timestamp` (Linux does not answer `info`/`mask`). Both ends must match. |
| `loss-ceiling` | false | both | Opt-in loss-aware ceiling for the pacer (see "ICMP path limits and pacing"). Off = delay only. |
| `slack-ms` | 8 | both | RTT growth tolerated before slowing down. |
| `hedge` | false | both | Send small young packets twice. Helps lossy tails, costs packets. |
| `fec` | off | both | `off` or `auto`: adaptive XOR parity for small transfers (see FEC). Needs 1.7.0 and `auto` on both ends. Since 3.3.0 parity is also loss-gated: it is sent only while the sender's measured loss is above `fec-on-loss`. |
| `fec-on-loss` | 2 (percent) | both (3.3.0) | `fec: auto` only: start sending parity once the sender's measured loss is above this percent (0.01 = 1 %, at most 50; must be above `fec-off-loss`). Local policy, no wire change. |
| `fec-off-loss` | 0.5 (percent) | both (3.3.0) | `fec: auto` only: stop sending parity once the measured loss falls below this percent (0 = once open it never closes; must be below `fec-on-loss`). See "FEC". |
| `allow-min`, `allow-max` | 1, 65535 | server | Range of target ports clients may ask for. |
| `allow-ports` | | server | Comma list of allowed target ports. |
| `allow-file` | | server | File with allowed ports, re-read when it changes. Overrides `allow-ports`. |
| `allow-clients` | empty (every source) | server (3.3.0) | Restricts holders of the PSK/token to these source addresses: comma/space separated IPv4/IPv6 addresses or CIDR prefixes that may open a session; any other source is dropped before admission (an unauthenticated source could not admit anyway). Admission only — an established session is never re-checked, so a NAT/roaming client keeps working. Only a carrier that reports the client's own IP can be filtered (direct icmp/udp/tcp/tls/gre/ipip and a bond of them): a CDN carrier (`ws`, `wss`, `h2`, `h2c`, `grpc`) or `sni` makes the combination a startup error, and with `reverse` the list is ignored with a warning. A source the carrier cannot attribute to an IP fails closed. The deny log is rate-limited over the whole server (3 lines/s, burst 3) with the suppressed count reported. See "Client allowlist". |
| `allow-clients-file` | | server (3.3.0) | File with the `allow-clients` list (comma/space/newline separated), read once at startup; replaces `-allow-clients`. Must be under `/etc/wattun` (the unit runs with `ProtectHome=yes`, so a list under `/root` or `/home` would not be readable): any other path is a startup error. An empty file is a startup error, never "allow every source". |
| `udp` | | client | UDP forwards, `PORT` or `listenPort:serverPort[@bind]`. |
| `udp-idle` | 60s | both | Close UDP flows idle this long. |
| `tls-cert`, `tls-key` | in-memory self-signed | server (client with `reverse`) | Certificate files for tls, wss, h2 and grpc, on whichever side listens. |
| `sni` | | client (server with `reverse`) | Server name in the TLS ClientHello, set on whichever side dials. |
| `tls-pin` | | client (server with `reverse`) | Hex sha256 of the listener's certificate. Also makes the dialing side check it. Without it the dialer does not verify the certificate. |
| `path` | `/wat` | both | URL path for ws, wss, h2, h2c, grpc (grpc: service name). Same on both ends, also with `reverse`. The manager picks a random `/api/...` path for each new tunnel (3.0.1); the program default stays `/wat`. |
| `host` | = `peer` | client (server with `reverse`) | Host header / authority, set on whichever side dials. |
| `plain` | false | both (dialer with `reverse`) | grpc without TLS. |
| `header` | | client (server with `reverse`) | Extra request header `Name: value`. Repeatable. |
| `fp` | `go` | client (server with `reverse`) | TLS ClientHello fingerprint (utls): `go`, `chrome`, `firefox`, `safari`, `edge` or `random`. Since 2.2.0. |
| `ech` | `off` | client (server with `reverse`) | Encrypted Client Hello, hides the SNI: `off`, `auto`, `ladder` or a base64 ECHConfigList. `auto` fetches the domain's HTTPS DNS record over DoH, by IP (1.1.1.1, 1.0.0.1, 8.8.8.8, 9.9.9.9), and falls back to no ECH. `ladder` (2.9.0) adds the through-the-tunnel DNS relay as the second rung when every direct DoH server fails (both ends 2.9.0). Since 2.2.0. |
| `ech-cache` | empty (off) | client, with `ech: auto` | File that keeps the last good ECHConfigList (`name base64` per line, written atomically, 0600). On start it is used at once while DoH refreshes in the background; cache errors are logged once and never stop the tunnel. Since 2.2.3. |
| `tls-frag` | 0 | client (server with `reverse`) | Split the ClientHello into pieces of N bytes. 0 = off. Since 2.2.0. |
| `tls-small-ch` | false | client | Keep the TLS ClientHello small: drop the post-quantum hybrid key share (Go 1.24+ offers `X25519MLKEM768` by default) and offer `X25519` + `P-256` only, so the hello is ~250 B instead of ~1.5 KB. Some DPIs silently drop large hellos — measured live on an Iranian path 2026-10-22, where 1474 B hellos never left `Send-Q` while 250–512 B hellos passed every time and the tunnel then came up with `srtt` 88 ms. The session's own ChaCha20-Poly1305 layer is unaffected. Since 2.10.4; also applies under `fp: chrome\|edge` (the browser presets' post-quantum share is removed too: a Chrome hello goes from ~1.8 KB to ~560 B) since 2.10.8. |
| `fake-sni` | empty (off) | client, or server with `reverse` (2.10.12) | Fake-SNI desync, tcp, tls, wss, h2 and grpc carriers: after each connection's TCP handshake the client injects a raw TLS ClientHello carrying this allowlisted SNI. The DPI classifies the flow as TLS to the allowed site; the server never receives it (wrong sequence number, a TTL that expires at the filtering hop, or a bad checksum), so the session flows on as if it were that TLS connection. Needs Linux + CAP_NET_RAW on the client, like the icmp carrier. Works over IPv4 and IPv6 peers (IPv6 since 2.10.9: the sniffer reads IPv6 frames and the markers go out through a raw `AF_INET6` socket; an IPv6 peer with extension headers before TCP is not tracked). Server unchanged. Since 2.6.0. |
| `fake-mode` | `seq` | client, with `fake-sni` | `seq`: the marker carries a sequence number below the stream start, the server drops it as an old duplicate. `ttl`: the marker carries a small TTL and expires at the filtering hop (needs `fake-ttl`). `sum` (2.7.1): the marker mirrors the first data segment in-window with a damaged TCP checksum; the server kernel drops it, DPIs that ignore checksums still read it — the mode for filters that check sequence numbers. `seqsum` (2.8.0, experimental): both the seq and the sum marker per connection, ~1 ms apart. `split` (2.10.5): the fake hello cut across `fake-split` TCP segments, so a per-packet SNI parser never sees the whole name. `hlen0` (2.10.5): F&F-style empty TLS record (length 0) that makes a stateful parser latch and stop reading the flow. `paws` (3.0.2): an in-window fake with a valid checksum and a stale TCP timestamp, dropped by the server kernel (PAWS); see [3.0.2](#302-probing-resistance-and-the-paws-marker). `fakeip` (2.10.5): a checksum-valid SYN + hello addressed to `fake-ip` (a CDN edge), for filters that allowlist by destination IP. `synrst` (2.10.5): in-window SYN\|RST with a damaged checksum, clears flow tables harder than `rst`. `all` (2.10.5): seq + sum + hlen0 markers ~1 ms apart. `ff` (2.10.6): the Irancell F&F record plan for the fake hello — a zero-length TLS record, then a 104-byte record, then 1-byte records around the SNI, cut across `fake-split` (default 11) below-window segments; the shape the field reports connecting at full speed on Irancell. `rst` (2.9.0): the marker is an in-window RST\|ACK with a damaged TCP checksum — a stateful middlebox clears the flow, the server's kernel drops the packet before it reads the flags. Since 2.6.0. |
| `fake-ip` | `104.16.0.1` (IPv4 peer) / `2606:4700::6810:1` (IPv6 peer) | client, `fake-mode: fakeip` | Destination of the injected fake SYN+hello, IPv4 or IPv6. A destination-IP allowlist then files the flow as CDN traffic. It has to be of the same family as the connection (`peer`); a mismatched one is replaced by that family's default. IPv6 since 2.10.9. Since 2.10.5. |
| `fake-split` | 0 (3) | client, `fake-mode: split` | How many TCP segments the fake ClientHello is cut into (2..16), so no single packet carries the SNI. Since 2.10.5. |
| `fake-ttl` | 0 | client, `fake-mode: ttl` | Hop count of the marker packet: one more than the distance to the filtering DPI box, one less than the distance to the server. Read it off a traceroute to the server. 0 also means auto since 2.7.0: the client learns the peer's inbound TTL from its SYN-ACKs, infers the path length from it (initial TTL 32/64/128/255 minus the arrival TTL) and sends the marker one hop short of the server (2.7.0-2.10.7 used the arrival TTL minus one, which still reached the server; fixed in 2.10.8). Unused by `seq` and `sum`. Since 2.6.0. |
| `batch` | empty (carrier default) | icmp, udp | recvmmsg/sendmmsg batching (`on`/`off`). Same switch as `WAT_BATCH`, which this overrides. |
| `bond-mode` | `balanced` | both | Bonded carriers: `balanced`, `active-backup` or `replicate`. |
| `path-probe-max` | 0 (30s) | client | Bonded carriers: maximum probe backoff for dead paths (blackout mode uses 6s). |
| `keep-slow` | empty (carrier default) | pool carriers | `on`/`off`: never close a pool connection for delivering below its share (default on for reverse and direct tcp/tls, off for CDN HTTP carriers). |
| `governor` | false | both | ICMP paths: learn the path's volume ceiling from the reroute signature and hold the rate under it. Opt-in experiment, not field-validated. |
| `ping-every` | 2 | both | Idle keepalive interval, seconds (0-60). Raise it on paths that rate-limit periodic packets; the liveness and server idle limits scale with it. |
| `dns-listen` | empty (off) | client | Local address for the DNS relay used by `ech: ladder` (e.g. `127.0.0.1:53`). |
| `dns-relay-upstream` | `8.8.8.8:53` | server | Resolver used by the built-in DNS relay behind target port 53 (with `ech: ladder`). |
| `metrics` | off | both | Serve `/stats` and pprof on this address. Always loopback (see Metrics). |
| `state-dir` | empty (next to the config) | both, needs `-config` (3.3.0) | Directory that holds the quota-usage and lifetime-totals files (`<config>.quota.json`, `<config>.totals.json`). Created 0700 when missing; the file names keep the config's base name, so one directory can hold several tunnels. Point it at tmpfs (`/run/wattun`) to spare the disk: the shipped unit creates that directory and keeps it across a service restart, but the counters are still lost on reboot. See "State files". |
| `state-save` | 30 | both (3.3.0) | Seconds between state-file saves (quota usage and lifetime totals); `0` = only on shutdown. The save itself is atomic (tmp + rename), as before. |
| `debug` | false | both | Log every stream open and close. |

### Example: ICMP (the production setup)

```yaml
# /etc/wattun/iran.yml   (Kharej: mode: server, no peer/bind/lanes)
mode: client
key-file: /etc/wattun/key
peer: 203.0.113.10
lanes: 4
max-mbps: 16
metrics: 127.0.0.1:19702
ports:
  - 443
  - 2053
  - 51820/udp
```

### Example: TCP pool

```yaml
# Iran: /etc/wattun/iran.yml
mode: client
key-file: /etc/wattun/key
carrier: tcp
peer: 203.0.113.10:4443
conns: 8
ports:
  - 443
```

```yaml
# Kharej: /etc/wattun/kharej.yml
mode: server
key-file: /etc/wattun/key
carrier: tcp
listen: ":4443"
ports:
  - 443
```

### Example: WebSocket behind Cloudflare

Cloudflare terminates TLS and forwards to Kharej over plain WebSocket on a port it supports (for example 8080).

```yaml
# Iran
mode: client
key-file: /etc/wattun/key
carrier: wss
peer: tunnel.example.com:443
sni: tunnel.example.com
host: tunnel.example.com
path: /api/v2/stream
conns: 8
ports:
  - 443
```

```yaml
# Kharej (origin behind Cloudflare, orange cloud on)
mode: server
key-file: /etc/wattun/key
carrier: ws
listen: ":8080"
path: /api/v2/stream
ports:
  - 443
```

Use a path that looks like a normal API route. Any other path gets a plain 404.

### Example: reverse

Kharej cannot be reached from Iran, but can reach Iran.

```yaml
# Iran: listens, still opens the streams and serves the public ports
mode: client
key-file: /etc/wattun/key
carrier: tcp
reverse: true
listen: ":4443"
ports:
  - 443
```

```yaml
# Kharej: dials out to Iran
mode: server
key-file: /etc/wattun/key
carrier: tcp
reverse: true
peer: 198.51.100.20:4443
ports:
  - 443
```

## Command-line flags

Every flag can also be a config key. Flags win over the file.

| Flag | Default | Meaning |
|---|---|---|
| `-mode client\|server` | | Role. |
| `-key SECRET`, `-key-file FILE` | | Pre-shared key. |
| `-config FILE` | | Config file (above). |
| `-carrier NAME` | `icmp` | Transport, or `a+b+c` to bond several. Also the 3.3.0 [shaped carriers](#shaped-carriers-330) (Linux + root for the raw tier; both ends 3.3.0 and the same name; single carrier only, a `+` list that contains one stops startup); `fortress` is the manager alias `icmp+tcp+tls+wss+udp` (80/443/8443/53). |
| `-peer-NAME ADDR`, `-listen-NAME ADDR` | | Bonded carriers: per-carrier peer / listen address (no `-listen-NAME` for the shaped raw tier). |
| `-peer ADDR` | | Server IP (icmp, udp, shaped raw tier) or `host:port` (pool and shaped UDP tier; a shaped UDP-tier bare host uses the protocol's conventional port). |
| `-listen ADDR` | `:4443` | Listen address of non-ICMP carriers; a shaped UDP-tier carrier defaults to its protocol's conventional port instead. |
| `-reverse` | off | Swap dial and listen (pool carriers), or which side sends the ICMP requests (`icmp`, 2.0.0). Rejected for `gre`, `ipip` and the shaped carriers. |
| `-bond-mode MODE` | `balanced` | Bonded carriers: `balanced`, `active-backup` or `replicate`. |
| `-path-probe-max D` | 0 (30s) | Client, bonded carriers: maximum probe backoff for dead paths (default 30s; blackout mode 6s). |
| `-map l:s[,...]` | | Client: listen port to server port. `l:s@127.0.0.1` keeps a port private. |
| `-udp SPEC` | | Client: UDP forwards. |
| `-udp-idle D` | `60s` | UDP flow idle timeout. |
| `-bind ADDR` | `0.0.0.0` | Client listen address. |
| `-src-ip ADDR` | | Client: outbound source IP address for carriers (per-carrier `-src-ip-NAME` in a bond). |
| `-port-offset N` | 0 | Added to every client listen port. |
| `-lanes N` | 4 | ICMP identifiers. |
| `-conns N` | 0 (auto) | Pool connections. |
| `-pool-rotate D` | `0` (off) | Client, pool carriers: recycle a healthy connection after this long (`30m`, `4h`, seconds), jittered ±40%; 0 = off (2.8.0; a `reverse` server that dials honours it since 3.0.2). |
| `-pool-rotate-bytes N` | `0` (off) | With or instead of `-pool-rotate`: also recycle after this many bytes (`500MB`, `4GB`, `300k`), jittered ±25%; 0 = off (2.8.1; `reverse` server since 3.0.2). |
| `-mtu N` | 0 | Datagram cap. |
| `-win-max N` | 0 (auto) | Both ends: cap the per-stream receive window in MB, 4-64 (0 = host tier: 4, 16 or 32-64) (3.0.3). |
| `-mem-budget N` | 0 (eighth of RAM) | MB of stream buffers (send data and grown receive windows) the whole process may hold before every stream shrinks to small buffers (3.2.0; see "3.2.0: fast by default, bounded memory, gre/ipip"). |
| `-max-mbps F` | 0 | Pace ceiling per direction and session; 0 = 16 with icmp, 1250 otherwise (2.4.18; 200 from 2.3.0). |
| `-tcp-cc NAME` | `bbr` | Pool sockets' TCP congestion control, Linux (2.4.18). `system` keeps the kernel default. |
| `-batch on\|off` | empty | sendmmsg batching for icmp and udp; empty keeps the default (on for icmp, off for udp). Same switch as `WAT_BATCH`, but kept in the config (3.0.0). |
| `-keep-slow on\|off` | empty | Pool carriers: `on` never retires a connection for delivering below its share, `off` always checks; empty = on for reverse and direct tcp/tls, off for the HTTP carriers (3.0.0). |
| `-hdr-mask` | true | Mask the packet header (3.0.0). |
| `-udp-dns` | false | udp carrier: DNS-shaped datagrams, for port 53 (3.0.0). Ignored on a shaped carrier. |
| `-tcp-mimic` | true | tcp carrier: ClientHello-shaped hello and masked frame lengths (3.0.0). |
| `-shape` | true | Pad small packets and jitter the keepalive (3.0.0). |
| `-shape-data PCT` | 0 (off) | Both ends (3.3.0): pad data-carrying packets to randomized realistic sizes, spending at most PCT (0-25) percent of the stream bytes sent; ignored on bonded carriers. See "Stream padding and idle noise". |
| `-noise MODE` | `off` | Both ends (3.3.0): idle filler traffic, per session: `off`, `low` (128 B/s, ~11 MB/day), `med` (1024 B/s, ~88 MB/day) or `custom` with `-noise-bps`. `-sessions` and Kharej's client count multiply it. |
| `-noise-bps N` | 0 | Both ends (3.3.0): filler budget in bytes/second for `-noise custom`, 64-1,000,000. |
| `-noise-window HH:MM-HH:MM` | empty (all day) | Both ends (3.3.0): local-clock window for noise, may cross midnight; requires `-noise` (ignored with a warning otherwise). |
| `-ping-every N` | 2 | Idle keepalive interval, seconds, 0-60; both ends use their own value, and liveness scales with it. |
| `-sessions N` | 0 (auto) | Client: N independent sessions, udp and the pool carriers only (2.3.0, server unchanged). Rejected for the raw and shaped carriers. |
| `-dns-listen ADDR` | empty | Client: listen here for DNS queries and forward them through the tunnel's DNS relay, e.g. `127.0.0.1:53` (2.9.0). |
| `-dns-relay-upstream ADDR` | `8.8.8.8:53` | Kharej: resolver the internal DNS relay queries (port 53, `-ech ladder`); empty = `8.8.8.8:53`. |
| `-icmp-type T` | `echo` | ICMP carrier: `echo`, `timestamp` (both ends the same; Linux does not answer `info`/`mask`). |
| `-loss-ceiling` | off | Pacer: also cut the rate when loss jumps far above its learned baseline (opt-in). |
| `-governor` | off | Pacer, ICMP paths: learn the path's volume ceiling from the reroute signature (a sudden base-RTT jump after sustained bulk) and hold the rate under it (opt-in, 2.9.0; see ICMP path limits). |
| `-slack-ms N` | 8 | Tolerated RTT growth. |
| `-hedge` | off | Duplicate small young packets. |
| `-fec auto` | off | Adaptive FEC, both ends; since 3.3.0 parity is sent only while the measured loss is above `-fec-on-loss` (see FEC). |
| `-fec-on-loss P` | 2 | `fec: auto`: start parity above this loss percentage (0.01 = 1 %, at most 50, above `-fec-off-loss`) (3.3.0). |
| `-fec-off-loss P` | 0.5 | `fec: auto`: stop parity below this loss percentage (0 = never close the gate, below `-fec-on-loss`) (3.3.0). |
| `-allow-min`, `-allow-max` | 1, 65535 | Server: target port range. |
| `-allow-ports LIST` | | Server: allowed target ports. |
| `-allow-file FILE` | | Server: allowed ports file, hot-reloaded. |
| `-allow-clients LIST` | empty (every source) | Server (3.3.0): restricts holders of the PSK/token to these IPv4/IPv6 addresses or CIDR prefixes, comma/space separated; every other source is dropped before admission. Admission only, direct carriers only: a CDN carrier or `-sni` is a startup error (the source would be the edge), and `-reverse` ignores it with a warning. The deny log is throttled to 3 lines/s over the whole server. See "Client allowlist". |
| `-allow-clients-file FILE` | empty | Server (3.3.0): file with the `-allow-clients` list, read once at startup; replaces `-allow-clients`. Must be under `/etc/wattun` (the unit's `ProtectHome=yes` hides `/root` and `/home`); any other path is a startup error. An empty file is a startup error. |
| `-tls-cert`, `-tls-key` | | Server: certificate files. |
| `-sni`, `-tls-pin` | | Client: TLS name, certificate fingerprint. |
| `-path`, `-host`, `-header`, `-plain` | `/wat` | HTTP carrier options. |
| `-fp NAME` | `go` | Dialer: TLS fingerprint `go`, `chrome`, `firefox`, `safari`, `edge`, `random` (2.2.0). |
| `-ech MODE` | `off` | Dialer: `off`, `auto`, `ladder` or a base64 ECHConfigList (2.2.0; `ladder` 2.9.0, see ECH bootstrap ladder). |
| `-ech-cache FILE` | empty | Dialer, with `-ech auto`/`ladder`: ECH config cache file (2.2.3). |
| `-tls-frag N` | 0 | Dialer: split the ClientHello into N-byte pieces (2.2.0). |
| `-tls-small-ch` | false | Client, tls/wss/h2/grpc: keep the ClientHello small by skipping the post-quantum key share (~250 B instead of ~1.5 KB) (2.10.4). |
| `-fake-sni SNI` | empty (off) | Client (or a `reverse` server): inject a fake TLS ClientHello carrying this allowlisted SNI after each outgoing TCP handshake (Linux raw socket + CAP_NET_RAW). See "Fake-SNI desync". Since 2.6.0. |
| `-fake-mode MODE` | `seq` | Marker for `-fake-sni`: `seq`, `ttl`, `sum`, `seqsum`, `split`, `hlen0`, `fakeip`, `synrst`, `all`, `ff`, `rst`, `paws` or `auto`. See "Fake-SNI desync". |
| `-fake-ip ADDR` | empty (family default) | `-fake-mode fakeip`: destination of the fake SYN + hello (empty = `104.16.0.1` for an IPv4 peer, `2606:4700::6810:1` for IPv6). |
| `-fake-split N` | 0 (3) | `-fake-mode split` (and `ff`): TCP segments the fake ClientHello is cut into, 2-16; 0 = 3 for `split`, `ff` uses 11. |
| `-fake-ttl N` | 0 (auto) | `-fake-mode ttl`: marker hop count; 0 calibrates from the server's replies. Unused by `seq`, `sum` and `seqsum`. |
| `-state-dir DIR` | empty (next to the config) | Both ends, needs `-config` (3.3.0): move the quota/totals state files into DIR (created 0700). The shipped unit creates `/run/wattun` (`RuntimeDirectory=wattun`) and keeps it across a service restart; tmpfs still loses the counters on reboot. See "State files". |
| `-state-save SECONDS` | 30 | Both ends (3.3.0): seconds between state-file saves; 0 = only on shutdown. |
| `-metrics ADDR` | off | Serve `/stats` and pprof. |
| `-debug` | off | Log every stream. |
| `-version` | | Print `wattun X.Y.Z` and exit. |

Signals: `SIGTERM` or `SIGINT` stops. On a server, `SIGUSR1` starts a drain (below).

### Client allowlist (`-allow-clients`, 3.3.0)

By default any source that can reach the server's carrier port may try to open a session; the PSK is the only gate.
On the direct carriers the server also knows the client's source IP, so `-allow-clients` / `-allow-clients-file` can
restrict admission. It **restricts holders of the PSK/token to the listed source IPs** — it is a brake on a leaked
token, not a scanner filter: a source without the key could never create a session anyway.

- **Format.** IPv4/IPv6 addresses or CIDR prefixes, separated by comma, space, tab or newline. A bare address is
  kept as its /32 or /128 and prefixes are masked, so `10.1.2.3/8` matches `10.0.0.0/8`. `-allow-clients-file` is
  read once at startup and replaces `-allow-clients` (no hot reload). It must live under `/etc/wattun`: the systemd
  unit runs with `ProtectHome=yes`, so a list at `/root/clients.txt` would pass a config check and then fail to read;
  any other path is a startup error. An empty file, or a list with no valid entries, stops the start instead of
  silently allowing every source.
- **Admission only.** The check runs before a session is admitted, on the packet that would create it. Established
  sessions are never re-checked, so a NAT/roaming client keeps working; a valid packet from a non-allowed source
  cannot create a session either.
- **Fail closed.** A source the carrier cannot attribute to an IP fails the check (for example a custom RawIO
  that reports no address at all).
- **Carriers.** It works where the carrier reports the client's own IP: `icmp`, `udp`, `tcp`, `tls`, the raw-IP
  `gre`/`ipip`, and a bond of them. Behind a CDN (`ws`, `wss`, `h2`, `h2c`, `grpc`) the source is the proxy edge, so
  the combination is a **startup error** (as is `-allow-clients` with `-sni`): every real client would be rejected.
  With `reverse` the server dials the client, so there is no client source to compare: the list is ignored with a
  warning.
- **Log.** A rejected source produces at most one line per 10 s, with the packets dropped since the previous line
  (`client 203.0.113.7 is not in -allow-clients: 42 packet(s) dropped`). The whole deny log is also capped at 3
  lines/s (burst 3) over the server, and the next line reports how many were suppressed by that throttle. The
  bookkeeping table is bounded (256 sources), so an address spray is dropped silently once it is full instead of
  filling memory or the log.
- **Client side.** Passing the flag to a client run is a startup error ("server option"). The server must run 3.3.0
  or newer to read the keys; old and new peers still interoperate.

## FEC

`fec: auto` (flag `-fec auto`, default `off`) cuts the tail latency of small request/response traffic on a lossy
path. After a burst of small packets, or every k of them, the sender emits one XOR parity packet over their
plaintext; if exactly one of them was lost the receiver rebuilds it, processes and acks it, so the sender does not
wait for a PTO (about 1.25 RTT) or for later acks. k adapts from 4 to 16 with the observed loss (more loss, smaller
k). Full-size packets are never covered and nothing is sent while the session is cwnd-limited, so bulk transfers pay
under 5 % extra packets. Both ends must run 1.7.0 with `fec: auto` for it to help: a peer with FEC off ignores the
parity packet, and an older peer stops parsing at the unknown frame, which sits alone in its packet.

**Loss gate (3.3.0).** On the target path the random loss is 0.2-2 %, and parity on a healthy link was pure
overhead. Since 3.3.0 the sender keeps a running loss estimate and sends parity only while it is above
`-fec-on-loss` (percentage, default 2); it stops once the loss falls below `-fec-off-loss` (default 0.5). The band
between the two plus a 2 s dwell keeps an estimate sitting on a threshold from flapping parity on and off. This is
local policy: the frame and its layout are unchanged, an older peer still reads the parity, and a peer without FEC
still ignores it. A closed gate also means the send path copies nothing for FEC (`fec_state` in `/stats`).
Values are validated at startup: `0 <= off < on <= 50`, otherwise the process refuses to start.

**Receiver side (3.3.0).** The receiver keeps the plaintext of small packets for reconstruction only while parity is
actually arriving, and stops 15 s after the last parity packet. A peer whose gate is closed sends none, so a healthy
tunnel does no FEC work in either direction. The cost is one group that cannot be rebuilt when parity resumes: the
packets before the first parity packet of the new burst were not kept. With FEC off the receive ring does not exist
at all.

Counters: `fec_sent`, `fec_recovered`, and `fec_state` (`on` while this end sends parity, `off` when FEC is off or
the gate is closed; with several sessions or clients, `on` while any of them has it open).

## Per-port traffic and limits

Both ends count traffic per port (client: the public port users connect to; server: the target port) and expose it
live in `/stats` under `ports` and on a cheap `/ports` endpoint (needs `-metrics`). Counters are cumulative since
process start. Since 2.5.0 the `*_total` and `conns_all_time` fields also keep counting across restarts: they are
saved to `<config>.totals.json` every 30 s and on shutdown (with `-config` only). Since 3.1.1 that file is bound to the
machine that wrote it (`<config>.totals.json.host`): a config copied to another server starts its counters from zero
instead of showing the previous server's traffic. `wattun-manager reset-traffic NAME` zeroes them in place (stops the
tunnel, deletes the file, starts it again).

```json
{"20001": {"bytes_up": 0, "bytes_down": 0, "bytes_up_total": 0, "bytes_down_total": 0,
  "conns_total": 0, "conns_all_time": 0, "conns_active": 0, "udp_flows_active": 0,
  "dgram_up": 0, "dgram_down": 0, "errors": 0, "refused": 0,
  "rate_bps_up": 0, "rate_bps_down": 0, "peak_bps_up": 0, "peak_bps_down": 0,
  "rate_limit_bps": 0, "quota_limit": 0, "quota_used": 0, "quota_exceeded": false}}
```

`up` is client to server payload. Rates are bytes/s over the last 1 s, peaks the best 1 s window. A UDP flow counts as
a connection. `refused` counts connections or datagrams turned away by a quota or rate limit.

Limits go in the config file (hot-reloaded every 3 s, like `ports:`), one item per port, sizes in decimal units
(`300k`, `5MB`, `1.5GB`):

```yaml
limits:
  - 20001 rate=5MB quota=100GB
  - 20002 rate=500k
```

- `rate`: bytes/s, applied to each direction separately and shared by all connections of the port (TCP is paced, UDP
  datagrams over the rate are dropped). No limit set means zero overhead.
- `quota`: total up+down bytes. Once used up, new connections are closed at once and existing ones are cut. Usage is
  saved to `<config>.quota.json` every 30 s and on shutdown, so a restart does not reset it. Removing the `quota=`
  item lifts the cut-off.
- Put limits in the file of the side that should enforce them (normally the client in Iran).
- Reset: `curl -X POST 'http://127.0.0.1:19700/quota/reset?port=20001'` (loopback callers only).

### State files (3.3.0)

Quota usage (`<config>.quota.json`) and the lifetime totals (`<config>.totals.json`) are the state files the engine
keeps on disk. Both are written atomically (tmp file + rename) so a reader never sees a torn file.

- `state-save SECONDS` (default 30) sets the period; `0` saves only on shutdown, and the shutdown save stays either
  way.
- `state-dir DIR` moves the pair into DIR instead of next to the config. The directory is created mode 0700 when
  missing, and an unusable one (a regular file, a read-only or full tmpfs) fails startup: a quota-capped port must
  not silently reopen on every restart because its usage was never saved. The file names keep the config's base name,
  so one directory can hold several tunnels' state.
- Typical use: point it at tmpfs (`/run/wattun`) so a busy tunnel's periodic rewrite does not wear the disk. That is
  the supported tmpfs path under the shipped unit: `install.sh` writes `RuntimeDirectory=wattun`,
  `RuntimeDirectoryMode=0700`, `RuntimeDirectoryPreserve=yes` and `ReadWritePaths=/etc/wattun /run/wattun`, so the
  directory exists and is writable inside the `ProtectSystem=strict` sandbox. The trade-off is explicit: tmpfs loses
  the counters on reboot, so quota usage and lifetime totals start from zero. They do survive a service restart
  (`RuntimeDirectoryPreserve=yes` keeps `/run/wattun`); before 3.3.0's fix the documented path made the unit
  crash-loop. The totals file is machine-bound anyway (3.1.1), so a reboot is the same "fresh machine" behavior as
  copying a config to another server.
- The default (no `state-dir`) is the 2.5.0-3.2.x location next to the config, so every existing tunnel keeps working
  without a change.
- The manager follows `state-dir`: its Advanced page edits `state-dir` and `state-save`, and `reset-traffic`, delete
  and uninstall remove or reset the files where the engine actually keeps them (a custom directory outside
  `/etc/wattun` included).
- Needs `-config`: the state files are named after the config, so a flags-only run keeps no state (as before).

## Metrics

With `metrics: 127.0.0.1:PORT`, `GET /stats` returns JSON. `/debug/pprof/` is on the same address. Keep it on
localhost.

Since 2.0.2 the metrics address is always loopback: a non-loopback value (`0.0.0.0:19700`, a public IP, a bare
`:19700`) is rewritten to `127.0.0.1` with the same port, and a log line says so, because `/stats`, pprof and
`/speedtest` must never be reachable from outside. The server also never forwards a tunnel stream to its own
metrics port, even if the port is in the allowlist.

| Field | Meaning |
|---|---|
| `version` | The wattun version string (for example `2.0.2`). |
| `carriers` | Only with bonded carriers (`carrier: a+b`): one entry per carrier with `name`, `alive`, `srtt_ms`, `share` (fraction of traffic), `sent`, `acked`, `lost`. |
| `ports` | Per-port counters (same data as `/ports`). |
| `alive` | Server: at least one client session and an authenticated packet from a client in the last 10 s (3.0.1; before, a session whose connections were all dead still counted until it closed, 45 s after its last packet). Client: an authenticated packet from the server arrived in the last 10 s (each side pings at least every 2 s, so an idle link stays alive); with `sessions` > 1, on any session. |
| `last_rx_age_ms` | Since 2.0.1. Milliseconds since the last authenticated packet from the peer (server: from any client, including sessions that have closed). `-1` = none since the process started. Monitors should use this rather than ping: it only moves on real tunnel packets. |
| `clients` | Since 2.1.0, servers only. One entry per live client session: `[{"ip":"203.0.113.5","carrier":"tcp","age_ms":1234}]`. Behind a CDN carrier (`ws`, `wss`, `h2`, `h2c`, `grpc`) `ip` is the proxy's address. Auto mode uses it to learn Iran's IP. |
| `tls_fp` | Since 2.2.0, pool carriers. The TLS fingerprint in use (`go`, `chrome`, ...). |
| `tls_mode` | Since 2.2.0. Fingerprint plus ECH state, for example `chrome+ech`, `go`. |
| `ech` | Since 2.2.0. `true` when Encrypted Client Hello is active on the dialed connections. |
| `edges` | Since 2.2.0, when `peer` lists several addresses: `[{"addr":"162.159.140.220:443","up":true}]`, one entry per address. |
| `sessions` | Server: client sessions. Client: the configured `-sessions` (1 before 2.3.0). |
| `sessions_up` | Since 2.3.0, clients. Sessions that are alive. |
| `session_list` | Since 2.3.0, clients with `sessions` > 1: one entry per session, `[{"alive":true,"srtt_ms":41.2,"rate_bps":2.4e7,"streams":3}]`. |
| `draining` | Server: not accepting new sessions. |
| `streams` | Open TCP streams. The drain timer waits for 0. |
| `srtt_ms`, `min_rtt_ms` | Smoothed and minimum round-trip time. |
| `rtt_ms` | Flat aggregate alias of `srtt_ms`, same value: `carriers` and `session_list` also contain `srtt_ms`, so a plain grep of the JSON would otherwise pick a per-carrier or per-session value. |
| `streams_total` | Flat aggregate alias of `streams`, same value, for the same reason: `session_list` entries also carry `streams`. |
| `rate_bps` | Current send rate in bytes per second. |
| `ceiling_bps` | Loss-aware soft ceiling in bytes per second (0 = none active). |
| `loss_pct` | Loss in the last judged 50 ms interval, percent (0 until 50 packets were sent in one). |
| `inflight` | Unacknowledged bytes. |
| `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in` | Totals since the process started. |
| `bytes_out_total`, `bytes_in_total` | Since 2.5.0. Wire bytes across restarts (saved in `<config>.totals.json`); the manager shows these. Since 3.1.1 the file is bound to the writing machine, so a config copied to another server starts from zero (`wattun-manager reset-traffic NAME` zeroes it in place). |
| `dgram_fragmented`, `dgram_reassembled` | Since 2.5.0. UDP datagrams too big for one packet that were sent in pieces / rebuilt from pieces (needs 2.5.0 on both ends; an older peer drops the pieces). |
| `retrans` | Retransmitted packets. |
| `fec_sent`, `fec_recovered` | FEC parity packets sent; packets rebuilt from parity. |
| `fec_state` | Since 3.3.0. `on` while this end is sending parity (its loss gate is open, see [FEC](#fec)), `off` when FEC is off or the gate is closed. With several sessions (client) or clients (server), `on` while any one of them has it open. |
| `shape_data_bytes` | Since 3.3.0. Plaintext bytes added by `shape-data` padding (frame header + filler). |
| `noise_sent`, `noise_bytes` | Since 3.3.0. Idle-noise packets sent and their wire bytes, from `noise`. Noise also increases `pkts_out`/`bytes_out` and the lifetime totals; the per-port counters, rate limits and quotas stay payload-only. |
| `send_errors` | Carrier send failures. |
| `ack_late` | Since 2.4.18, reliable carriers. Received packets that only a late ACK reported (they arrived below the newest 64 ranges, see [Direct pools (2.4.18)](#direct-pools-2418)). |
| `dup_recv`, `rx_too_old` | Since 2.4.18. Packets dropped on receive as already seen, and as older than the replay window (131072 packets on reliable carriers). `rx_too_old` above 0 means data was lost and resent. |
| `dgram_sent`, `dgram_recv` | UDP datagrams. |
| `dgram_dropped_queue`, `dgram_dropped_size`, `dgram_dropped_rx` | UDP drops: queue full, too big, bad on receive. |
| `dgram_flows` | Active UDP flows. |
| `dgram_rejected` | UDP flows refused (port not allowed). |
| `dgram_flow_cap_drops` | Datagrams dropped at the flow cap. |
| `tcp_cc` | Since 2.4.18. The congestion control the kernel set on pool sockets. |
| `pool_drops` | Since 2.4.18. Packets dropped because a pool connection's queue was full (should stay 0; the session waits instead). |
| `pool_conn_deaths` | Since 2.4.18. Pool connections that died (both ends count their own). |
| `pool_conns` | Since 2.4.18. One entry per open pool connection, oldest first: `age_s`, `tx` and `rx` (datagrams), `queue`, `stalled_ms` (how long its current socket write has been blocked). Uneven `tx` deltas show a skewed spread. |
| `conn_limit_drops` | Client: connections refused by the public TCP listeners' cap (4096 in total, 256 per source IP). |
| `conns_active` | Client: TCP connections the public listeners currently hold (the cap counts these). Not the per-port `conns_active` in `ports`. |
| `pool_slow_closed` | Since 2.4.7, pool carriers. Pool connections this process closed for delivering far below their share (see [Stalled pool connections](#stalled-pool-connections-245)). |
| `cc` | Since 2.4.10. Pacer diagnostics, see below. |

**The `cc` object (2.4.10).** What held the sender back and why it slowed. Counters run since the start (summed over
sessions); compare two reads to see what happens now.

| Field | Meaning |
|---|---|
| `ticks` | 50 ms pacer ticks. |
| `tok_limited`, `cwnd_limited`, `app_limited` | Ticks in which the sender was held by its pace (rate tokens), by its window, or had nothing to send. Mostly `app_limited` means the tunnel is not the bottleneck. |
| `loss_cuts`, `delay_cuts` | Rate cuts caused by loss and by delay. Since 2.4.11 a reliable carrier (tcp/tls/ws/wss/h2/h2c/grpc) should show `delay_cuts` 0. |
| `deep_trips` | Times the delay rule let the rate fall below the start rate (the 2.4.2 deep-queue signal). |
| `lost`, `spurious` | Packets declared lost, and how many of them were acked later after all (the carrier's TCP delivered them late). |
| `floor_bps` | The current rate floor, bytes per second. |
| `cwnd` | The current window, bytes. |
| `loss_time_ms`, `pto_ms` | The loss timer and the probe timeout now in use. |
| `loss_timer_x` | Reliable carriers: how far the loss timer is stretched (1-8x) because retransmits kept turning out spurious. |
| `pool_full` | Since 2.4.18. Ticks in which the session held back because every pool connection's queue was full (the pool's backpressure). |
| `win_blocked` | Streams that have data to send but no window from the peer right now (a gauge, not a counter). A high value means the receiving side reads slowly. |

With `sessions` > 1 (client) the top-level numbers cover all sessions: counters, `rate_bps`, `ceiling_bps`, `streams`
and `inflight` are sums, `srtt_ms` is the median of the live sessions, `min_rtt_ms` the smallest, `loss_pct` the
highest, and `last_rx_age_ms` the newest packet on any session.

The process also logs a stats line every 10 seconds when something moves (it includes `ceiling=` and `loss=`). Noise
filler alone is not counted as movement, so an idle tunnel with `noise` on does not keep that line printing.

### Speed test (1.8.1)

On a client, `GET /speedtest?dir=down|up&mb=N` (on the `metrics` address, default 10) moves N MB through
the live session and returns `{"dir","bytes","seconds","mb_per_s","mbit_per_s","ok","error"}`. The stream asks the
server for target port 0, which the server answers itself (it sends or absorbs the bytes), so no test service or
extra port is needed and the allowlist is not involved. Both ends need 1.8.1 or newer. Only the client process serves
the endpoint, because only that side can open streams: on Kharej the manager's speed-test key says so instead of
reporting a version error (3.1.1), and the live monitor shows current throughput there.
`wattun test NAME` runs it 10 MB each way. `streams=N` (1-32) runs N streams on every session: the default is 16
since 3.3.0 (8 before), so the figure reflects multi-connection capacity rather than one connection's share; Auto mode
asks for 8 during its screening and 16 on its finalists. Since 2.3.0 the answer also has `"sessions"`: with
`sessions` > 1 the test opens one stream on every live session at once, each moving its share of N MB, and reports the
total over the wall time. N is split between the streams, and each stream carries at most 256 MB, so N is capped at
256 × `streams` (2.5.1; before, any N above 256 fell back to 10 MB). A larger N gives a longer run, which helps when
sampling CPU: 16 streams at 100 MB/s move 200 MB in 2 s.

### Several sessions (2.3.0)

`sessions: N` (client only; the server needs no change, it already tells sessions apart by their random id) runs N
independent sessions to the same server, each with its own carrier (`conns` connections of a pool carrier, or its own
udp socket), its own pacer and its own session id. Why: one session has one receive goroutine and one send
goroutine, and every stream starts with a 4 MB flow-control window (2.4.0 grows it, see below; before that one stream moved at
most about 4 MB / RTT) (measured on a simulated lossless link: 59 MB/s at 40 ms, 29 at 100 ms, 15 at 200 ms). Through a CDN
from Iran the RTT under load is far above the ICMP path's 40 ms, which is what kept one session at 16-18 MB/s while
separate processes added up.

- New TCP connections go to the live session with the fewest open streams, then the fewest bytes in flight; ties
  rotate. A session that is down (nothing heard for 10 s) gets no new streams while another is up; it reconnects
  by itself as before.
- UDP flows stick to one session, chosen by a hash of the flow id (so a flow's datagrams stay in order); only while
  that session is down does the flow use the next live one.
- With several `peer` addresses the sessions share one TLS engine (fingerprint, ECH state and cache) and one view of
  which edges work; session k's connections continue the edge rotation where session k-1's stopped.
- Every session counts against the server's limit of 32 sessions (a handover runs two clients), hence the cap of 16.
- Not for `icmp`, bonded carriers (`a+b`) or `reverse`: the client refuses to start with a clear message.
- Wire: nothing new. The server has always run one session per session id (that is how the two slots of a
  handover share it), so any 2.x server serves a multi-session client.

### Stream window auto-tuning and cheaper receive path (2.4.0)

- **Per-stream window.** Every stream still starts with the implicit 4 MB window, so an old peer behaves exactly as
  before. The receiver now grows the window it advertises (the existing window frame, nothing new on the wire): once
  per RTT it checks how much arrived; if the sender filled at least half the window and the reader is keeping up
  (under a quarter of the window unread), the window doubles toward 2x the bytes per RTT, up to **16 MB per stream**
  and **64 MB of growth per session** (beyond the 4 MB bases). A lagging reader stops the growth, and an advertised
  limit is never taken back. The sender accepts whatever the window frame says and lets `Write` buffer that much.
  A one-stream download is no longer capped at 4 MB / RTT: on a simulated lossless 150 ms RTT link one stream went
  from 20.5 to 32.7 MB/s (`TestStreamWindowAutoTune`; a 40 MB/s link, so the new figure is link-limited).
  Compatibility: only the receiving end decides, so the gain needs the *receiver* of the bulk data to be 2.4.0
  (a 2.3.x receiver never advertises more than 4 MB, and a 2.3.x sender never buffers more than 4 MB, so either
  one keeps the old limit).
- **Pool carriers, receive side.** `tcp|tls|ws|wss|h2|h2c|grpc` read each connection into 64 KB slabs and hand the
  datagrams out as slices of them: no bufio copy and no allocation per datagram. The gRPC reader moves a message
  straight into the caller's buffer (no staging copy). Smaller bufio buffers for the ws/grpc readers were tried and
  measured no better. Write coalescing was already there (each connection's writer fills a 64 KB buffer and flushes when its
  queue runs dry); a yield before the flush to gather more was measured and gave nothing, so it is not in.
- **GC.** 2.4.0 to 2.4.5 set the GC target to 200 % unless `GOGC` was set. 2.4.6 uses Go's default (100 %) again:
  on a busy CDN tunnel 200 % let the heap reach about 1 GB for 400 MB of live data, and the GC itself took under
  0.1 % CPU. `GOGC` and `GOMEMLIMIT` still override it.
- **`GOMEMLIMIT` needs room.** Set it to at least twice the tunnel's normal heap, or leave it unset. Close to the
  heap, Go collects almost without pause: an Iran client limited to 256 MiB with a ~210-280 MB heap (ICMP, ~300
  connections, 2.4.7) used 75-130 % CPU. With 768 MiB, the 2.4.8 client next to it used about 20 % CPU and 76 MB
  RSS at ~200 connections (2026-10-12).
- **Forwarding buffers (2.4.8).** The two copy buffers of each forwarded connection start at 4 KB and double, up to
  32 KB, only while reads fill them. At ~1,300 connections the fixed 32 KB buffers were 41 MB of Kharej's 197 MB heap
  and 20 MB of Iran's 214 MB.

### Memory with slow readers (2.4.3)

When a user's own connection reads slower than the tunnel delivers, which is typical for mobile users, each stream
used to park its full 4 MB window at the receiver. The sender, blocked by that window, buffered another 4 MB in a
backing array of up to 8 MB. Field, 2026-10-12 (production CDN, 180 streams): 761 MB of live heap on Kharej
(`Stream.makeRoom`) and 625 MB on Iran (`Stream.appendReady`).

- **Receiver.** Once per RTT, if unread data keeps piling up, the stream advertises only 2 RTTs of what its reader
  actually consumed (at least 256 KB). When the backlog runs dry the window grows back by half, up to the normal
  window. A fast reader is never limited, because the window only shrinks while the reader is the bottleneck. The
  advertised limit is never taken back, updates just pause, so an older sender works unchanged.
- **Sender.** `Write` buffers at most 256 KB beyond what the peer's window lets it send, and the send buffer never
  grows past its cap.
- **Both ends.** A big backing array is given back once the stream needs much less.

On a simulated 150 ms link with a reader at about 2 MB/s, the receiver's backlog went from 4 MB to 0.2-0.3 MB and the
sender's from 4 MB to under 0.5 MB, while a fast single stream still reached 32.7 MB/s
(`TestSlowReaderBuffersBounded`, `TestStreamWindowAutoTune`). Each half works on its own: a 2.4.3 receiver
saves the receiver's memory, and a 2.4.3 sender saves the sender's.

Field result, the same production tunnel 26 minutes after the update: Kharej RSS went from 806 to 74 MB, Iran's from
808 to 75 MB.

**2.4.4.** In 2.4.3 the sender gave back an oversized buffer whenever it was more than twice what it needed. That
need moves with every ack, so the buffer was copied again on almost every ack. A single slow stream allocated about
6.6 GB in 8 s, and Kharej's `wattun` threads rose from 2-13 % to 40-73 % CPU under load. The buffer is now given back
at most once a second per stream, and only when it is over 4x the need. That is 142 MB allocated in the same test.
`TestSlowReaderBuffersBounded` now fails above 1 GB.

**2.4.6.** A drained stream used to keep up to 1 MB of buffer in each direction for reuse. On a busy tunnel most
streams are idle keep-alive connections, and 220 of them held about 190 MB on the receiving end (field heap profile,
2.4.5). The kept buffer is now at most 256 KB. `BenchmarkSessionBulk` on 2 CPUs measured 68.5 vs 68.9 MB/s, which is
within noise.

Field result, production CDN with about 250 user connections, 2026-10-12: Iran RSS went from 997 MB on 2.4.5 (22 min)
to 79-100 MB on 2.4.6 (25-29 min, peak 207 MB), and Kharej from 415 MB (peak 551) to 75-103 MB (peak 276). Live heap
was about 80 MB on each end. The 30 s download loop averaged 40.8 MB/s, within the time-of-day range of 2.4.5.
Note that 2.4.3 had also looked fine at 26 minutes (75 MB) and grew to about 630 MB by 52 minutes; 2.4.6 has been
checked up to 29 minutes.

### Streams whose connection closed (2.4.17)

A stream used to be retired only once the local side had read every byte the peer sent. When the local connection
closed while data was still buffered, or while the peer was still sending, that never happened: the stream stayed in
the session with no connection behind it. Field, 2026-10-13 (CDN client after a load test): Iran kept 69-76 open
streams with 0 TCP connections on the port, and RSS grew from 40 to 159 MB in 36 minutes.

From 2.4.17 the forwarder closes the stream's receive side when its connection ends (`Stream.CloseRead`). Unread data
is dropped, so it no longer blocks retirement. If the peer had not finished sending, the stream is reset, so the
peer stops too. A cleanly closed connection is unchanged, and the send direction is never cut short. Both roles use
the same forwarder, so update both ends. Nothing changes on the wire (`TestCloseReadReapsLingeringStream`).

Field result, 2.4.17 (test CDN tunnel, 50-connection load, 2026-10-13): Iran held exactly 50 streams during the load
(2.4.16 climbed from 60 to 91) and both ends dropped to 0 when it stopped, staying there for the 8 minutes checked.
Iran RSS stayed at 33-43 MB during the load (2.4.16: 40 to 159 MB) and fell back to 32 MB afterwards. Throughput
and RTT were unchanged.

## Pacing on TCP-based and CDN carriers

Since 2.4.11 these carriers are paced by delivery rate, see [Delivery-rate pacing](#delivery-rate-pacing-2411); this
section describes the delay pacer they used before (still used for ICMP and UDP, and with `WAT_REL_V1=1`).

TCP never drops a datagram by itself, so on `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` and `grpc` the pacer judges delay
by each 50 ms interval's fastest sample and allows a third of the base RTT, because CDN edges and TCP buffering add
delay without any queue of ours.

- **2.4.1.** The pace never drops below the start rate (8 MB/s per session), and delay cuts apply only while the
  session fills its window, so bursty web traffic is not cut down to a crawl.
- **2.4.2.** The window is sized from at most 1.5 x the base RTT, not the smoothed RTT, which includes our own queue.
  Two signals can now take the pace below the start-rate floor for about 30 s, down to the configured floor (200
  KB/s):
  - an interval whose fastest sample is above twice the base RTT (and at least 40 ms above it) while the window is
    full;
  - an interval in which at least 4 packets, and at least 1/20 of those sent, waited past the loss timer (400 ms).
    This cuts the pace by 20 %.

  Before 2.4.2, four sessions at the 8 MB/s floor kept pushing at least 32 MB/s into a CDN path that sustained about
  10 MB/s. Cloudflare buffered the excess until packets timed out. Sustained downloads fell from 40-50 to about
  10 MB/s, with 500 ms stalls (field measurement, 2026-10-12). The change is sender-side only and changes nothing on
  the wire. It matters most on Kharej, which sends the downloads, but update both ends.

### Late delivery is not loss (2.4.9, 2.4.10)

Through a CDN, TCP's own retransmits can delay a datagram past the tunnel's loss timer. The tunnel then resends a
packet TCP was about to deliver, and both copies arrive. Field, 2026-10-12 (wss through Cloudflare): Kharej resent
about half its packets while its TCP connections were clean, the 2.4.2 loss rule read that as congestion, and all four
sessions sat at the floor (about 41 down to about 1 MB/s).

- **2.4.9.** A packet declared lost and then acked anyway counts as *spurious*, and is removed from the loss signal.
  While a tick's losses are mostly spurious (at least half), the loss timer stretches by 1.25x per tick, up to 8x,
  and it shrinks back slowly once they are not. Real loss (at least 4 packets and 1/20 of a tick's packets, after the
  spurious ones are removed) cuts the rate by 20 % and sets a ceiling that creeps back up, instead of dropping to
  the floor.
- **2.4.10.** 2.4.9 rarely matched a late ack, because the given-up packet was forgotten before its ack came back.
  Given-up packets are now kept for 5 s, so the late ack is matched. 2.4.10 also added the `/stats` `cc` object
  (see [Metrics](#metrics)).

Reliable carriers only: ICMP and UDP keep the old rule. On an emulated CDN link resends fell from 6-12 % to about
3 %. These two releases did not fix the field slowdown on their own: the `cc` counters showed the cause was delay
cuts, which 2.4.11 removed. `WAT_REL_V1=1` restores the pre-2.4.9 rule.

### Delivery-rate pacing (2.4.11)

Through 2.4.10 the pacer judged TCP-based carriers by delay, like the ICMP path. On a real CDN that failed: TCP does
its own congestion control and its retransmits delay a datagram without any queue of ours, so the measured round trip
jitters between 1x and 5x the base RTT. The pacer read that jitter as congestion and cut, and a single CDN stream sat
at about 1 MB/s with hundreds of delay cuts to one loss cut while the TCP socket below it was idle (field 2026-10-13).

From 2.4.11 the reliable carriers are paced by **delivery rate** instead, which TCP's jitter and retransmits do not
disturb:

- The sender counts bytes acked per second and keeps the windowed maximum over about ten round trips (busy intervals
  only, so an idle lull never lowers it, and a burst of acks released by a stalled connection is averaged over at
  least one RTT so it does not inflate it). This is the path's delivery capacity.
- The pace tracks `relBWGain` (1.2x) above that estimate, and inflight is bounded to `relCwndBDP` (3) bandwidth-delay
  products, so over-pacing becomes window-limited headroom that probes for a little more without inflating latency.
- Delay never cuts a reliable carrier now. Genuine wire loss still does, through the 2.4.9 rule below (a gentle
  multiplicative cut with a ceiling that creeps back up), after spurious retransmits are removed.
- A slow last leg behind a deep CDN buffer (the 2.4.2 case) is handled by the same BDP bound: delivery plateaus at the
  drain rate, so the estimate and the pace stop climbing and inflight stays near one BDP, instead of queueing until
  packets time out. The 2.4.1/2.4.2 floor-drop rules above apply only to the pre-2.4.11 delay pacer, still used for
  ICMP and UDP and reachable with `WAT_REL_V1=1`.

On an emulated CDN link (shallow edge buffer, 90 ms base RTT, per-connection stalls) this took a single flow from
about 1 to 5-7 MB/s and a parallel download from under 1 to 10-14 MB/s, with no delay cuts. The `/stats` `cc` object
(2.4.10) reports the live picture: `delay_cuts`, `deep_trips`, `loss_cuts`, `spurious` of `lost`, what limited the
sender each tick, and the window and loss-timer gauges.

**Draining to re-measure the base RTT (2.4.12, corrected in 2.4.13).** The BDP bound is `maxBW x minRTT`, so it needs
a true `minRTT`. A single, deeply queued connection never delivers a drained sample, so `minRTT` climbed with its own
queue and the window ran away with it (field 2026-10-13: `minRTT` rose to 550 ms from a real 108, inflight over a
megabyte). Every 8 s (just under the 10 s `minRTT` window, so a sample is always fresh) the pacer enters a BBR-style
PROBE_RTT: it caps inflight to a few packets (`cwnd` returns the drain floor, 4 packets), **waits for inflight to
actually reach that floor**, then holds there ~1 RTT so `sample` reads the base with the queue empty. 2.4.12's first
cut drained only to half a BDP, which on a large queue is still a large queue -- the field showed `minRTT` stuck at
314 ms and the window still running away, so the drain floor is now fixed and low, and the queue depth is read from
the live inflight (mirrored into the pacer). A sample may raise `minRTT` only while draining *and* with inflight at
the floor; otherwise `minRTT` only ever falls, so a queued sample can never pull the base RTT up. On a clean single
connection this holds `minRTT` at the true base and lets a lone stream fill ~90 % of the link; the leftover gap under
heavy per-connection stalls is single-connection head-of-line blocking, which the production pool (8 connections)
routes around.

A drain cycle is entered only when a standing queue of our own could be hiding the base, which takes **both** of two
conditions (2.4.16):

- **inflight above twice the drain floor** -- this sender is holding a real queue. An app-limited sender (the receive
  side of a transfer, or an idle session) sits at the floor, builds no queue, and its delayed samples are reverse-path
  or scheduling noise, never a base to re-measure from. Draining there once raised a client's `minRTT` from 107 to
  545 ms *while it was only receiving a download* and wrecked its next upload (the window sized from a 545 ms base
  queued to a 5 s `srtt` and the stream reset; field 2026-10-13). Requiring inflight above the floor also means the
  `minRTT` raise in `sample` can fire only after a genuine drain down from a real queue.
- **`srtt` above `minRTT x 1.5`** -- there is actually a queue to clear. A pool session runs at `srtt ~ minRTT` (its
  many connections keep each one's queue shallow and `minRTT` fresh), so it skips the drain and its throughput dip; a
  single queued connection sits far above and drains every cycle.

The two conditions were added separately and each alone was wrong: 2.4.14 gated on `srtt` only and let an app-limited
sender re-measure off noise (broke uploads); 2.4.15 gated on inflight only and so drained pool sessions every cycle
(cost pool throughput). 2.4.16 requires both.

**Field result, 2.4.16** (test CDN tunnel through Cloudflare, 2026-10-13). Pool sessions kept `srtt` at 109-116 ms
against a 86 ms `minRTT` instead of drifting up over time, with no delay cuts. Pool speed tests: 22.6 and 32.4 MB/s
up. A single connection: 24.4 MB/s down on a 28-32 ms Cloudflare edge, and 4.41 MB/s up where 2.4.14 had reset the
stream. The slow single-connection results seen earlier (0.6-0.8 MB/s) were on an 84 ms edge, which is why the
manager's edge scan matters.

### Direct pools (2.4.18)

A pool carrier with no CDN in between (`tcp` or `tls` direct, or any pool carrier with `reverse`) is "direct": the
only queues are the pool's and the kernel's, and both push back. 2.4.18 changes how such a tunnel sends; CDN tunnels
(ws/wss/h2/grpc direct to a CDN edge) keep the 2.4.17 behaviour except where noted. Field results, reverse tcp,
Kharej → Iran (the direction with heavy random loss, 3-14 % kernel retransmits), 200 MB per run:

| Change | Before | After |
|---|---|---|
| BBR on pool sockets (`tcp-cc`) | upload 12 MB/s | upload 47-56 MB/s |
| Late ACKs | download 8 streams 30.5, 16 streams 27.8 MB/s; 61-82k resends | 49-51 and 64.7 MB/s; 0-1.7k resends |
| Warm tunnel, 16 conns, 32 streams | | 68.9-73.8 MB/s |

Raw TCP on the same path (8 BBR connections, no tunnel) moved 78 MB/s; 32 connections 127 MB/s.

- **BBR.** The kernel default cubic halves a connection's window on every lost segment, and on this path loss is
  random, not congestion: 8 raw cubic connections moved 2.5 MB/s, 8 BBR ones 78. Pool sockets now ask for BBR
  (`tcp-cc`). Local to each end.
- **Late ACKs** (receiver only). A stalled pool connection leaves a hole for every packet it carries. An ACK frame
  names only the newest 64 received ranges, so those packets, arriving later and lower, were never acked and the
  sender resent them all: resends grew with the stream count. Each ACK now first carries a frame with the received
  packets the main frame leaves out, with a one-hour ack delay so no sender version takes an RTT sample or declares
  a loss from it. Works against any peer version; only the receiver of a direction needs 2.4.18.
  `WAT_NO_LATEACK=1` turns it off.
- **Replay window** 16384 → 131072 packets on reliable carriers (a 1 MB ring per session): at 32 connections a
  connection in loss recovery outlasted the old window and its delivered packets were dropped as replays.
- **Pool backpressure.** A full pool queue used to drop the packet silently (the session resent it after its loss
  timer). The session now waits while every connection's queue holds 16 packets or more (`pool_full`;
  `WAT_POOL_BACKLOG` sets the depth, `WAT_NO_BACKLOG=1` restores the old behaviour). Since 3.0.0 the queue is also
  bounded in bytes, 64 KB per connection (`WAT_POOL_BACKLOG_BYTES`): with 16 KB payloads the 16 packets were 256 KB,
  ~85 ms of our own queue at 3 MB/s per connection in front of every interactive packet. Connections are ranked by
  queued bytes, not packets. With 3 or more connections bulk keeps off the first one (the express lane), so a ping,
  a datagram or an ACK always finds a short queue (`WAT_NO_EXPRESS=1` turns it off). The kernel's unsent queue per
  socket (`TCP_NOTSENT_LOWAT`, 128 KB) is tunable with `WAT_POOL_LOWAT` for A/B tests. A session also waits while
  the pool has no connection yet, so datagrams sent during the first dial are no longer lost (3.0.0).
- **Window and timers.** A direct session's window is one second of delivery rather than 3 bandwidth-delay
  products, it skips the minRTT drain, and the pool keeps slow connections (TCP recovering is not a slow path).
  When a pool connection dies, its unacked packets are resent at once instead of after the loss timer.
  `WAT_NO_DIRECT=1` turns direct mode off.
- **All connections stalled (3.0.1).** A pool whose connections all stop at once (a middlebox cutting every flow, or a
  path that blackholes) used to wait for the kernel's retransmit limit, about 15 minutes, before redialling. Now
  every connection stuck longer than 5 s is closed by the health loop (client and server pool alike) even when no healthy one exists, and the
  pool sockets carry `TCP_USER_TIMEOUT` (30 s, `WAT_POOL_USER_TIMEOUT` in seconds, 0 turns it off), so the slots
  redial within seconds. Rate control also holds on a path that delivers nothing, instead of ramping to the maximum.
- **Startup.** A direct session paces at 2.5x its delivery estimate until the estimate stops growing (a fresh
  tunnel's first 200 MB ran at 42-45 MB/s, the next at 53-71).
- **Pinning.** Each stream rides one pool connection, assigned round-robin, as separate TCP connections would; a
  packet with interactive data takes the least queued connection, so ping under a full download stayed at the
  38-40 ms base. Resent data goes on any connection. `WAT_NO_PIN=1` sprays every packet instead (about the same
  speed in the field). A stream counts as bulk after 256 KB; since 3.0.0 that count decays with a 1 s half-life, so
  an SSH session that once pasted a large file turns interactive again once it goes quiet.
- **Loss cuts off.** A direct pool no longer cuts its rate on loss (TCP's loss is not ours; `WAT_REL_LOSSCUT=1`
  restores it), and its window also covers 2 x srtt (`WAT_CWND_MINRTT=1` turns that off). CDN tunnels keep the
  2.4.17 rules for both. `WAT_DIRECT_LOSS_MS=N` sets a loss-timer floor for direct carriers in ms (test/experiment only; off by default).
- **Speed test** takes `streams=N` (1-32, default 16 since 3.3.0; was 8): `/speedtest?dir=down&mb=200&streams=16`. One stream rides one
  pool connection now, so a single-stream test shows one connection's speed.
- **More connections.** `conns: 16` beat 8 on this path (73.8 against 51 MB/s); 32 fell to 26 MB/s from loss
  bursts. Both ends update for the full gain; the pool's own sending changes are local to each end.

### One session, no longer capped (2.5.0)

Field 2026-10-16, after the route's MSS fix: raw TCP Kharej → Iran did 167 MB/s on 8 connections, 243 on 16 and
314 on 32, and 4 independent reverse tcp tunnels (4 connections each) together 136-143 MB/s down and 173 up, but one
tunnel with 16 connections still 49-60. The limit was the session's own work, on one core:

- **Acks.** Every ack walked every packet in flight, and a direct pool keeps a second of delivery in flight. Now each
  ack range is a binary search into the sent list, and the reliable loss check stops at the first packet young enough
  (packets are in send order).
- **16 KB datagrams** on direct pools by default (was 4 KB): a quarter of the packets, seals and ack entries per byte.
  `mtu` still overrides it. Older peers read them.
- **Fewer acks** on reliable carriers: after 16 packets instead of 6 (the 2 ms bound is unchanged).

All three are local to the sending or receiving end; mixed versions work. Update both ends for the full gain.

Field result (2026-10-16, production reverse tcp tunnel, 16 connections, ~400 user connections, srtt 41-43 ms):

| Run (200 MB) | MB/s | Kharej CPU | Iran CPU |
|---|---|---|---|
| down, 8 streams | 37.9 | 28 % | 103 % |
| up, 8 streams | 101.7 | 63 % | 124 % |
| down, 16 streams | 53.3 | 34 % | 117 % |
| up, 16 streams | 149.7 | 67 % | 134 % |

CPU is percent of one core for the tunnel process; both hosts have 2 cores. Before (2.4.18, 16 streams): down 49-58,
up 49-55. Upload tripled. Download did not move: there the Iran end receives, decrypts and acks everything on about
one core, so its receive path is the next limit.

### Cheaper stream buffers (2.5.1)

A CPU profile of the Iran end during a 16-stream download (2026-10-16) put about 25 % of the tunnel's CPU into its
receive buffers. Each stream kept its in-order bytes in one slice that was dropped whenever the reader caught up
and then re-grown by doubling, with the unread bytes moved to the front whenever the end was reached. The copies,
the zeroing of every new array and the GC behind them did most of the work. The sending end (Kharej) had the same
pattern in its send buffer: a buffer at its size cap moved all its unacked bytes for every write once the front had
freed a little (17 % of its CPU).

- Received in-order bytes now sit in a queue of pooled 64 KB chunks. Each byte is copied once in and once out,
  nothing grows, and a drained or idle stream holds no receive memory.
- The send buffer moves its live bytes to the front only when the acked front is at least half their size;
  otherwise it grows, up to twice its cap.

Both are local to each end and change nothing on the wire. Field A/B on the same Iran and Kharej servers, a test
reverse tcp tunnel (16 connections, BBR) beside the production one, 16 streams, 200 MB per run:

| Run | 2.5.0 | 2.5.1 |
|---|---|---|
| 1 | 57.5 MB/s | 64.8 MB/s |
| 2 | 66.6 MB/s | 116.0 MB/s |
| 3 | 70.9 MB/s | 106.0 MB/s |

An earlier 2.5.0 set gave 53.4, 61.1 and 60.5 MB/s. Iran RSS during the 2.5.1 runs stayed at 149-161 MB (2.5.0:
77-197 MB). The Iran box itself was near saturation, mostly in kernel and softirq time, so the next gains need
fewer system calls per byte rather than less Go work.

Production, 2026-10-17, the same reverse tcp tunnel as the 2.5.0 table above (16 connections, ~155-200 user
streams at the same time). CPU is percent of one core for the tunnel process, averaged over the run:

| Run | MB/s | srtt | Kharej CPU | Iran CPU |
|---|---|---|---|---|
| down, 8 streams, 200 MB | 122.3 | 40 ms | 44 % | 94 % |
| up, 8 streams, 200 MB | 140.7 | 39 ms | 56 % | 96 % |
| down, 16 streams, 200 MB | 157.0 | 51 ms | 58 % | 89 % |
| up, 16 streams, 200 MB | 276.1 | 43 ms | 72 % | 132 % |
| down, 16 streams, 2048 MB | 194.6 | 48 ms | 59 % | 128 % |

Against 2.5.0 on the same tunnel (down 53.3, up 149.7 at 16 streams): download about 3x, upload about 1.8x.

### Stalled pool connections (2.4.5)

Through a CDN, one edge connection can sit in TCP retransmit backoff for tens of seconds with megabytes queued in the
kernel while the others flow. In the field on 2026-10-12, Kharej showed connections with `backoff:8` and up to 5 MB of
Send-Q. The pool picks the connection with the shortest queue of its own, and a stalled socket still swallows writes
into the kernel, so it kept getting picked. Every packet sent there was lost for 400+ ms, and its streams waited:
9-12 % loss, 1 s freezes even at idle, and downloads of 2.5-7 MB/s. 2.4.4 made this visible: 2.4.3's CPU waste had
throttled the sender enough to hide it.

- Each pool socket gets `TCP_NOTSENT_LOWAT` of 128 KB (Linux), so a stalled connection blocks its writer instead of
  queueing megabytes.
- A connection whose socket write has been blocked for more than 300 ms is skipped while any healthy connection
  exists. If every connection is stalled, the path itself is slow, and the pool keeps sending as before.
- A connection stuck for more than 5 s while a healthy one exists is closed, and the client redials it.

This is local to each end and changes nothing on the wire.

**2.4.7.** A connection can also stay writable but deliver little (a slow edge or path). Every second each end counts
what every pool connection delivered. Once the pool has at least 3 connections older than 3 s and enough traffic to
judge, a connection that delivered under half the typical count (the upper quartile) for 3 seconds in a row is
closed, at most one per second, and the client redials it through a fresh path. `pool_slow_closed` in `/stats`
counts these. It works with any peer version, because it only closes connections.

Field result, production CDN, 2026-10-12, measured back to back the same morning: the 30 s download loop averaged
30.4 MB/s on 2.4.3 and 42.9 / 44.7 MB/s on 2.4.5, at 2 and 21 minutes after the restart. Kharej showed no connection
in backoff, and the p95 of a small request during the loop fell from 1114 ms to 269-549 ms.

## 3.2.1: audit hardening

No wire-format change: an older peer keeps working, and either order of updating is fine. Found by a full audit of
2026-11-03; this release fixes the operational edge cases it found, not the packet path.

- **The pool listener cannot be squatted.** An unauthenticated connection that sent only the 8-byte pool id and then
  idled used to hold its slot until the remote TCP stack died; enough of them filled every pool and a real client
  could never rejoin. The listener now accepts at most 128 connections per source address, closes a connection it
  never wrote a byte on after 5 minutes, and closes one silent in both directions for 30 minutes. All three run in
  the health loop; a refused client redials through the normal path.
- **A malformed ACK delay cannot fake mass loss.** The peer-reported delay becomes a `time.Duration` added to the
  loss timer; a huge uvarint overflowed it negative and marked the whole in-flight window lost, which a hostile or
  buggy *authenticated* peer could use for a retransmit storm. It is now clamped to zero for negative-encoded or
  absurd values (up to ten times the protocol's own one-hour late-ACK sentinel stays accepted), and the ACK's ranges
  are still applied — dropping the frame had stalled bulk transfers.
- **The client resets its replay state when the server restarts with a lower clock.** After such a restart every
  server->client packet was below the client's replay watermark and was dropped until the client process was
  restarted too; the client now clears the window when the new server boot id arrives. The nonce-reuse caveat is
  unchanged and still operator-side: keep NTP on.
- **The metrics server refuses cross-site requests.** `/carrier/toggle`, `/speedtest` and `/quota/reset` answer 403
  to a browser page on another origin (Sec-Fetch-Site / Origin checks). curl and the manager send neither header, so
  they are unaffected.
- **A flag-run server with no allowlist warns once.** The documented default (every port 1-65535 on 127.0.0.1) is
  unchanged, but the server now says so at startup. Manager-written tunnels carry a `ports:` list and do not warn.
- **`/stats` gains flat aggregate aliases** `rtt_ms` and `streams_total`: the nested `carriers` and `session_list`
  objects also carry `srtt_ms`/`streams` and sort before the aggregate keys, so a plain grep of the JSON could read a
  per-carrier value (the manager did).
- **Removed the "emergency revive" engine.** It had 168 lines, a server receive-path hook and two tests, but nothing
  could produce a knock and every action only logged, so it advertised a recovery channel that could not work. The
  knock parse also leaves the server receive path.
- **Anti-censorship CI, a safer installer, shipped `wprobe`.** New `.github/workflows/ci.yml` runs `go build`, `go vet`,
  a `gofmt` gate, both test suites, the shell syntax checks plus `test-manager.sh`, the DPI-model self-test, Windows
  and linux/arm64 cross builds, the ICMP/raw-socket tests under `sudo`, and a race subset. The release job now refuses
  a tag that does not match `wat/version.go` and both README badges. `install.sh` requires `openssl` and refuses any
  remote install whose `SHA256SUMS.sig` is missing or invalid (a local `dist/` build still installs). `build.sh` also
  ships `cmd/wprobe` as `wattun-wprobe-<os>-<arch>`.

**Follow-up audit pass (same day, same unreleased 3.2.1).**

- **A session id cannot be orphaned by an eviction race.** A full server evicts a silent session and closes it in a
  goroutine while the reconnecting client can be re-admitted under the same id; the old close then deleted the new
  session entry, leaking it and hanging that client's streams. `subIO.Close` now removes/retires only the entry it
  still owns (`ss.io == b`).
- **Hostile ACK ranges cannot wrap.** The range decoder validated `gap+len <= lo` with an addition that overflowed
  for hostile uvarints; a wrapped ACK decoded into overlapping ranges and multiplied `onAck`'s delivery walk. It now
  validates by subtraction (`gap >= lo || len > lo-gap`), rejecting the wrapped form.
- **The memory budget covers buffered data, not just windows.** Received stream bytes (`rxHeld`) and fragment
  reassembly (`reasmHeld`, 32 MB cap) are now charged to the process budget; when it is full the offending stream is
  reset (RST) and over-cap fragment pieces are dropped, instead of a key-holding peer pinning gigabytes. The 4 MB
  base windows are deliberately not charged, so ordinary stream concurrency is unchanged. The received-datagram queue
  is 64 entries (it can hold reassembled `MaxDatagram` frames).
- **Public listeners are capped** at 4096 connections in total and 256 per source IP; refused connections are closed
  and counted in `/stats` as `conn_limit_drops`, with `conns_active` for the live count.
- **`pprof` and the read metrics endpoints reject cross-site browser requests** like the side-effect routes already
  did, so a visited page cannot start a CPU profile on the loopback metrics port.
- **The manager reads the aggregate `/stats` values** (`rtt_ms`/`streams_total`) instead of a nested per-session row,
  so a `-sessions > 1` tunnel no longer shows the first session's RTT and stream count.
- **The installer/manager trust chain covers the scripts.** `build.sh` copies `install.sh` into `dist/` and includes it
  in `SHA256SUMS`; `wattun-manager update` downloads the installer from the release assets, verifies the RSA signature
  and the installer's hash against the signed list, and only then runs it as root. `install.sh` refuses an unsigned
  manager for releases that do not ship one. `WAT_ALLOW_UNSIGNED_MANAGER=1`/`WAT_ALLOW_UNSIGNED_UPDATE=1` are explicit
  opt-ins; a `WAT_PROXY`-fetched installer script itself stays trust-on-first-use.
- **Tests and CI.** New tests cover the close-identity check, wrapping ACK ranges, the receive budget, the connection
  limiter, the cross-site guard, the `/stats` aliases and `cmd/wprobe`'s parser/checksum; the hot-reload test can no
  longer skip its assertion. CI adds `-timeout 15m` to the long suites and the release job asserts that
  `dist/install.sh` exists in the signed `SHA256SUMS`. The flag table gained the flags it had omitted (fake-SNI family,
  pool rotation, win-max, mem-budget, ping-every, src-ip, tls-small-ch), the Keys table `mem-budget`/`src-ip`, and
  `/stats` the two connection counters.

**Second audit pass (same evening, same unreleased 3.2.1).**

- **A reverse pool now ignores unauthenticated dialers.** The merged listener used to add every TCP connection that
  wrote eight bytes to its one pool; the send side then preferred the least-queued connection, so a stranger could
  receive the tunnel's packets and hold every slot. The pool now pins itself to source addresses that delivered a
  packet the session authenticated (up to eight, FIFO, so a peer whose egress address changes keeps working), never
  writes to any other connection, reaps an unauthenticated connection after five seconds, and evicts the oldest
  connection (strangers first) when a full pool must admit a new dialer. No wire change: old peers work.
- **A bonded packet is only sent on a carrier that can frame it.** `pathSet.choose` now takes the datagram size and
  skips carriers whose `MaxMTU`/`MTU` is smaller while another path fits, so a 16 KB datagram sized for a direct pool
  can no longer be handed to the 2 KB-buffered ICMP leg at a burst boundary.
- **The CI ICMP job fails instead of skipping on a raw-socket error** when running as root, so a primary-carrier
  regression cannot report green with the only end-to-end ICMP test skipped.
- **The manager's heal minimum-rate SLA works again** (`rate_bps` is a float in `/stats`; the integer division is now
  done defensively) and the release/trust paths gained executing tests (a throwaway RSA keypair for `sums_verify`, the
  embedded release-key parity between `install.sh` and `wattun-manager`), a release self-verification step, shell,
  vet and gofmt gates in the release workflow, and a `gofmt` gate that includes `testbench`.

## 3.2.0: fast by default, bounded memory, gre/ipip

Measured on a 2 vCPU Iran / 2 vCPU Kharej pair, 76-80 ms, raw TCP ~2 Gbit/s sustained on 16 streams (iperf3),
built-in `/speedtest`, 16 streams, default settings, `bench/pair.sh`:

| | 3.1.2 | 3.2.0 |
|---|---|---|
| tcp down / up | 193-248 / 112 MB/s | 224-282 / 146 MB/s; **271.7 MB/s (2.17 Gbit/s) sustained over 16 s (4.3 GB)** |
| tls down / up | 196 / 123 | 187-209 / 140 |
| one stream down / up (tcp) | 67 / 49 | 147-152 / 36-56 |
| tcp client to a server with `icmp` among its carriers | 16 MB/s per session (cap) | 206 / 142 |
| 32 sessions on one server | OOM-killed at 2.7 GB | no kill, peak 1.8 GB on a 3.8 GB box |

- **The ICMP cap only applies to ICMP.** `max-mbps` defaulted to 16 MB/s per session for the whole process whenever
  `icmp` was among the carriers. Every auto Kharej server (`carrier: icmp+udp+tcp+...`) therefore held tcp, tls and
  wss clients to 16 MB/s per session. Now the default is 16 only for a lone `icmp` carrier; in a bond the icmp path
  alone is held to `wat.ICMPPathBps` (16 MB/s) by a token bucket in the path scheduler, and bulk beyond it goes to the
  other carriers. Updating the Kharej binary is enough; no config change.
- **Sessions: 2 by default, never forced.** Sessions each run their own pacer and read each other's queue as
  congestion: 1 session 176, 2 sessions 261, 4 sessions 147, 8 sessions 68-74 MB/s down on the same pair. The engine's
  auto value is now at most 2 (4-core hosts used to get 4), and `wattun-manager` no longer writes `sessions: 4` for
  every pool tunnel. An explicit `sessions:` still works.
- **Memory.** A stream's unacknowledged send data is now a queue of pooled 64 KB chunks (it was one slice doubled up to
  twice the window, 28 % of the sender's CPU in `memmove` and 7 % zeroing). Send data and grown receive windows are
  counted for the whole process against `mem-budget` (MB, default an eighth of the RAM); over it every stream holds at
  most 256 KB of send data and windows stop growing. The Go heap gets a soft limit of a third of the RAM unless
  `GOMEMLIMIT` is set.
- **A full server gives up stale slots.** With all 32 session slots taken, a new authenticated client replaces the
  session that has heard nothing for 10 s or more. A client restarted with many sessions used to be locked out until
  the idle timeout closed its own dead sessions.
- **Knock parsing only for strangers.** The revive engine parsed every received data packet as a possible DNS knock
  (base32, upper-casing): 15 % of a server's CPU at 130 MB/s upload. It now runs only for packets of no live session.
- **Bond loss penalty.** A carrier's bulk share was `w * (1 - loss)`, so 10 % loss kept 90 % of the share. It is now
  `w * (1 - loss)^4`: 10 % loss keeps 66 %, 20 % keeps 41 %, 30 % keeps 24 %.
- **`gre` and `ipip` carriers** (see [Carriers](#carriers)). Both ends need 3.2.0.
- **Auto test tunes the chosen type.** After the type is chosen (`wattun-manager` Iran wizard with an auto token, and
  `auto-test NAME`), the manager tries the advanced settings that change its speed, one at a time, each against the
  best so far, with about 2 s of traffic each way (20-200 MB): pool carriers `sessions` 1/4/8, `conns` 4/8/32/64,
  `mtu` 16384; udp `sessions` 1/4, `mtu` 1200, `batch` on, `loss-ceiling`; icmp `mtu` 1000/1400, `batch` off,
  `loss-ceiling`. A value is written to the config only when it beats the best so far by 10 %; otherwise the setting
  stays at the engine's auto value. Values given with `--sessions`, `--conns`, `--mtu` or a preset are not tested.
  Bonds and reverse tunnels are not tuned. On the test pair: tcp kept the auto values (sessions 4 +7 %, 8 -50 %), udp
  kept `sessions: 4` (61 vs 47 MB/s down+up). It takes 30-70 s. Switching an auto tunnel to another type drops the
  tuned settings, because a value for one type can break another (the engine refuses `sessions` with icmp).
  The unattended re-test of auto-heal does not tune.
- Not changed: `loss-ceiling` stays opt-in for udp. On this pair (UDP shaped to ~270 Mbit/s) it cut retransmits from
  33.5k to 3.8k but halved upload (50 to 23 MB/s).
- Still open: upload stays below download (the receiving server is CPU-bound at ~1.8 of 2 cores, and direct pools
  keep about a second of data in flight, which shows as spurious retransmits); sessions do not yet share one pacer.

## 3.1.1: authenticated session aging, machine-bound totals, matrix for bonds

- **The server's session table only trusts authenticated packets.** The janitor used a timestamp updated for every
  packet that carried a live session id, so forged or replayed junk could keep a dead session in the table. It now uses
  `Session.LastRecv` (set only after decryption), falling back to the session's creation time, and the server remembers
  the highest authenticated packet number of a session that left the table (bounded map, 4096 ids): `Server.admit`
  refuses a packet at or below that watermark, so the session's own captured packets cannot open a new one
  (`Session.LastPN`, `retiredPN`).
- **Liveness follows `-ping-every`.** The value is validated (0-60 s). `Alive()` is `max(10 s, 3 × ping-every)` and the
  server's idle timeout `max(45 s, 3 × ping-every)`, so a raised keepalive interval does not show a healthy tunnel as
  down (a keepalive gap is 0.6-1.4× the interval and each ping is acked at once).
- **Idle traffic follows `-ping-every` too.** The server's boot-id frame (`frBoot`, the client's only signal that the
  server restarted and lost its streams) went out every second whatever the keepalive was set to; it now uses
  `-ping-every`, which cut the session payload of an otherwise silent tunnel from 15.3 to 11.0 MB/day at the default
  2 s (measured 2026-10-29, one session, udp carrier; 8.9 → 4.0 MB/day at `-ping-every 20`). A server also keeps its
  last known lanes when every lane has aged out of `laneSeen`, instead of sending nothing at all - not even the boot
  frame - until the client speaks again, and the 30 s silence reset now scales like `Server.IdleTimeout`
  (`max(30 s, 3 × ping-every)`) so a long keepalive no longer resets every open stream.
- **`-sessions` clones keep the `tcp-mimic` hello.** The hello-v2 parameters moved behind one atomic pointer and `Clone`
  copies them; before, the extra sessions opened with the plain 8-byte pool id while the first looked like TLS.
- **A UDP flow pins its session.** The flow picks a session on its first datagram and keeps it while it lives
  (`cflow.session`). Re-picking per datagram let a flapping session (down, then live again) pull the flow back and
  reorder it.
- **Lifetime totals are bound to their machine.** `<config>.totals.json` is paired with `<config>.totals.json.host`
  (`/etc/machine-id`): see [Per-port traffic and limits](#per-port-traffic-and-limits). `wattun-manager reset-traffic
  NAME` zeroes the counters in place, and deleting a tunnel removes its totals and quota files with the config.
- **Installer: the manager is a signed release asset.** `build.sh` copies `wattun-manager` into `dist/` and includes it
  in the RSA-signed `SHA256SUMS`; `install.sh` fetches it from the release and checks its hash like the binary's, and
  only falls back to `raw.githubusercontent` for releases that predate the asset (never through `WAT_PROXY`).
- **Anti-censor matrix.** Modes are version-gated: an older binary silently treats unknown modes as `seq`, so offering
  `synrst` or `paws` to it reported a false winner. `paws` joined the list, bonded tunnels are tested leg by leg (each
  pool leg is a throw-away client; the winner's `fake-sni`/`fake-mode` then apply to every pool leg, plus `ech` when the
  winner carries it), and each variant moves 8 MB per direction with the top 3 re-measured at 20 MB before ranking.
- **Manager polish.** The Kharej speed test says the test runs on Iran instead of claiming an old binary (the endpoint
  exists only in the client process). The tunnel page has a Kharej "Change Iran Address" and an Iran "Change Listen
  Port" for reverse tunnels; pasting a new token rewrites the whole connection (carrier, peer, reverse, listen, path,
  firewall) instead of leaving stale fields. The bonding menu only adds or removes carriers on auto tunnels, reading
  each carrier's port from the plan. `h2c` can be chosen directly (key `0`). The dashboard marks a live direct pool
  tunnel with no disguise as `[anti-censor off]`.

## 3.1.0: host-aware defaults and two fixes

- **Defaults follow the host.** At start the program reads the CPU count (`min(NumCPU, GOMAXPROCS)`) and the RAM it may
  use (`/proc/meminfo`, lowered by a cgroup v1 or v2 memory limit, so a container is not sized by its host; Windows asks
  the OS; an unknown value counts as lean) and picks a tier. The start line shows it:
  `host: 2 CPU, 1920 MB RAM, standard tier, conns 16, sessions 2`.

  | Tier | When | Pool `conns` | `sessions` (forward client) | Window cap per stream | Session window growth | `TCP_NOTSENT_LOWAT` |
  |---|---|---|---|---|---|---|
  | lean | 1 CPU or up to 1.5 GB | 8 | 1 | 4 MB | 32 MB | 64 KB |
  | standard | everything between | 16 | 2 (2+ CPUs) | 16 MB | 64 MB | 128 KB |
  | highperf | 3.5 GB+ and 2+ CPUs | 24 (32 with 4+ CPUs) | 2 (4 with 4+ CPUs) | 32 MB | 128 MB | 256 KB |

  `-conns`, `-sessions`, `-win-max` and `WAT_POOL_LOWAT` always win. `sessions` is chosen only for a forward client with
  one non-`icmp` carrier. Things to know: a lean host now holds a single stream near 4 MB / RTT (about 44 MB/s at 90 ms),
  which is about what a one-vCPU box reached in our tests (50 MB/s); a standard host opens twice the sockets of 3.0.x and its memory
  peaked at 1 GB (client) during a 512 MB upload on a 1.9 GB box, so on a small box that also runs other services set
  `sessions: 1` or `win-max: 4`.
- **Fixed: the server's receive loop could wedge for good.** `Server.getBuf` returned a too-small pooled buffer with a
  blocking send; a concurrent `putBuf` could refill the slot and the only receive goroutine blocked forever. Symptom: the
  first speed test passed and every later one died with "session closed" while the connections stayed up. Reproduced end
  to end (1 success then 11 failures), fixed build 12/12 (`TestGetBufNeverBlocks`).
- **Fixed: bonded sessions pinned bulk streams to a lane the bond does not have.** A bond routes by its own path index,
  so per-stream pinning sent every bulk packet to carrier 0 (or dropped it on a reverse bond). Pinning is now only used
  when the carrier is not a path chooser (`TestBondChooserDisablesPin`).
- **Field numbers, one pair, one day, 16 streams, 1 GB** (2 vCPU each, Iran 1.9 GB, Kharej 3.8 GB, 81 ms, raw TCP between
  them 1.5 Gbit/s received, host buffers raised to 16 MB with BBR): tcp 1057 down / 981 up Mbit/s, tls 1140 / 805, ws 1132 / 808,
  wss 1066 / 676, h2c 1131 / 547, grpc 1027 / 670, udp 578 / 542; with fake-SNI `rst`, `synrst` or `paws` on tcp
  1043-1113 down. Single runs; this pair's run-to-run spread is about 20 %. With the kernel defaults (208 KB receive
  buffer, cubic) tcp, ws and wss stay above 1 Gbit/s down, but h2c and grpc fall to 487 and 340: raise `net.core.rmem_max`
  and `tcp_rmem` on both ends for them. Under a 1 Gbit/s load the tunnel's round trip rose from 81 ms to 94-127 ms
  downloading and 383-414 ms uploading (queueing inside the process); below saturation `icmp` stayed within 4 ms of the
  route. 2 Gbit/s is not reachable on that pair (the wire itself tops out near 1.5 Gbit/s).

## 3.0.2: probing resistance and the PAWS marker

- **`fake-mode: paws`.** An in-window fake ClientHello with a valid TCP checksum, so a DPI that checks window and
  checksum accepts it and classifies the flow, carrying a TCP timestamp 2^30 behind the real one. The server's Linux
  kernel drops the segment (RFC 7323 PAWS) and answers with a duplicate ACK, which releases the real data like `seq`
  does. The kernel adds a random offset to every connection's `TSval`, so the stale value is derived from the observed
  one; a fixed value would be "older" only about half the time and the server would take the fake as the real stream.
  Without a timestamp option on the connection (`net.ipv4.tcp_timestamps=0` at either end) it sends the `seq` marker
  instead. `fake-mode: auto` probes it after `rst` and `synrst`. Needs wattun 3.0.2 on the client only. The server
  kernel's `TcpExtPAWSEstab` counter rises by one per dropped fake (`nstat -az TcpExtPAWSEstab`). On the test pair, whose
  filter cuts direct flows after ~3 KB unless it is told to forget the flow, `paws` drops the fake correctly but the
  flow is still cut, like `seq`; only `rst` and `synrst` work there. Use it against SNI allowlists that do not track TCP
  timestamps.
- **Churn on reverse tunnels.** `pool-rotate` and `pool-rotate-bytes` were ignored on a server, so a reverse tunnel's pool (Kharej
  dials Iran) kept the same TCP connections for hours and was cut after 30-40 minutes under heavy traffic (flow-duration limits).
  A server that dials (`reverse: true`) now recycles its connections like a client does. The manager writes `pool-rotate: 30m` into
  new reverse pool tunnels and auto companions; existing tunnels need the key added by hand. On the test pair a 20 s rotation kept
  every connection under 20 s old and still moved 80 MB/s down / 68 MB/s up; the control run without rotation lost all
  receive traffic on its 150-second-old connections during the upload phase (one run each, not a proof).
- **HTTP/2 receive window.** The `h2`, `h2c` and `grpc` servers advertise 8 MB per stream and 32 MB per connection (Go's
  default is 1 MB per stream, which limits one pool connection to about 11 MB/s on a 90 ms path). Applies to the side that
  receives, so it speeds up forward upload and reverse download.
- **`tls-frag: -1`.** Splits the ClientHello right after the first character of the SNI, so neither segment holds a
  parseable host name. Any positive N keeps the fixed-size split.
- **Web server face.** An HTTP carrier server (`ws`, `wss`, `h2`, `h2c`, `grpc`) answers `/` with the default
  "Welcome to nginx!" page and every other path that is not the tunnel path with nginx's 404 page (`Server: nginx`, no
  version), so a prober that fetches a page finds a web server. The tunnel path itself still answers 404 without a valid
  upgrade.
- **Throwaway certificate.** The self-signed certificate of `tls`/`wss` servers has a random host name, no
  organization and 90 days of validity, instead of `CN=localhost` with ten years.
- **WebSocket request.** `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits` joins the Chrome
  header set. Frames are never compressed, so a peer that answers with an extension is refused at the handshake;
  `Origin` is `http://` for `ws` and `https://` for the other carriers.
- **`wattun-manager iran-firewall on|off|status|update [ports]`.** Accepts connections on this Iran server's client
  ports only from Iranian addresses (iptables plus an ipset filled from the ipdeny.com list). It needs a successful
  download of the list and refuses a list under 50 ranges; it changes nothing when the download fails and no cached
  list exists. Your own users abroad are dropped too, IPv6 is not covered, and the rules do not survive a reboot unless
  iptables-persistent and ipset-persistent are installed.

## ICMP path limits and pacing

Measured 2026-10-10 on the real Iran <-> Kharej path (only ICMP passes):

- The path delivers at most about 50-55k ICMP packets per second Kharej -> Iran (about 33 MB/s at 640 B payload),
  shared by every ICMP type. Past about 45k pps a queue builds (p99 one-way delay +300 ms) and loss rises. Random
  loss on this path is only about 0.2 %.
- **Packet size (2026-10-12).** The path passes full 1500-byte ICMP packets again, both ways, with DF set: 0-0.5 %
  loss from 640 to 1472 bytes, no fragmentation needed. A route `mtu lock 680` on either end still caps it, so check
  `ip route get <peer>` first. Measured with a test tunnel next to production, same 30 MB/s cap, 3 runs each:

  | `mtu` | Down MB/s | Up MB/s | Kharej retrans (download) | Ping during download, p50/p95 |
  |---|---|---|---|---|
  | 640 (default) | 22-24 | 21-22 | 3.6-4.9 % | 41 / 43 ms |
  | 1400 | 27.5 | 26 | 0.8 % | 41 / 42 ms |

  Larger packets need fewer packets per MB, so they stay further below the packet-rate limit above. Test the size
  with `ping -M do -s SIZE <peer>`, then set `mtu` on **both** ends (each end sends at its own size).
- **Volume limit (2026-10-12).** Twice, ICMP held above ~30 MB/s in total for a few seconds (34.5 and 41.5 MB/s) was
  followed 5-30 s later by a reroute inside Iran (base RTT 40 -> 76 ms) that lasted minutes. On that route bulk
  transfers collapse (~2 MB/s, 50-90 % loss) while light traffic is fine. Runs at or below ~27 MB/s never triggered
  it. Keep the total `max-mbps` of every ICMP tunnel on the path at about 30 or less, whatever the packet size.
- `max-mbps` stays at 16 by default for `icmp` (and any bond that includes it). The ceiling that really binds is the path's packet rate, so values above
  roughly 30 only add queueing.
- **Volume governor (2.9.0, opt-in `-governor`).** The hardcoded `max-mbps 16` above is the safe default for a
  path that reroutes above ~30 MB/s total; the governor learns the real ceiling instead. It watches the base RTT
  in 2 s windows (stable for 6 s = armed), and when the base jumps > 25 % (the field's 40 → 76 ms reroute
  signature) it sets a ceiling at 80 % of the highest rate of the 4 s before the jump and holds it for 60 s. After
  the hold, quiet windows creep the ceiling up 2 % each (released at 1.25× the rate that triggered it), so a path
  that got faster is followed. It never raises the rate, only caps the delay rule's growth — the sim tests' pacer
  pins are untouched. Watch `srtt_ms` and `min_rtt_ms` in `/stats`: a governor path shows the jump, then a rate
  that stops climbing before the next jump.
- **Loss-aware ceiling (1.8.0, opt-in).** Off by default: the pacer is delay-based and loss alone is not congestion.
  With `loss-ceiling: true` (`-loss-ceiling`) it also compares, every 50 ms, the interval's loss with a learned
  baseline (slow average of quiet intervals, at least 0.5 %). If loss is above `max(3 %, 4 x baseline)` the rate is
  cut by 15 % and a soft ceiling is set 5 % above the new rate; the ceiling then rises 2 % per loss-free interval
  and the rate may not climb past it. It helps when a too-high `max-mbps` makes the path drop packets (a test pair
  with `max-mbps 80` ran 30-35 % of the wire as retransmissions). Steady random loss (even 2 %) does not trigger
  it. Intervals with fewer than 50 packets are ignored, and TCP-based carriers never use it. With it off,
  `ceiling_bps` stays 0. Watch `ceiling_bps` and `loss_pct` in `/stats`.
- **Batching is on by default for the ICMP carrier on Linux** (sendmmsg / recvmmsg): one flow went from 15 to
  25 MB/s and CPU per MB from 0.043 to 0.026 on the real path. `WAT_BATCH=0` forces it off; other carriers keep
  batching off unless `WAT_BATCH=1`. Since 3.0.0 the `batch: on|off` key does the same from the config, and reverse
  udp batches its sends too. `WAT_GSO=1` (udp, Linux, opt-in) sends runs of equal-size datagrams as one UDP GSO
  write and turns GRO on for receive; a kernel or NIC that refuses it falls back to sendmmsg on that socket.
- **`icmp-type`** picks the ICMP message type the tunnel hides in: `echo` (8 request / 0 reply, the default),
  `timestamp` (13/14), `info` (15/16) or `mask` (17/18). The client sends the request type, the server answers with
  the matching reply. The kernel BPF filter accepts only that pair (and the tunnel's identifier range), so other
  ICMP software never sees the packets and an `echo` tunnel is unaffected. Both ends must use the same value.
  Note: Linux itself answers timestamp requests (and echo requests unless `icmp_echo_ignore_all=1`); the kernel's
  extra reply carries our own payload back, fails authentication and is dropped. `info` and `mask` requests are
  ignored by the kernel.

## Handover, drain and rollback

A restart cuts every connection. WatTunnel avoids restarts on a live system.

- **Two clients, one key.** Each client session has its own random id and key, so two Iran instances (slots) can run
  side by side against the same server.
- **Port changes need no restart.** The server re-reads its `ports:` list or `allow-file`. The client re-reads
  `ports:`.
- **Handover.** Start the idle slot on offset ports, prove the link and push data through it, flip
  the NAT redirect from the old slot to the new one, then let the old slot drain.
  If the proof fails, the live slot is not touched.
- **Drain.** `SIGUSR1` to a server stops new sessions. It exits when the last session ends. Stop an old client slot once its `/stats` shows `streams` 0.
- **Rollback.** Every install keeps the previous binary as `wattun.prev`. `wattun` (the manager) can roll back to it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Where to start | `wattun test NAME`, then `systemctl status wattun@NAME` and `journalctl -u wattun@NAME -f`. |
| `DISCONNECTED`, or the log says `no reply from the server` | Different key or carrier on the two sides: paste the token again on Iran. For ICMP, check that Iran can ping Kharej, and run the doctor. |
| Works some days only | The route is filtered on the bad days. Keep auto-heal on and a second tunnel with another carrier as a backup. |
| CDN tunnel works from some Iran servers or networks but not others | The Kharej address on Iran is a plain IP, so traffic is not going through Cloudflare. Use your Cloudflare domain (orange cloud) or run `wattun cdn-tune NAME`, and check the SNI is spelled exactly like the domain. |
| A CDN tunnel connects and then stalls | Run `wattun cdn-tune NAME full`. |
| Connected, but users can't open sites | Nothing listens on Kharej's `127.0.0.1:PORT`. |
| `alive: false` on both ends, no errors | Wrong key, or the carrier is filtered. Compare the key files (`sha256sum`). Try `ping` between the servers: ICMP must pass. |
| Iran cannot ping Kharej, Kharej can ping Iran (often one day on, one day off) | A one-way block on Iran's own pings. Use `reverse: true` on both ends with `icmp` (see Reverse ICMP). |
| ICMP works with small pings but the tunnel stalls | MTU. Go back to the default 640 on both ends, then test larger sizes with `ping -M do -s SIZE <peer>` before raising `mtu` again. |
| tcp, tls, ws never connect | That carrier is filtered on this path. Check with `nc -vz HOST PORT` from the client. On a path where only ping passes tCP and UDP are cut: use `icmp`. |
| tcp pool connects, then drops after a few packets | A middlebox cuts long TCP flows. Try `tls`, `wss` or `grpc`, or `reverse`. |
| Pool carriers or UDP forwards do not work, the other end is older | Version mismatch. Both ends must run 1.3.0 or newer for pool carriers and 1.2.0 or newer for UDP forwards. Check `wattun -version` on both ends. |
| `listen tcp ...: address already in use` | Another process owns the port. `ss -ltnp \| grep :PORT`. Never start a test on a port a live instance uses; test ports should be 10811 or higher. |
| `restart needed for KEY` in the log | You changed a key other than `ports:`. Only `ports:` is hot-reloaded. Do a handover. |
| Config does not apply | A parse error keeps the old config. The log says `config FILE: line N: ...`. |
| WireGuard (or another UDP VPN) connects, small apps like Telegram work, web pages do not | Its packets are bigger than one tunnel packet. Update both ends to 2.5.0 (big datagrams are split), or set `MTU = 1280` in WireGuard (udp carrier, or icmp with `mtu: 1400`). `dgram_dropped_size` in `/stats` rising confirms it. |
| Slow, high CPU on Iran | Two cores saturate under many processes. Run one instance, not one per port. Check `retrans` and `send_errors` in `/stats`. Lower `max-mbps` only if the link is rate limited. |
| Time or clocks | Authentication does not compare clocks. A server restart starts its packet numbers from the current time so a nonce is never reused, so keep NTP on and never set a server clock back. |
| Foreign traffic on the listener | Expected. Strangers' packets fail authentication and are dropped. On a direct carrier you can also refuse them by source address with `allow-clients` (see "Client allowlist"). |
| `-allow-clients` rejects a client that should pass | The tunnel log names the source (`client IP is not in -allow-clients`). Check the list/CIDR, the address family, and the carrier: behind a CDN the source is the proxy edge, and the program now refuses that combination at startup; with `reverse` the list is ignored. The check is admission only, so an already-connected session is not cut. |
| `-allow-clients-file` stops the start | The file must be under `/etc/wattun` (the systemd unit runs with `ProtectHome=yes`) and must not be empty. |
| `fec_state` stays `off` although `fec: auto` is set | Expected on a healthy path: parity is loss-gated and the measured loss is below `fec-on-loss` (default 2 %). Lower it only if the link really needs parity; `fec_sent` staying flat confirms the gate is closed rather than FEC being off. |
| Lifetime counters and quota usage restart from zero after a reboot | `state-dir` points at tmpfs (`/run/wattun`). They survive a service restart (`RuntimeDirectoryPreserve=yes` in the shipped unit) but not a reboot; move the state directory next to the config (or to a persistent one) when the counters must survive reboots. |
| Startup fails with an unknown key after editing the config | The running binary is older than the keys: `state-dir`, `state-save`, `allow-clients`, `allow-clients-file`, `fec-on-loss`, `fec-off-loss`, `shape-data`, `noise`, `noise-bps` and `noise-window` are 3.3.0 keys. Run `wattun update` on that end, or remove the keys. |
| A shaped carrier fails at startup | The raw tier (`sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3`) needs Linux with CAP_NET_RAW on both ends; the UDP tier needs 3.3.0 on both ends and the same carrier name. Check `wattun -version` on both. |
| Two shaped peers connect the socket but carry no data | Both ends must select the same shaped carrier name and share the key (a datagram whose key-derived fields do not match is dropped). These are wattun-internal shapes, not the real protocol: a real IPsec/VXLAN/NTP peer cannot talk to them, and a mismatched name at either end just drops traffic. |
| `shape-data` or `noise` is set but nothing changes | `shape-data` is ignored on bonded carriers (the log warns); `noise-window` without `noise` is ignored with a warning; `noise` only fires while the session has no user data for about two keepalives. The cost shows in `/stats` as `shape_data_bytes`/`noise_sent`/`noise_bytes` and in the session totals, not in the per-port counters. |

## Security model

- **Pre-shared key.** Both ends hold the same secret. It is never sent.
- **Per session keys.** Each client session picks a random 8-byte id. The packet key is SHA-256 over a fixed module
  prefix, the secret and that id. Packet = `session id | packet number | ChaCha20-Poly1305(frames)`. The nonce is
  the packet number and is never reused: server numbers start at a time-based value with a direction bit set.
  Since 3.0.0 the first 16 bytes are masked on the wire (see "Traffic shape"). That "never reused" guarantee
  assumes the server clock never goes backwards across restarts; if it does, the client now resets its replay
  state when it sees a new boot id (the tunnel recovers), but keep NTP on as before.
- **Forward secrecy (2.10.0, both ends).** The client offers an ephemeral X25519 key in its packets (re-offering
  about once a second until the switch is done; the `frKex` frame is always the last frame of a packet: an older
  peer stops parsing there and never sees it). The server answers with its own key and both derive a fresh session
  key from the PSK plus the X25519 shared secret. Each side
  switches to sending under the fresh key once the other side's packets authenticate with it; until then the old key
  still opens in-flight packets, for a 30 s grace, then it is dropped. After the switch, traffic recorded earlier
  cannot be decrypted even if the key file leaks later. The first RTT or so of a session is still PSK-only — that is
  the window a passive recorder could use. An older peer that never answers gets offers forever, about one a second:
  every 10 s the client re-arms with fresh keys, so an exchange whose replies were lost completes once the path
  recovers. If a switched client hears nothing for 4 s while it keeps sending (the Kharej process
  restarted: its new process cannot open the fresh key, so it could never authenticate the client),
  for the next 10 s it sends a lone PSK-sealed offer about once a second and accepts PSK-key packets,
  so the restarted server re-authenticates the session, sends its boot frame, and a full re-exchange
  completes — streams recover in a few seconds instead of hanging. The data itself stays on the fresh
  key throughout (since 2.10.10), so a server that is alive and only cut off for a while keeps opening it,
  and no user data ever goes out PSK-only after the switch. `WAT_NO_KEX=1` turns the exchange off (A/B tests).
- **Authenticate first.** The server creates a session only if a packet authenticates. Garbage, scans and replays of
  another key are dropped without a response, and packet numbers are tracked, so a captured packet replayed later is
  dropped too.
- **Server checks.** Clients can only reach the target ports on the server's allowlist, and only on `127.0.0.1`.
- **What TLS, wss, h2 and grpc add.** They hide the traffic's shape from a middlebox: it looks like HTTPS, a
  WebSocket or gRPC. They do not add secrecy; the session is already encrypted. With the default self-signed
  certificate the client does not verify the server. The PSK still stops an impostor, because it cannot read or forge
  the session. Set `tls-pin` to also reject a wrong certificate.
- **Shaping and the shaped carriers (3.3.0).** `shape-data`, `noise` and the F19 shaped carriers change only the
  outer bytes, sizes and timing; they add no secrecy and are not interoperable with the protocols whose headers they
  imitate. Padding and noise count in the session totals but not in the per-port counters or quotas; noise spends real
  bandwidth (up to the configured byte rate **per session**), so a traffic quota is not bypassed. See "Spoofing and
  shaping, explained" and "Shaped carriers".
- **What none of this hides.** The server's address, the volume and timing of packets under load, and the fact that
  ICMP or the carrier is in use. Since 3.0.0 no byte of a packet's header is constant and idle packets vary in size
  and timing, but a long-lived, high-volume flow to one foreign address is still visible as such. WatTunnel is not an anonymity tool.
- **Protect the key file.** `chmod 600`, and do not put the key on the command line (`ps` shows it). The manager
  keeps `/etc/wattun` at mode `700` and key files at `600`. **The token contains the key**, so share it privately.
- **Metrics.** Keep `metrics` on `127.0.0.1`. pprof is on the same address.

## Build and test

```bash
go test -race -count=1 ./wat/                                   # simulated-link and loopback tests
GOOS=linux GOARCH=amd64 go vet ./... && GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/wattun
sh build.sh                                                     # dist/ binaries
```

`-race` needs cgo and does not work on a Windows checkout whose MinGW gcc path contains a space (the linker splits
the path). On Ubuntu, CI runs `go test -race -count=1 ./cmd/...` plus a selected `./wat/` subset, now including the
3.3.0 shaping, noise, FEC and client-allowlist tests.

CI (`.github/workflows/ci.yml`) runs `go build`, `go vet`, the `gofmt` gate, the `cmd` and `wat` suites, the shell
syntax checks plus `test-manager.sh`, the DPI self-test, Windows and linux/arm64 cross builds, and the race subset
above. Separate jobs run the tests on real linux/arm64 hardware, compare a few data-path benchmarks against
`bench/baseline.txt` (a catastrophic-regression floor, not a precise benchmark), and run the ICMP/raw-IP tests under
`sudo`, where they do not skip.

Layout: `wat/` is the library (session, congestion control, streams, carriers), `cmd/wattun` the binary,
`cmd/wprobe` a path probe (ships in `dist/` as `wattun-wprobe-<os>-<arch>`). Bump `wat/version.go` for every shipped change, and
rebuild `dist/` (`sh build.sh`). A change that is slower on ICMP is not
shipped.

`cmd/wprobe` is the standalone ICMP path prober for the Iran ⇄ Kharej route: server mode on Kharej, client on
Iran; it measures the reply ratio and loss against rate, packet size and ICMP identifier count. It is not part of the
tunnel, ships in `dist/` as `wattun-wprobe-<os>-<arch>`, and needs Linux + CAP_NET_RAW (root), like the `icmp` carrier.

## Release history

Update **both** servers for every release, unless an entry says otherwise. Versions 2.4.9 to 2.4.16 were steps
toward one fix for CDN tunnels that got slower over time. If you are on any of them, go straight to 2.4.17 or later.

- **3.3.0: full-speed auto mode, safer automatic cleanup, client allowlist, 13 shaped carriers.** Update both ends
  for the shaped carriers; everything else works in any order (no wire change to the existing carriers or frames; the
  new `frPad2` is an ignorable last frame). (1) Auto test measurement is duration-based: screening probes 8 MB each
  way per variant (growing to 16 MB when the measured rate needs more time), the top 3 are re-measured with 16 streams
  for at least 1.5 s each way (20-40 MB each way), and the printed budget now counts tuning too — up to 1184 MB
  (544 screening + 240 finalists + 400 tuning), about 3 min at the manager's conservative 8 MB/s assumption. Tuning is
  reduced to `sessions`/`conns` at fixed 20 MB probes; `mtu`, `win-max`, `batch` and `loss-ceiling` are no longer
  probed. The manager's limits match the engine (sessions 1-16 on one udp/pool carrier, conns 1-64, mtu 256-1400 or
  16384 with pool legs, a bond uses its smallest leg). (2) `fec: auto` is loss-gated: parity while measured loss is
  above `-fec-on-loss` (2 %), stops below `-fec-off-loss` (0.5 %), 2 s dwell; the receiver copies plaintexts only
  while parity is arriving, so a healthy tunnel pays nothing; new `/stats` field `fec_state`. (3) New opt-in traffic
  shaping, both off by default and framed by the new ignorable last frame `frPad2`: `-shape-data PCT` (0-25, budgeted
  realistic sizes, `shape_data_bytes`) and `-noise off|low|med|custom` + `-noise-bps` + `-noise-window` (idle filler at
  a byte budget **per session**, delivered at the configured rate; counts on the host bill and in session totals, not
  in per-port quotas/payload counters; noise alone no longer keeps the 10 s stats line printing). (4) `-state-dir` /
  `-state-save` move the quota/totals state files; the shipped unit now creates `/run/wattun`
  (`RuntimeDirectory=wattun`, mode 0700, `RuntimeDirectoryPreserve=yes`, `ReadWritePaths=/etc/wattun /run/wattun`), so
  the documented tmpfs path actually works and counters survive a service restart (they are still lost on reboot).
  (5) Auto Kharej cleanup: after Iran's pick has been stable for `autoprune` minutes (default 12) the heal pass closes
  the unused **reverse** companion/watchers only by default; the direct `carrier:` list is never rewritten, because a
  bonded Iran client looks like a single leg. Full direct narrowing is opt-in
  (`autoprune-direct=1` in `.manager.conf`, or `auto-prune NAME --direct`). The auto wizard, `auto-ip` and the next
  manager run install the heal timer on a Kharej-only server; if no open carrier works for 3 checks the full token
  plan is reopened (`autowiden`, default 10 minutes, 0 = off). Bond auto-retest is a bond-only setting, default off
  (`bond-retest NAME`). (6) Server-side `-allow-clients` / `-allow-clients-file` restrict holders of the PSK/token to
  the listed addresses/prefixes (direct carriers; the file must be under `/etc/wattun`; a CDN carrier or `-sni` is now
  a startup error instead of a warning; the deny log is globally throttled to 3 lines/s with the suppressed count
  reported). SECURITY.md gains a threat model and TECHNICAL a "Spoofing and shaping, explained" section. (7) 13 shaped
  carriers: raw `sit`, `6to4`, `xfrm-ipsec`, `etherip`, `l2tpv3` (Linux + CAP_NET_RAW) and UDP `fou-gre`, `gue-ipip`,
  `vxlan`, `geneve`, `dnscrypt-udp`, `ntp-direct`, `openvpn-dco`, `srtp-direct`; both ends need 3.3.0 and the same
  name, and they are wattun-internal wire shapes, not real protocol interoperability. A shaped carrier is
  single-carrier only (engine and manager refuse a `+` bond that contains one), and an explicit `-mtu` above the
  shape's ceiling is clamped with a log line (raw tier: `sit`/`6to4` 1360, `xfrm-ipsec` 1392, `etherip` 1384,
  `l2tpv3` 1396; UDP tier 1326-1396). Careful repeated loopback runs put them 0.3-4.5 % below plain udp; single short
  runs scatter more. (8) Manager: Advanced rows for the new keys, gated on a 3.3.0+ engine so a 3.2.1 binary never
  receives a key it rejects; `auto-prune` / `auto-widen` / `bond-retest` commands; a "Spoofing & shaping" help page;
  shaped-carrier support in the unattended/token paths and the interactive picker ("More transports (advanced)");
  the Advanced page grouped as Performance / Shaping & DPI / Safety / State & data, with FEC `a` for the band and
  `win-max`/`loss-ceiling` rows; `delete` stops the unit before removing the state files, so a deleted tunnel's
  quota/totals cannot come back; a coverage test ties every engine key to a UI or file-only path; the self-test ends
  with 802 checks (`MGR_VERSION=2026110403`). (9) Hardening from the same
  audit: the shaped raw carriers check direction and install a BPF filter (a host no longer accepts its own looped
  proto-41/50/97/115 frames), NaN/Inf are rejected by the new float flags, and CI gained an arm64 test job, a
  benchmark regression gate and the new shaping/noise/FEC/allowlist tests in the race subset. (10) Auto now tests
  `gre`/`ipip` by default; an opt-in Kharej `--extended` (both ends 3.3.0) also tests the 13 shaped carriers through
  one hidden single-carrier unit per shape (raw tier Linux+root and cloud protocols 41/50/97/115; old Iran ignores
  them and the default prune closes unused listeners). See "Auto mode", "Shaped carriers (3.3.0)", "Stream padding
  and idle noise (3.3.0)" and "Client allowlist".
- **3.2.1: audit hardening.** Any order of updating works (no wire change). (1) The pool listener reaps connections it never used and caps connections per source address, so an unauthenticated peer can no longer hold every pool slot. (2) An out-of-range peer-reported ACK delay is clamped instead of overflowing the loss timer. (3) The client clears its replay window when the server restarts with a clock behind the previous run, so the tunnel recovers without restarting the client; keep NTP on. (4) The metrics server refuses state-changing cross-site requests. (5) A flag-run server with no allowlist logs a warning (the default is unchanged). (6) `/stats` has flat `rtt_ms`/`streams_total` aliases so a grepped value is not a per-carrier one. (7) The dead "emergency revive" engine is removed. (8) CI, the tag/version gate, the mandatory `openssl`/signature check in `install.sh`, and shipping `cmd/wprobe` in `dist/`. See "3.2.1: audit hardening".
- **3.2.0: fast by default, bounded memory, gre/ipip.** Update both ends for the raw-IP carriers; the rest works in any order. (1) `max-mbps` 16 now applies to the icmp path only, so a server that lists `icmp` among its carriers no longer caps tcp/tls/wss clients at 16 MB/s. (2) Auto sessions are at most 2, and the manager no longer forces 4. (3) Send data is a queue of pooled 64 KB chunks; a process-wide `mem-budget` and a Go heap soft limit at a third of RAM bound memory. (4) A full server evicts the session silent for 10 s. (5) The bond loss penalty is `weight * (1-loss)^4`; new `gre` (IP protocol 47) and `ipip` (protocol 4) raw-IP carriers. (6) The auto test tunes sessions/conns/mtu/batch/loss-ceiling of the chosen carrier. See "3.2.0: fast by default, bounded memory, gre/ipip".
- **3.1.2: cheaper idle tunnel, quiet-client fix.** Any order of updating works (timing only, no wire change). (1) The server's boot-id frame follows `-ping-every` instead of a fixed 1 Hz: 15.3 → 11.0 MB/day per idle session at the default, 8.9 → 4.0 at `-ping-every 20` (measured 2026-10-29). Restart detection is delayed by up to one keepalive interval; keep `-ping-every` at 20 s or less, because `wattun-heal` treats 35 s without a received packet as down. (2) A server whose client went quiet for 20 s keeps its lane set instead of sending nothing at all until the client speaks again. (3) The dead-session reset scales with `-ping-every`, so 40/60 no longer reset every open stream every 30 s. See "3.1.2: idle cost and quiet clients".
- **3.1.1: machine-bound counters, bonded matrix, signed manager.** Any order of updating works. (1) Lifetime traffic totals are bound to the machine that wrote them, so a config copied to a new VPS starts from zero; `wattun-manager reset-traffic NAME` zeroes them on purpose and deleting a tunnel removes its counters and quota files. (2) The anti-censor matrix tests bonds leg by leg, offers only modes the installed binary supports, adds `paws`, and re-measures the top 3 at 20 MB. (3) The manager is shipped in the signed release checksums and verified by `install.sh`. (4) The server ages sessions by authenticated packets only; a captured packet can no longer revive or reopen one. (5) `-sessions` clones keep the `tcp-mimic` hello; each UDP flow pins its session; `-ping-every` is validated and liveness scales with it. See "3.1.1: authenticated session aging".
- **3.1.0: defaults follow the host, two bug fixes.** Update both ends for the first fix (the server hang), any order for the rest. (1) Connections, sessions, window cap and socket low-water mark are chosen from the CPU count and RAM (cgroup limits included): `-conns` and `-sessions` default to 0 = auto, new `-win-max`. (2) The server's receive loop could block for good after the first speed test. (3) Bonded sessions no longer pin bulk streams to a lane that does not exist. See "3.1.0: host-aware defaults".
- **3.0.2: reverse tunnels recycle connections, auto test presets.** Update both ends. (1) `pool-rotate` / `pool-rotate-bytes` now work on the dialing server of a `reverse` tunnel; the manager writes `pool-rotate: 30m` into new reverse pool tunnels (add it by hand to existing ones). (2) The manager's auto test asks for *normal* or *anti-censor* (every desync mode, SNI, TLS fragment, fingerprint and ECH variant) with skip / stop keys. (3) `fake-mode: paws`, `tls-frag: -1`, the nginx web face, a throwaway TLS certificate, h2/grpc receive window 8 MB, `wattun-manager iran-firewall`. See "3.0.2: probing resistance and the PAWS marker".
- **3.0.1: no fixed strings in `ws`/`wss`/`h2`/`grpc` tunnels.** Any order of updating works; an existing tunnel keeps its path until you change it on both ends. (1) The manager gives every new `ws`, `wss`, `h2`, `h2c` or `grpc` tunnel (the auto tunnel too) its own URL path, `/api/` plus 12 random hex digits, instead of the `/wat` every install used: a filter could match `GET /wat` with `Upgrade: websocket` on a plain `ws` tunnel as the signature of this tool. The path travels in the token, so Iran follows by itself. To change a running tunnel set the same `path:` on both ends and restart. (2) The `ws` upgrade request now has a browser's header set in a browser's order (`User-Agent`, `Origin`, `Pragma`, `Cache-Control`, `Accept-Encoding`, `Accept-Language`); before it had no `User-Agent` at all. A header you give with `header:` replaces the default of the same name. Both only matter where the request is visible in plain text (`ws`), or where the path is read after the TLS layer (never by a passive filter). For `tls`, `wss`, `h2` and `grpc` the ClientHello is still the Go library's unless you set `fp: chrome` (or `firefox`, `random`): do that on any route that blocks the server's IP after some minutes.
- **3.0.0: no constant bytes in the packet header, random idle shape, reverse `udp`, DNS-shaped `udp`.** Update both ends for
  reverse `udp`; for the rest any order works. (1) The session id and packet number at the start of every packet are
  masked (`hdr-mask`, default on): a flow classifier no longer sees 8 equal bytes plus a counter in each datagram. An
  older peer is detected and answered in the plain header. (2) Packets without stream data are padded with 0-100
  random bytes and the idle keepalive interval is jittered (`shape`, default on); `frPad` is a new ignorable frame.
  (3) `carrier: udp` supports `reverse: true`: Iran binds and only answers, Kharej sends authenticated punch
  datagrams, so Iran starts no flow towards a foreign address (the model of reverse tunnels such as Backhaul). The
  manager offers it for `udp` in the wizard and under direction. (4) Raw `tcp` opens with a TLS ClientHello-shaped
  hello that carries the authentication and masks the 2-byte frame lengths (`tcp-mimic`, default on; an older peer is
  detected and answered with the plain pool id after 6 s). (5) The manager shows and lets you pick the source address
  (`src-ip`). (6) `udp-dns`: DNS-shaped udp on port 53, which a route that cuts every other UDP flow lets through. (7) A
  client that started before its server no longer stays on the plain header for the session. See "Traffic shape".
  (8) `fake-mode: auto` probes by acknowledged bytes and can pick `none`, `rst`, `synrst` or `seq`; `sum`/`seqsum`
  are refused with `-reverse`; the marker wait follows the RTT and the marker is resent once (see Fake-SNI). (9) Pool
  carriers: byte-bounded queues, an express lane for interactive packets, bulk detection that decays, no lost
  datagrams while the first connection dials, and pool slots after the first dial with a 50-250 ms stagger. (10) New
  keys `batch` and `keep-slow`; `WAT_GSO=1` for udp; `WAT_GRPC_MSG` sets the grpc message size (default 32 KB).
  (11) Manager: `rst-fast` preset, `rst` as the fake-mode default, `synrst` selectable. Kernel echo copies are
  now also rate-limited on **Kharej** for normal ICMP tunnels (before, only on Iran in reverse): Kharej then answers
  at most 10 ordinary pings per second per sender (see Reverse ICMP).
- **2.10.12: fake-SNI fires on every connection, and it works from a reverse server.** Dialer-side fix, no wire
  change. This release also ships 2.10.11, which was never tagged (the duplicate-ACK wait and the 517-byte Chrome
  fake hello). (1) The `TCP_REPAIR` probe read the wrong queues, so the fake used a wrong or missing stream start and fired on
  only one of two pool connections (field test of 2.10.11); fixed. A handshake the sniffer cached before `Wrap` now also
  fires the fake when the socket probe is unavailable. (2) `fake-sni` runs on the dialing end of a `-reverse` tunnel (the
  Kharej server), on tcp, tls, ws, wss, h2 and grpc; the manager's anti-censorship presets allow it. The `tcp` carrier
  gained `TCPClientOptions.DialHook` for this. (3) `Session.Alive` reads the honest authenticated-packet clock, so
  `/stats` `alive` and `/speedtest` no longer show a dead tunnel as alive for 10 s of every 30 s. (4) `filter_profile.mode`
  is empty when no probe ran instead of `seq`. (5) Manager: anti-censor is a toggle, off by default so a tunnel stays the
  plain full-speed one. Tunnel page, `z` (or Advanced, `k`): `1` turns it on with a preset or off again, `w` picks another
  preset (new first choice `cloudflare`: fake `www.cloudflare.com`, `seq`, no churn, the combination field-tested in
  2.10.12), `r` switches normal/reverse, `e` sets any single key (fake-ip, fp, tls-small-ch, conns ...). It runs on the
  dialing end, which is Kharej once a pool tunnel is reverse. CLI: `wattun-manager preset NAME cloudflare|off`.

- **2.10.10: the Kharej-restart probe no longer stalls a live tunnel.** Client-side fix (the Iran server); no wire
  change, works with every 2.10.x server. Since 2.10.1 a client that heard nothing for 4 s sealed **all** its
  traffic with the PSK key for 10 s, in case the Kharej process had restarted. When the server was alive and only
  cut off (a one-way blackout, an ICMP reroute) and its 30 s old-key grace was over, it dropped every one of those
  packets: up to 10 s of extra stall after the path came back, and the data had no forward secrecy. Worse, the
  probe cleared the key-exchange state for good, so after one false alarm a later real Kharej restart hung the
  session until the Iran service was restarted. Now the probe is a lone PSK-sealed offer once a second, data stays
  on the fresh key, and the state survives, so the next restart is still detected. The probe also starts only when
  the client has sent something 4 s after the last packet it heard, so an idle tunnel with `ping-every` of 4 s or
  more is not probed forever. Regression test `TestKexFalseProbeThenRestart`.
- **2.10.2: anti-censor matrix tester, ECH lock contention fix, and transport resilience.** Client-side
  reliability update, fully backward-compatible with 2.10.x servers.
  (1) **Autonomous anti-censor matrix tester**: `wattun-manager matrix NAME` tests every resilience combination
  (`base`, `seq`, `seqsum`, `sum`, `ttl`, `rst`, `auto-probe`, ECH ladder across allowlisted SNIs) entirely
  from the Iran server using throw-away clients, ranking and applying the best working combination without
  requiring SSH access to Kharej.
  (2) **ECH ladder concurrency**: `echState` no longer holds `s.mu` across blocking network lookups (4 s DoH race +
  6 s tunnel relay), eliminating pool dial stalls during cold boots or network blips.
  (3) **HTTP carrier Host fallback**: When `-host` is omitted, `HTTPClientOptions.host()` now defaults to
  `TLS.ServerName` instead of raw peer `IP:port`, preventing Cloudflare edge host rejections.
  (4) **Desync link-layer support**: `parseEthIPv4` now decodes raw IPv4 (tun/wg), 802.1Q VLAN tags, and Linux SLL
  cooked headers alongside standard Ethernet frames.
  (5) **Capabilities and daemon stability**: `install.sh` systemd template retains `CAP_NET_BIND_SERVICE` and
  `CAP_NET_ADMIN` alongside `CAP_NET_RAW` for port 53 and TCP sequence probes. Manager deduplicates `ech:` config
  lines to prevent daemon boot crashes.
- **2.10.1: the audit round after 2.10.0.** Both ends benefit; no wire change, old and new peers interop either
  way. A five-reviewer sweep of the tree (19 findings) plus the first `-race` run of the `wat/` suite.
  (1) **Kharej restart recovery** (a 2.10.0 regression): a switched client that hears nothing authenticated for
  4 s seals and accepts PSK-keyed packets for 10 s and keeps offering, so a restarted (PSK-only) server
  re-authenticates the session, sends its boot frame and the exchange completes — streams recover in seconds
  instead of hanging for good.
  (2) **Key exchange**: the client re-arms with fresh keys after its 10 s give-up instead of staying PSK-only for
  the session, and the server's fresh key expires when the offers stop (before: one failed AEAD open per packet
  for the session's lifetime).
  (3) **Fake-SNI and the probe**: `fake-mode: auto` can now pick `sum` (its verdict keyed on a recheck that made
  the case unreachable); each fire synthesizes a fresh ClientHello instead of replaying one byte-identical copy
  per peer, and the seqsum marker's 1 ms gap no longer sleeps under the sniffer's lock.
  (4) **Pacer and governor**: the no-estimate ramp respects `-loss-ceiling` and the governor's ceiling, and the
  governor's rate history is trimmed by age, so the reroute ceiling is learned on fast paths too.
  (5) **`cmd/wattun` robustness**: `-map` targets are range-checked, a malformed FEC length varint can no longer
  panic the process, the built-in DNS relay works under the default allowlist, per-port state files are written
  by one goroutine at a time, the drain exit saves quota, and oversized DNS queries are dropped rather than
  truncated.
  - [Security model](#security-model).
- **2.10.0: forward secrecy — X25519 key exchange on every session.** Both ends need it for the new protection;
  old and new peers interop either way. Inside the existing encryption the two ends run an ephemeral X25519
  exchange: about one RTT into a session both sides switch to a fresh session key derived from the PSK plus the
  X25519 shared secret, and from then on a later leak of the key file does not decrypt the traffic recorded before
  the switch. Until the switch (and entirely with an older peer) the session is PSK-only, as before. No config
  change; `WAT_NO_KEX=1` turns the exchange off for A/B tests. The offer frame (`frKex`) is ignorable by older
  peers, so the wire stays compatible in both directions.
  Scripts (served from `main`, no tag needed): `install.sh` now fails closed — a download with no checksum file,
  or whose RSA-signed checksum list does not verify against the public key baked into the script, is refused
  (proxy mirrors are untrusted); the shipped systemd unit drops to `CAP_NET_RAW` only and adds the usual
  filesystem/namespace hardening. `wattun-manager` warns when a Kharej tunnel is created without a port allowlist,
  points at `tls-pin` for the TLS-family carriers, and takes the public IP from the interface first (third-party
  lookup only when the address is NAT'd).
  - [Security model](#security-model).
- **2.9.0: filter probe + auto fake-mode, ICMP volume governor, ECH bootstrap ladder.** Client-side probe and
  pacer logic, one small server-side addition (the DNS relay below). No wire format change: old peers interop
  in both directions.
  (1) **`fake-mode: auto`** — the client measures the filter once at startup with two throwaway markers on one
  throwaway connection and picks `seq`/`sum`/`seqsum` from which marker the flow survived; verdict in the log
  and as `filter_profile` in `/stats`. Failure degrades to `seq`. Not yet field-validated: treat the verdict
  as a hint.
  (2) **`-governor` (opt-in)** — learns an ICMP path's volume ceiling from the reroute signature (base-RTT jump
  after sustained bulk, the field's 40 → 76 ms) instead of the hardcoded 16 MB/s default: ceiling = 80 % of the
  pre-jump rate, 60 s hold, 2 % per quiet window creep, released at 1.25× the trigger. Never raises the rate;
  the sim tests' pacer pins are untouched.
  (3) **`ech: ladder`** — when every direct DoH server is unreachable, the ECH config lookup goes through a
  built-in server-side DNS relay (stream target port 53, the speed-test pattern): raw DNS query in, one UDP
  exchange with a recursive resolver on the Kharej side, answer back. Old server: port 53 is just a failed
  local dial, the ladder falls back to no ECH. Both ends need 2.9.0 for the relay rung.
  (4) **`fake-mode: rst`** — an in-window RST|ACK marker with a damaged checksum: a stateful middlebox
  clears the flow, the server kernel drops it before reading the flags (see Fake-SNI desync).
  Also in 2.9.0 (manager, from `main` without a tag): the `wattun blackout NAME [SNI]` one-command enable and
  the Diagnose/heal pointers to it (see the 2.8.2 entry).
  - [fake-mode auto](#fake-sni-desync-whitelisting-survival) · [governor](#icmp-path-limits-and-pacing) ·
    [ECH ladder](#ech-bootstrap-ladder-290-ech-ladder).
- **2.8.2: manager — `wattun blackout`, kit stays off the default flow.** Manager only (`MGR_VERSION`
  2026102002/2003), no client or wire change. (1) New command `wattun blackout NAME [SNI]`: the
  blackout moment is the wrong moment for five questions, so it asks one thing — the allowlisted name
  — and writes `fake-sni` + `fake-mode: seq` + auto ttl (pool-rotate stays off; tune later in Advanced
  settings). (2) Diagnose points at it when a direct pool carrier's TCP port is reachable but the
  tunnel cannot connect (the SNI-allowlist tell), and the heal timer logs the hint after restarts do
  not fix the tunnel. (3) The resilience block stays off the plain wizard flow (one explicit question,
  Enter = skip); unattended flags and profiles prefill it as before.
  - [Fake-SNI desync](#fake-sni-desync-whitelisting-survival) · [manager commands](#managing-tunnels).
- **2.8.1: byte-axis churn, fake-SNI on TLS carriers, manager resilience profiles.** Client-side only, server
  unchanged, no wire format changed. (1) New `pool-rotate-bytes`: recycle each healthy pool connection after this
  many bytes handed to its socket, alone or on top of `pool-rotate`; the byte budget is jittered like the time
  budget and whichever limit hits first recycles. (2) `-fake-sni` now fires on the `tls`, `wss`, `h2` and `grpc`
  carriers too: the desync layer unwraps the TLS/framing wrapper instead of requiring a bare `*net.TCPConn`.
  (3) `Clone` carries the fake-SNI dial hook, so the second and later sessions keep it. (4) The sum-mode mirror
  base is now per connection: two pool connections opening at once no longer cross-set each other's base.
  (5) `wattun-manager` collapses fake-SNI and churn into one resilience block (Iran wizard and Advanced
  settings), adds `profile save/list/show/del/apply` to re-apply a working combination after a reinstall, and
  accepts `--fake-mode seqsum`, `--pool-rotate` and `--pool-rotate-bytes` unattended. The unattended
  `--fake-sni`, `--fake-mode` and `--fake-ttl` flags were parsed as unknown options before and never worked.
  - [Fake-SNI desync](#fake-sni-desync-whitelisting-survival) · [the flags and config keys](#command-line-flags).
- **2.8.0: connection churn, dual-marker mode, checksum fix.** Client-side only, server unchanged, no wire
  format changed. (1) New `pool-rotate`: recycle each healthy pool connection after a jittered lifetime budget
  (±40 % per connection, re-rolled on every recycle), so no single flow shows a months-stable lifetime to a
  behavioral classifier — the field's strongest detection tell after raw volume. (2) New `fake-mode: seqsum`
  (experimental): both the seq and the sum marker per connection, ~1 ms apart, so a filter must discard both
  correctly. (3) Fixed the sum-marker checksum damage: the old `(checksum ^ 1) - 1` formula is an identity for
  every even checksum, so about half of the sum-mode markers shipped with a fully VALID checksum and the server
  would have accepted their payload as real stream data (flow corruption). It is now `checksum - 1` with a wrap
  guard. **If you run `fake-mode: sum` on 2.7.x, update the client.**
  - [Fake-SNI desync](#fake-sni-desync-whitelisting-survival) · [pool-rotate](#config-file).
- **2.7.1: fake-SNI `sum` mode, probe fix, manager support.** Three client-side fake-SNI changes, server
  unchanged, no wire format changed. (1) New `fake-mode: sum`: the marker mirrors the first data segment in-window
  (same seq/ack) with a damaged TCP checksum — for filters that validate TCP sequence numbers, where `seq`
  fails; server kernels drop the marker at checksum validation. Dies behind checksum-validating NATs. (2) Fixed a
  probe off-by-one: the ISN probe (`TCP_REPAIR`) reports SND.NXT = ISN+1 right after the handshake, and `Wrap`
  announced it as the ISN, putting the `seq`-mode marker one sequence number too high (the server would have seen
  it as in-window). The tests pinned the wrong relation too; both are corrected. (3) `wattun-manager` now offers
  fake-sni in the Iran wizard and Advanced settings (`--fake-sni/--fake-mode/--fake-ttl` unattended).
  - [Fake-SNI desync](#fake-sni-desync-whitelisting-survival).

- **2.7.0: fake-SNI hardened, more carriers.** The fake-SNI desync (2.6.0) now anchors the marker packet to the first
  outbound packet it can observe (handshake final ACK or first data segment) instead of requiring the sniffer to
  have seen the whole handshake — the 2.6.0 sniffer only fired when the SYN landed after `Wrap` announced the
  connection, so on most dial orders it silently timed out unclassified. The injector also follows a NAT that
  rewrites sequence numbers uniformly (the marker stays below the stream start as the server sees it), auto-learns
  the TTL for `fake-mode: ttl` (`fake-ttl: 0`, the default, calibrates from the peer's SYN-ACKs), and now applies
  to the `wss`, `h2` and `grpc` carriers too. Client-side only, Linux + CAP_NET_RAW; the server is unchanged and
  no wire format changed.
  - [Fake-SNI desync](#fake-sni-desync-whitelisting-survival).

- **2.6.0: fake-SNI desync for the permit-list regime.** When a filter permit-lists flows by their TLS ClientHello
  name (the 2026 whitelisting, where only a handful of Iranian sites' HTTPS passes), the tcp and tls carriers can
  now inject one raw extra ClientHello carrying an allowlisted SNI right after the TCP handshake of every pool
  connection. The DPI classifies the flow as TLS to an allowed site; the server never receives the marker (it
  carries a sequence number below the stream start, or a TTL that expires at the filtering hop), so the session flows
  on as if it were that TLS connection. Only the Iran client needs the new version (client-side only, Linux, needs
  CAP_NET_RAW like the icmp carrier); the Kharej server is unchanged and no wire format changed.
  - New client keys: `fake-sni`, `fake-mode` (`seq`, default | `ttl`), `fake-ttl`.
  - Works where the ISP's NAT does not normalize sequence numbers before the DPI (field reports of the same
    method in other tools: it died on some ASNs after days; the allowlisted SNI itself must pass from your ISP).
  - [Fake-SNI desync](#fake-sni-desync-fake-sni-260).

- **2.5.1: faster download.** The receiving end kept re-growing and re-copying each stream's buffer. On a 2-core Iran
  server, that took about a quarter of the tunnel's CPU during a download. Received data now goes into reused 64 KB
  chunks, and the sending side no longer copies its whole buffer on every write.
  - Test tunnel: download went from 53-71 to 65-116 MB/s, and memory stayed flat (149-161 MB).
  - Production tunnel: download went from 53 to 157 MB/s, and to 195 MB/s (~1.6 Gbit) on a 2 GB run. Upload went
    from 150 to 276 MB/s.
  - `/speedtest` accepts `mb` up to 256 × `streams`.
  - Mixed versions work. [Details](#cheaper-stream-buffers-251)
- **2.5.0: one tunnel is no longer capped near 50-60 MB/s.** On a direct TCP pool (tcp, tls, or any reverse pool),
  every acknowledgement walked every packet in flight. Now each acknowledgement touches only the packets it covers.
  The pool also sends 16 KB datagrams instead of 4 KB, and acknowledges less often.
  - Production: upload went from 49-55 to 149.7 MB/s. Download stayed at 53 MB/s, limited by the Iran CPU (fixed in
    2.5.1).
  - Also new: WireGuard and other big UDP packets pass every carrier (split and rebuilt inside the tunnel), traffic
    totals survive restarts, a Windows binary (`wattun-windows-amd64.exe`, no ICMP), and **m** on a tunnel's page
    changes its connection type or joins several.
  - [Details](#one-session-no-longer-capped-250)
- **ICMP: bigger packets, a setting change (no update needed).** Since 2026-10-12 the Iran ⇄ Europe route passes full
  1500-byte pings again. Set `mtu: 1400` on **both** ends and keep the same 30 MB/s cap:
  - Kharej resends 0.3-0.8 % of its packets instead of 3-5 %.
  - Download went from 22-24 to 27.5 MB/s, and upload from 21-22 to 26 MB/s.
  - Ping stayed at ~41 ms under load.
  - [Details](#icmp-path-limits-and-pacing)
- **2.4.18: TCP pool tunnels 2-4x faster.** For tcp, tls and every reverse pool carrier (no CDN in between).
  - On the reverse tcp test pair, upload went from 12 to 47-56 MB/s. Download went from ~20-30 to 49-51 MB/s with 8
    connections, and up to 69-74 MB/s with `conns: 16`.
  - Pool sockets use BBR (`tcp-cc`).
  - Packets that arrive late are acknowledged instead of sent again: needless resends per 200 MB fell from 61-82k
    to under 2k.
  - `/stats` gained `pool_conns`.
  - [Details](#direct-pools-2418)
- **2.4.17: no more leftover connections.** When a user's connection closed while data was still on its way, the
  tunnel kept it open inside. After a load test, an Iran server held 69-76 of them, and its RAM grew from 40 to
  159 MB in 36 minutes. They are now cleaned up when the connection closes.
- **2.4.16: CDN speed holds over time.** On a test tunnel through Cloudflare, the round trip stayed at 109-116 ms
  against an 86 ms base, and speed tests reached 22.6-32.4 MB/s up.
- **2.4.15:** fixes single-connection uploads that 2.4.14 could stall and reset.
- **2.4.12 to 2.4.14: the window stays bounded.** On a busy CDN connection, the tunnel's queue used to grow without
  limit: it measured a 550 ms base round trip instead of 108. It now drains briefly every 8 seconds to measure the
  real base.
- **2.4.11: CDN pacing by delivery rate.** On an emulated CDN link, a single connection went from about 1 MB/s to
  5-7 MB/s.
- **2.4.10: diagnostics.** A `cc` block in `/stats` shows what holds the sender back.
- **2.4.9: late is not lost.** A packet that TCP delivers late through a CDN is no longer resent and read as
  congestion.
- **Manager:** when you create a `wss`, `grpc` or `h2` tunnel on Iran with the Kharej server's IP as the address,
  the manager warns that the traffic does not go through Cloudflare.
- **2.4.8: less RAM per user connection.** Idle connections keep 4 KB copy buffers instead of 32 KB. If you set
  `GOMEMLIMIT`, give it at least twice the tunnel's normal memory.
- **2.4.7: CDN connection health.** A CDN connection that delivers far less than the others is replaced.
- **2.4.6: RAM stays low.** On a production CDN tunnel with about 250 user connections, the Iran server went from
  about 1 GB to about 100 MB.
- **2.4.5: no more stuck CDN connections.** Sustained production downloads went from 30 to 43-45 MB/s.
- **2.4.4: CPU fix** for 2.4.3, which burned 40-73 % per thread on slow readers.
- **2.4.3: less RAM for slow users.**
- **2.4.2: CDN downloads no longer collapse.** Sustained downloads went from 39 to 50 MB/s on average.
- **2.4.1:** TCP-based and CDN tunnels no longer slow to a crawl under bursty web traffic.
- **2.4.0:** stream windows tune themselves.
- **2.3:** several sessions per tunnel (default 4 for TCP-type carriers).
- **2.2:** CDN mode through Cloudflare with ECH.
- **2.1:** Auto mode.
- **2.0:** reverse ICMP.

## License and attribution

WatTunnel is released under the MIT License (see [LICENSE](../LICENSE)). It uses `golang.org/x/crypto`, `golang.org/x/net` and
`golang.org/x/sys` (BSD-3-Clause).

Ideas, not code, come from several projects. GOST (MIT licensed) is the comparison baseline and the reference for what a
forwarding tool should offer. Backhaul and BackPack were studied as benchmarks and
for feature ideas; no code from them is copied. The ICMP engines we compared against (pingtunnel, Hans, ptunnel-ng) are
their own projects.
