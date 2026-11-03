# Plan: fast by default, 2 Gbit/s, no OOM (2026-11-03)

Goal: a tunnel created by `wattun-manager` with default answers runs at the speed the link allows (~2 Gbit/s on the
test pair), never runs out of memory, and gains the GRE/IPIP carrier and the bond loss penalty.

Test pair: Iran 185.84.158.216 (2 vCPU E5-2699A, 1.9 GB RAM) and Kharej 85.155.230.20 (2 vCPU Xeon Gold 6138,
3.8 GB RAM), RTT 76-80 ms, wattun 3.1.2.

## 1. Why tunnels come out slow

1. **A 16 MB/s cap on every auto tunnel.** `wattun-manager:2675` (`write_auto_server`) always writes
   `carrier: icmp+<the rest>` for the Kharej server. `cmd/wattun/main.go:275-279` then sets `max-mbps` to 16 for the
   whole process when `icmp` is among the carriers. That cap is per session and covers every carrier, so tcp, tls and
   wss clients are held to 16 MB/s per session downstream too. Both live Kharej services log `max 16 MB/s`. The cap
   is there to keep ICMP under Iran's ~30 MB/s reroute threshold, and it should only touch ICMP traffic.
2. **Sessions used to get around the cap make it worse.** The manager's `sessions_line` (`wattun-manager:2514`) forces
   `sessions: 4` for pool carriers, the `rst-fast` preset forces 4 sessions x 4 conns, and the tunnel on the test pair
   was created with 8. Measured: 2 sessions 193-248 MB/s, 1 session 159, 8 sessions **68**. Each session has its own
   delay-based pacer, so each one reads the others' queueing as congestion and backs off.
3. **The manager's own prompts say "default 16".** Lines 1599, 2261, 4932 and 6106 advertise 16 MB/s as the default
   ceiling for every carrier.
4. **Memory has no limit.** Each stream's send buffer is one contiguous array that grows to 2 x `sendCap` (up to
   32 MB, `Stream.makeRoom`, `wat/stream.go:585`), and nothing caps the total. Results: the Kharej test server was
   OOM-killed at 2.7 GB (32 sessions), the Iran client at 932 MB (8 sessions x 16 conns). One client at full speed
   takes a server to 1-2.2 GB. Memory of dead sessions is freed only after the ~60 s idle timeout.
5. **A third of the CPU is copying.** Sending side: `memmove` 28 % + memclr 7 % (from `makeRoom` growth), seal 29 %,
   syscalls 16 %. Receiving side: syscalls 24 %, open 24 %, `memmove` 17 %, memclr 8 %. A 2-vCPU box runs out of CPU
   before 2 Gbit/s in both directions.
6. **Upload is half of download.** tcp 112 MB/s and tls 123 MB/s up, while raw TCP does 1.2 Gbit/s (8 streams) to
   3.4 Gbit/s (32 streams) up.
7. **One stream is capped at 67 / 49 MB/s.** The window allows ~200 MB/s at 80 ms. A real user is one big flow.
8. **The udp carrier wastes packets on shaped paths.** It had 83k retransmits in one test on a path that drops UDP
   above ~270 Mbit/s: delay-based cc ignores loss by design.

**Measured with the cap and the extra sessions out of the way** (test server without icmp, 2 sessions, 16 streams):
tcp 248 MB/s down (1.98 Gbit/s) / 112 up; tls 196 / 123; wss 169 / 65; udp 19 / 37; one stream 67 / 49. The raw link
(iperf3) does ~2 Gbit/s sustained on 16 TCP streams; UDP is shaped to ~270 Mbit/s.

## 2. Steps

Every step: `go test ./cmd/... ./wat/` and `go test -race ./wat/` green, ICMP sim bounds unchanged (CLAUDE.md
"Performance"), measured on the pair with the step 0 script, version bumped. New frames stay ignorable by older peers
(CLAUDE.md "Wire compatibility"). Release when the owner says so.

### Step 0. Bench script
`bench/pair.sh IRAN KHAREJ`: starts throw-away server and client on spare ports with a temporary key. Runs
`/speedtest` per carrier (down/up; 16 streams and 1 stream; 10 s and 60 s) and samples RSS and CPU on both ends. Saves
pprof heap/cpu, prints one table, kills everything it started. It waits on explicit PIDs: a bare `wait` after starting
wattun hangs.

### Step 1. ICMP cap only on ICMP (cause 1)
- Engine: the 16 MB/s default applies per session by its carrier. An icmp session (or a bond's icmp path) gets 16; a
  tcp/tls/ws/wss/h2/h2c/grpc/udp session gets 1250. On a bond, the icmp path's share is limited in the path scheduler
  (`wat/paths.go`), not the whole session.
- An explicit `max-mbps` keeps working as today.
- Old Kharej servers fix themselves on update: no config change needed.
- Test: a server with `carrier: icmp+tcp` serves a tcp client above 16 MB/s in a `cmd/` test; the ICMP sim is
  unchanged.

### Step 2. Fast defaults in the manager (causes 2, 3)
- Stop writing `sessions:` by default (`sessions_line`): the engine's auto value is used.
- Change the engine's auto value: 1 session for direct tcp/tls until step 4 lands; keep CDN paths at what the matrix
  measures.
- Drop the `rst-fast` preset's forced 4 x 4.
- The anti-censor matrix measures sessions 1/2/4 and conns 8/16/32 on the winning carrier and writes the best.
- Fix the four "default 16" prompts: "default: no cap (16 for ICMP)".
- Audit every creation path (Kharej auto server, Iran client from token, reverse, `--pick bond`, presets,
  non-interactive flags). A tunnel made with default answers on the pair reaches step 1's numbers.

### Step 3. Memory budget (cause 4)
- Replace the contiguous send buffer (`sroot`/`sbuf`, `makeRoom`) with a queue of pooled 64 KB chunks, like `rdQueue`
  (2.5.1). No growth copies and no zeroing; acked chunks go back to the pool.
- Process-wide byte budget, default min(25 % of RAM, 768 MB), key `mem-budget`. It is split over active streams, and
  each stream's window and `sendCap` are clamped to its share.
- Free a session's buffers ~5 s after its last pool connection is gone, not after the idle timeout.
- Test in `wat/`: 32 sessions x 16 streams with a slow reader keeps the heap under the budget.

### Step 4. Sessions that share one pacer (cause 2)
All sessions of a client to one server share one rate estimate and split it by queue length, so they stop reading
each other's delay as congestion. Target: 8 sessions >= 1 session. Sessions can then come back as the default where
the path likes many flows (CDN).

### Step 5. Less copying and fewer syscalls (cause 5)
Batch pool writes (one `writev`/flush per scheduler round), batch reads, and test `mtu` 16384 as the tcp/tls default
(fewer seals per byte). Target: <= 1.2 cores on Iran at 250 MB/s down.

### Step 6. Upload (cause 6)
Profile the Iran sender during `dir=up`. Scale pool conns for the upload direction (raw TCP went from 1.2 to
3.4 Gbit/s from 8 to 32 streams). Target >= 200 MB/s up.

### Step 7. One stream (cause 7)
Trace window growth (`tuneWindow`), `sendStage` (256 KB), and how one stream's packets spread over pool conns. Target
>= 150 MB/s for one stream.

### Step 8. udp carrier on shaped paths (cause 8)
When retransmits stay above ~10 % of packets for several seconds, the udp carrier (not icmp) turns `loss-ceiling` on
by itself, and turns it off again when loss drops.

### Step 9. GRE/IPIP carrier
- New carriers `gre` (IP proto 47) and `ipip` (proto 4), file `wat/carrier_rawip_linux.go`. It follows
  `icmp_linux.go`: one raw socket (`ip4:47` / `ip4:4`), client `PacketIO`, server `RawIO` demultiplexed by session id,
  same sealing.
- `gre`: a valid 4-byte GRE header (proto 0x0800) plus a valid inner IPv4 + UDP header around the sealed packet, so it
  parses as GRE carrying UDP. `ipip`: an inner IPv4 + UDP header, the same way.
- `Profiled` hints: MTU 1400 minus 28/24 bytes of headers; uncapped by default (not ICMP).
- Both need root and Linux, like icmp. They join bonds (`carrier: gre+tcp`). The manager's matrix tests them as
  direct candidates.
- Evidence it is worth it: a user's ctunnel run had every UDP method dead while gre/ipip/xfrm passed at
  ~1.1-1.2 Gbit/s.
- Wire: a new carrier, so no frame change. Both ends need this version; this is noted in `docs/TECHNICAL.md`.
- Tests: a loopback raw-socket test on Linux (skipped when not root), plus the bond tests with a `gre` path.

### Step 10. Bond loss penalty
- `weight()` in `wat/paths.go:332` uses `w * (1 - loss)`, so a carrier with 10 % loss keeps ~90 % of its share and
  keeps feeding retransmits. Change it to `w * (1 - loss)^k` with k ~ 4 (10 % loss gives 66 % of the share, 20 %
  gives 41 %), and move a path to suspect when its loss EWMA stays above ~30 %.
- Balanced mode slow after an Iran restart (user report): log `/stats` carriers for 2 minutes after a restart. If the
  share (`p.w`) and revive ramp warm-up is the cause, start new paths at the median share of the live ones.
- Bond only: the single-carrier ICMP path is not touched.
- Test: a `wat/` bond sim with one path at 15 % loss shows its share falling and total goodput rising against the
  current weight.

### Step 11. Smaller items
- **IPv6:** let udp/tcp/tls take `[v6]:port` and test it on a v6 pair (the new Kharej has IPv6, Iran does not).
  icmp stays v4.
- **Docs:** `docs/TECHNICAL.md`, `README.md` and `README.fa.md` get the new defaults and the measured numbers from
  this pair.
- **Telegram replies** (no code): padding/jitter exist since 3.0.0; interactive packets already ride the lowest-RTT
  carrier; `quota.json`/`totals.json` is one small write each per 30 s; CDN failures: check the proxied domain,
  Cloudflare port, origin, and `fake-mode: rst`.

## 3. Order and done

Order: 0, 1, 2 (fast defaults: biggest gain for every user), then 3 (OOM), 4, 5, 6, 7, then 9 and 10, then 8 and 11.

Done when, on the test pair, a tunnel created with default answers gives:
- tcp/tls >= 250 MB/s down and >= 200 MB/s up, sustained 60 s;
- one stream >= 150 MB/s;
- no OOM with 32 clients, server RSS under the budget;
- gre/ipip working direct and in a bond;
- a lossy bond path losing its share within seconds;
- all tests green and the ICMP sim unchanged.

Limits: ICMP stays at 16 MB/s per session (Iran reroutes above ~30 MB/s), and UDP is shaped to ~270 Mbit/s on this
path. The 2 Gbit/s target is for tcp/tls/wss/gre/ipip.
