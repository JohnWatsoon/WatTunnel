# Plan: speed fixes and own carriers (after 3.3.6)

Source: Fable's 7 ideas (2026-11-14), checked against the 3.3.6 code. Nothing here is measured yet. Order is
"cheapest decision first": field kill tests, then engine fixes every datagram carrier needs, then new carriers only
where a kill test said yes.

## Code check of the claims

| Claim | Code | Verdict |
|---|---|---|
| Direct pools keep ~1 s in flight | `wat/cc.go:116` `relDirectWin = time.Second`, used at `cc.go:646` | True. Explains 383-414 ms RTT under upload on an 81 ms route |
| udp sends one syscall per datagram | `wat/batch_linux.go:29` batching off unless `WAT_BATCH` set (on only for ICMP); GSO needs `WAT_GSO=1` (`:153`) | True |
| AEAD seal under `s.mu` | `wat/session.go` send loop calls `s.build()` up to 160 times inside `s.mu.Lock()` | True: `build()` calls `s.seal(p)` (`session.go:1109`) |
| Server receive is one goroutine | `wat/server.go` `Server.run()` reads `srv.raw.Recv()` in one loop | True |
| Bond might already do Split | `wat/bond.go` `Send` picks a path per packet on each end on its own; paths are keyed by carrier name (`-peer-<carrier>`) | Partly. Each end already chooses its own send path, but liveness/ACK feedback assumes every path is two-way, and one carrier name cannot appear twice (no icmp+icmp to 2 IPs) |
| Sessions share no pacer | each `Session` owns its `cc` | True (old 2 Gbit/s plan Step 4, plan file no longer in the repo) |

## Phase 0: field kill tests (no new binary)

Run on the filtered Iran/Kharej pair. Each one kills or keeps an idea.

1. **ICMP-wide.** Two ICMP tunnels to two Kharej IPs, 20 MB/s each (`-max-mbps 20`). Then one tunnel `-icmp-type
   echo` plus one `-icmp-type timestamp` to one IP, 20 each. Reroute still fires at ~30 MB/s total: idea dead.
   Holds in one case: note which (per IP pair, per destination IP, per type).
2. **IPv6.** Only if both servers have v6. `ping -6` flood at ~40 MB/s and a plain UDP6 stream Iran to Kharej.
   Note if the 30 MB/s line and the 3-datagram cut exist on v6.
3. **Spray probe.** Needs a ~20-line tool (`bench/` or a `wattun` hidden subcommand): 3 datagrams on each of 50
   source ports, receiver counts arrivals. ~150 arrive: cut is per 5-tuple, keep Spray. ~3 arrive: cut is per IP
   pair, drop Spray.
4. **udp batch/GSO.** Same pair, plain `udp` carrier: default, `WAT_BATCH=1`, `WAT_BATCH=1 WAT_GSO=1`. MB/s and
   CPU per MB. Baseline: tunnel 578 Mbit/s, raw UDP ~1280, tcp 1057.

## Phase 1: engine fixes (help every datagram carrier, ICMP included)

Do these before any new carrier: Phantom and Spray sit on this same path and would inherit the limits.
ICMP sim tests in `wat/` must stay green with unchanged bounds.

1. **Seal outside `s.mu`.** `build()` only frames under the lock; the AEAD seal runs after `Unlock` on the batch.
   Packet number and nonce stay assigned under the lock. Test: existing suite plus a benchmark of receive-side lock
   wait under bulk send.
2. **Server receive fan-out.** `Server.run()` keeps the read; the session lookup by id and the copy move to N
   workers sharded by session id (keeps per-session order). Only helps when CPU-bound (field: ~1.8 of 2 cores).
3. **udp batching on by default** if Phase 0.4 shows a gain; GSO default only if it was measured on the field.
   Change is the `batchDisabled()` default plus the docs.
4. **Direct-pool window.** Replace the flat 1 s `relDirectWin` with a cap from measured srtt (e.g.
   `maxBW x min(2 x srtt, minRTT + 200 ms)`), and check the 2026-10-16 case (Kharej to Iran, 6-14 % retransmits,
   78 MB/s bare TCP) still fills. `loss_test.go:443` pins the current window and will need its bound re-derived,
   not loosened. Field test: RTT and MB/s during a 16-stream upload, before and after.
5. **Shared pacer across sessions** (old Step 4). One rate estimate per process for all sessions to one peer,
   split by queue length. Field target: 1/2/4/8 sessions no longer 176/261/147/68 MB/s, more sessions never slower.

No frame change in this phase; one end can update alone.

## Phase 2: carriers, gated by Phase 0

Order is Fable's ranking, minus anything Phase 0 killed.

1. **ICMP-wide** (Phase 0.1 says yes). Let a bond hold the same carrier more than once: icmp to 2-4 Kharej IPs, or
   icmp echo + icmp timestamp. Needs per-instance names in `bond.go`/config (`-peer-icmp` is one value today) and a
   per-path rate cap under the reroute line. Server: one raw socket already sees every type; check `RawIO` for
   several local IPs. Both ends on the new version only if the server side needs a change.
2. **Coded downlink.** Sliding-window repair (not the per-block XOR in `fec.go`) from Kharej, Iran sends a few
   status packets per second instead of per-packet ACKs. New frame type, last in packet, ignored by old peers;
   feature negotiated, both ends new. Kill test: p99 of a small interactive stream beside a bulk download on ICMP,
   coded vs today.
3. **Phantom (ptcp).** Raw-socket fake TCP: handshake, moving seq/ack, timestamps, mimic ClientHello as first
   flight; reverse from day one (Kharej sends SYN). Installer adds the RST-drop firewall rule (and removes it on
   uninstall). New carrier, no frame change. Test: same pair, ptcp vs tcp, MB/s both ways and RTT during a
   16-stream upload. Start after Phase 1.1-1.3.
4. **Spray** (Phase 0.3 says per 5-tuple). Source-port hopping every 1-2 packets on udp, then inside Phantom.
   Watch for scan-like blocking: cap new flows per second.
5. **Split.** A send-only bond leg: a path that carries data one way and needs no return traffic on itself, with
   its liveness taken from the session's ACKs arriving on another path. Plus reverse for the raw tier. Test:
   download MB/s against the best reverse tunnel on the filtered pair.
6. **Phantom offload** (AF_PACKET + `PACKET_VNET_HDR`). Only after Phantom wins somewhere; little gain expected on
   the Iran e1000 card.
7. **IPv6 carriers** (Phase 0.2 says yes): v6 for icmp and udp first.

Not doing: more raw protocol numbers (SCTP, DCCP, UDP-Lite), QUIC-shaped UDP/443. No fix in our code for the
Iran e1000 NIC; the provider must switch it to virtio.

## Release

No tag per item (owner releases on request). Every binary change bumps `wat/version.go`; wire-changing items
(coded downlink, ICMP-wide if the server changes) state the needed version in code and `docs/TECHNICAL.md`.
