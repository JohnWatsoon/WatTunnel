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

## Order (owner, 2026-11-14)

ICMP is not a priority: no ICMP-wide test. Order: fast field test (Spray, Phantom, IPv6) -> engine/speed fixes ->
Phantom and Spray carriers -> manager + auto test.

## Phase 0: fast field test (`bench/fieldprobe`)

One static tool, both roles, about 40 s per direction and family. Build: `GOOS=linux CGO_ENABLED=0 go build -o
fieldprobe ./bench/fieldprobe`. Needs root; it adds iptables/ip6tables rules for its port and deletes them on exit.

    Kharej: ./fieldprobe -role recv -port 40400
    Iran:   ./fieldprobe -role send -peer KHAREJ_IP -port 40400          # Iran -> Kharej, v4
    Iran:   ./fieldprobe -role send -peer KHAREJ_V6 -port 40400          # same, v6 (if both have v6)
    then swap roles (recv on Iran, send on Kharej) for the reverse direction.

Read the receiver's `RESULT` lines against the sender's `SENT` lines:

- `udp` ~3/50 and `spray` ~150/150: the cut counts per 5-tuple, Spray lives. `spray` ~3-9/150: per IP pair, Spray dies.
- `ptcp` 50/50 with `synack=true`: fake TCP passes a full flow, Phantom lives. `ptcp` cut but `ptcp-spray` 100/100:
  Phantom only works with port hopping. Both cut: Phantom forward is dead; test it reverse.
- `*-bulk` `persec`: steady = no rate trigger; falling to 0 mid-run = blocked after a volume or a flow count.
- v6 lines vs v4 lines: whether IPv6 has the same filter.

Also on the same pair (no new code), for Phase 1:

- `udp` carrier with default, `WAT_BATCH=1`, `WAT_BATCH=1 WAT_GSO=1` (MB/s, CPU per MB).
- direct tcp: RTT and MB/s during a 16-stream upload with default and `WAT_DIRECT_WIN_MS=300`/`500` (3.3.7).
- tcp with `sessions` 1/2/4/8 on 3.3.7: the 176/261/147/68 figures are from 3.1.2, before bounded memory, and
  direct carriers no longer cut on delay, so the cause of the drop needs a fresh measurement before a shared pacer
  is built.

### Results, 2026-11-14 (iran2 85.133.233.178 <-> kharej 88.218.196.198, 3.3.7 probe)

Iran -> Kharej (the filtered direction), v4:
- One flow is cut after ~29-34 packets, at 300 B and at 1400 B alike: the filter counts packets per 5-tuple, not
  bytes. Same for udp and fake TCP (`udp` 33/50, `ptcp` 34/50 with `synack=true`; `udp-bulk` 33, `ptcp-bulk` 25).
- Spray passes: `spray` 149/150, `ptcp-spray` 100/100 (50/50 SYN-ACKs), `spray-bulk` 99.7 % of 39k datagrams over
  19.5k flows at 9.3 MB/s, steady per second. 20k flows in 5 s caused no block. The probe's sender topped out at
  ~4k new sockets/s (~10 MB/s at 30 and 80 MB/s targets): a carrier that writes source ports on a raw socket has no
  such limit, and that rate is still unmeasured.
- So: **Spray lives** (hop every <= 20 packets keeps a margin under the ~30 cut), and **Phantom works only with
  hopping** in this direction.

Kharej -> Iran, v4: nothing is cut. udp, spray, ptcp and their bulk runs all 10.00 MB/s steady. The Iran NIC merges
fake-TCP segments on receive (GRO: 9834 reads carried all 50 MB), which is good for Phantom's receive cost.

IPv6: dead on this pair. iran2 has a v6 address but no route out (ping6 to Google fails with errors); nothing
arrived over v6 either way.

## Phase 1: engine fixes

1. **Done (3.3.7): seal outside `s.mu`.** `build()` frames the packet (`Session.frame`); the send loop seals the
   batch after it drops the lock (`sealOut`), in place in the out buffer.
2. **Server receive fan-out: not now.** `Server.run()` only looks up the session, copies and queues; the AEAD open
   and parse already run in each session's own goroutine. Profile the server (pprof on the metrics address) before
   touching it.
3. **udp batching on by default** if the Phase 0 A/B shows a gain; GSO default only if it was measured.
4. **Direct-pool window: field-tunable in 3.3.7** (`WAT_DIRECT_WIN_MS`). Pick the default from the A/B above; the
   1 s value was tuned on the lossy Kharej -> Iran leg (2026-10-16) and must still fill there.
5. **Shared pacer across sessions:** only if the sessions 1/2/4/8 re-measure still shows the drop.

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
