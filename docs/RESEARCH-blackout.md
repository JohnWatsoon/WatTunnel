# Blackout research: keeping WatTunnel alive when nothing reaches Kharej

Status: **research/brainstorm, 2026-10-30** — not a spec, nothing decided. Written for other agents:
file:line anchors point into this checkout. Verify web claims independently before relying on them.

Trigger: "full blackout (no CDN works)". Two reference repos were evaluated plus everything
already in this codebase. TL;DR of the whole document:

> A full blackout has exactly one software-side crossing that has ever survived in the field:
> **client → domestic recursive resolver → your authoritative NS on Kharej** (DNS tunneling).
> SNI spoofing and every other WatTunnel trick are tools for the *filtered* regime, not the
> *cut* regime — in a cut there is no flow to hide anything inside of. The realistic build is:
> a `dns` carrier riding the existing Session machinery, a DNS bootstrap/bulletin-board control
> channel (half of it already exists in `revive.go`), and automating the documented relay chain.

---

## 1. Two different "blackouts" — do not conflate them

Everything below depends on which of these the network is actually in:

- **B1 — filtered/whitelisted.** International bandwidth exists; a DPI only lets flows through
  that look allowed (SNI allowlist, DNS-only port 53, allowlisted CDN edges). WatTunnel 3.x is
  largely built for this regime: `fake-sni` desync (`wat/desync.go`, TECHNICAL.md:568),
  `udp-dns` shaping (`wat/dnsshape.go`, TECHNICAL.md:982), tcp mimic, uTLS fp, ECH, CDN carriers.
- **B0 — cut.** International bandwidth to users is ~0. Foreign IPs unreachable, foreign CDN
  edges dead, ICMP to Kharej dead, direct DoH to 1.1.1.1 dead (already IP-blocked in Iran in
  normal times — `cmd/wattun/echladder.go:3-4`). Domestic intranet (banks, government, local
  services) works. This is the regime the user asked about ("no CDN works").

The two reference repos sit on opposite sides:

| Repo | Regime it addresses | One-line verdict |
|---|---|---|
| patterniha/SNI-Spoofing | **B1 only** | Same trick as our `fake-mode: seq`; we already ship a superset. One importable idea: it does this on **Windows** via WinDivert. |
| masterking32/MasterDnsVPN | **B0 (and B1)** | The competitive benchmark and the evidence that DNS tunneling survives real cuts. Its feature list is a good checklist for our `dns` carrier. |

---

## 2. What actually crosses the border during a B0 cut

Ranked by evidence strength:

1. **DNS recursion via domestic resolvers.** The state keeps its recursive resolvers resolving
   (the intranet and whitelisted services need names, and the resolvers keep a narrow upstream
   path). A client query for `chunk.your-domain.tld` walks: domestic resolver → root/TLD →
   **your authoritative NS, which is the Kharej server**. That is the entire crossing; no
   direct user→foreign packet ever exists.
   - Evidence: MasterDnsVPN's README claims it kept users online through Iran's 88-day blackout
     ("99% of the connection to the outside world physically cut off"). Their claim, not
     independently verified here, but consistent with 15 years of prior art surviving real
     events: DNSTT (Go, KCP+Noise, built for exactly this), iodine, dns2tcp, godoh (DoH),
     SlipStream (Rust, QUIC-in-DNS), even commercial C2 (Cobalt Strike DNS beacon).
   - Iran-specific circumvention DNS services (e.g. 403.online) show resolver-based paths are
     an actively used channel there. (Background knowledge; search API was down — verify.)
2. **Domestic hosts that keep international lines.** B2B/enterprise providers, universities,
   some "Iran location" clouds keep narrow foreign routes for their own business. If a relay
   can be placed on one, everything else follows from it. WatTunnel already documents the
   two-hop chain recipe (TECHNICAL.md:652, "domestic relay chain", no new code).
3. **State-adjacent networks** (banking, aviation, government links). Not reachable by us in
   software; listed only for completeness.
4. **Physical layer** (Starlink terminals, smuggled SIMs, HF radio). Out of scope for the
   tunnel. Only note: our delay-based CC tolerates high-latency satellite links if a user has
   hardware.
5. **Everything else is dead in B0**: ICMP, any direct TCP/UDP to Kharej, `udp-dns` (it talks
   *directly* to the Kharej IP — it only wins in B1 where port-53-shaped UDP to that IP passes),
   foreign CDN edges, foreign DoH/DoT.

Corollary: **B0 software options = DNS tunneling, full stop.** The rest is relay placement
(§7) and control-plane coordination (§6).

---

## 3. What WatTunnel already has — do not rebuild any of this

| Piece | Where | Blackout relevance |
|---|---|---|
| DNS knock over a query (36-byte HMAC'd knock → base32hex label → A query; server parses any arriving query) | `wat/revive.go:113-167`; server hook `wat/server.go:421-430` | **Half the B0 uplink already exists.** Missing: a client sender that goes *via a resolver*, and a response leg. |
| AEAD-sealed session packets (ChaCha20-Poly1305, per-session key) | `wat/session.go` | A resolver that hijacks/forges answers produces packets that fail auth → degrade to "loss", never to "compromise". |
| Session/Stream ARQ, reordering, dedup, FEC | `wat/stream.go`, `wat/fec.go` | A `dns` carrier can be a dumb lossy datagram pipe; all reliability already sits above it. |
| Bonding / multipath over carriers | `wat/bond.go`, `wat/paths.go` | **Multi-resolver = multipath, almost free.** Each resolver is one path; health-check and failover logic exists. |
| Governor (rate pacing) | `wat/governor.go` | Repurpose for resolver QPS budgets (resolvers SERVFAIL/throttle heavy clients). |
| Carrier `Profile` (MTU etc.) | `wat/io.go:20-36` | A `dns` carrier declares a small MTU; the session frames packets to fit — the mechanism exists (udp-dns precedent). |
| DNS-shape framing utilities | `wat/dnsshape.go` | Label/name generation patterns reusable for camouflage. |
| DNS relay over a live tunnel (target port 53) + client-side DNS listener | `cmd/wattun/echladder.go`, `cmd/wattun/dnslisten.go` | Not B0 tools (need a live tunnel), but their plumbing is the client-side DNS API precedent. |
| Relay chain recipe | TECHNICAL.md:652 | The other half of B0; manual today, automation missing. |
| ICMP path prober | `cmd/wprobe` | Pattern for a "does anything cross the border" oracle (§8). |
| Manager blackout command (writes the fake-sni kit) | `wattun-manager blackout` | Entry point to extend into a full blackout playbook (§8). |

---

## 4. Idea 1 — flagship: a real `dns` carrier (resolver → authoritative NS)

The only missing transport for B0. Design sketch, mapped onto existing interfaces:

**Server side (Kharej).** Runs an authoritative NS for a delegated subdomain, on UDP 53 (TCP 53
as truncation fallback). It is a `RawIO`-style carrier: every arriving query carries (a) the
session id and packet bytes encoded in the qname, (b) a return path = the querying resolver.
Answers carry downlink packet bytes in answer records. Deployment prerequisite: the operator
owns a domain, sets `A ns → Kharej_IP` and `NS t → ns` (identical to the MasterDnsVPN setup;
their README documents the exact records, including "short domain names leave more room for
data").

**Client side (Iran).** A `PacketIO` carrier: `Send` builds a DNS query whose labels encode the
sealed session packet chunk, and sends it to a **resolver list** — system resolver
(`/etc/resolv.conf`, the ISP's DHCP-assigned one), optionally public resolvers, optionally a
DoH endpoint where one exists. `Recv` collects responses and extracts downlink chunks. One
query = one uplink chunk + one downlink response opportunity (downlink piggybacks on every
response — downlink is usually the scarce direction, so pack it).

**What rides for free:** session ARQ/reordering/dedup (resolver retries produce duplicate
queries — already handled), FEC over small chunks, delay-based CC (a resolver's variable
recursion latency looks exactly like the delay signal it already uses), bonding across
resolvers (per-resolver health + failover), governor pacing per resolver, AEAD authentication
of both directions, `hdr-mask`/`sessions` compose as with `udp-dns`.

**Honest capacity numbers** (assume the worst: plain UDP 53, no EDNS cooperation):

- qname budget: 255 bytes total, minus ~15–25 for the delegated suffix and label overhead;
  base32hex ≈ 5 bits/char → **~100–120 bytes of sealed packet per uplink query**
  (multiple ≤63-char labels). 36-byte knock precedent fits a single label (`revive.go:114`).
- downlink: without EDNS a response is capped at 512 bytes (TXT/NULL record ≈ 400 usable);
  with EDNS0 ~1232; over TCP 53 up to 64 KB but TCP 53 is often blocked/rewritten.
- sustainable rate per resolver before throttling/SERVFAIL: order of 5–30 qps (MasterDnsVPN
  built health checks + failover + 8 balancing strategies precisely because resolvers
  misbehave under load).
- ⇒ with 3–5 resolvers bonded: **tens of kbps, optimistically low hundreds.** Enough for
  messaging, SSH/serial remote management, text web, keepalives, coordination. Not video, not
  bulk. This is the lifeline expectation — consistent with what DNS tunnels have historically
  delivered in real blackouts. Set expectations in the docs exactly this way.

**Hard problems, and their status in this codebase:**

- **Negative caching / resolver caches:** every qname must be unique (per-query nonce) and the
  server must answer NOERROR (not NXDOMAIN, which resolvers negatively cache) with TTL 0.
- **0x20 case randomization** by resolvers: use a case-insensitive encoding (lowercase
  base32hex, accept case flips on the server) — `FormatDNSQuery` already lowercases
  (`revive.go:115`).
- **Resolver QPS limits / flaky behavior:** governor pacing + bonded multi-resolver + health
  checks. MasterDnsVPN's feature table is the checklist: health checks, auto-disable,
  background reactivation, failover, MTU discovery — map onto bond/paths.
- **DPI fingerprinting of random labels:** long random subdomains are the classic DNS-tunnel
  tell. Mitigations: dictionary-word label chunking (lower entropy density), realistic query
  mix (mostly A/AAAA with a few TXT), per-resolver rate caps, rotating domains. It is an arms
  race — document, don't promise.
- **The terminal risk:** if the state blocks recursion to *your* zone (or forces all DNS to
  resolvers that refuse foreign zones), the DNS carrier dies and **no software-side B0 option
  remains except relay placement (§7)**. Say this in the docs; it is the honest limit.
- **NS exposure:** the Kharej IP becomes the public NS of the operator's domain — deanonymizes
  the server. Recommend one dedicated domain + IP pair per deployment, never the CDN-fronted one.
- **Open NS = open attack surface:** anyone can query it; garbage queries are just like any
  other spoofed traffic to a `RawIO` carrier and fail auth. Rate limiting per source exists in
  the ports/limits machinery; review whether it applies to the dns carrier socket.

**Testing — the rare good news:** unlike `fake-sni` and `icmp`, a dns carrier needs **no raw
socket and no Linux** — plain UDP sockets. The whole thing can be developed and sim-tested in
this **Windows checkout**: write a fake recursive resolver (drops/delays/dedups/hijacks)
inside `wat/` tests, exactly the pattern the sim suite already uses. `testbench/emulate_dpi.py`
can grow a DNS-verdict mode later for the real-link bench.

**Wire compatibility:** carrier selection is per-deployment; the DNS envelope is outer framing
exactly like `udp-dns` (`dnsshape.go`), session packets unchanged → old peers unaffected, but
both ends of a dns-carrier deployment need the new version. New frame-in-query format must
parse-and-ignore unknown parts for future extension, same rule as `wire.go`. Version bump +
TECHNICAL.md + both READMEs on release.

---

## 5. Reference-repo evaluations

### patterniha/SNI-Spoofing — B1 tool; we already ship a superset

What it actually is (from source, not the near-empty README): a **Windows** local proxy
(WinDivert via pydivert) that completes a normal TCP+TLS-shaped connection to the target, then
after the handshake injects ONE extra raw packet carrying a ClientHello with a whitelisted SNI
(example config: `auth.vercel.com`), with `tcp.seq = ISN+1-len(payload)` — below the window, so
the destination kernel ignores it as an old duplicate while the DPI reassembles and reads it.
It then watches for the peer's dup-ACK as *proof the injected packet crossed the filter* before
handing the connection to the proxy (`fake_tcp.py`: `fake_send_thread`, `wrong_seq` branch,
`fake_data_ack_recv`).

- That is exactly our `fake-sni` + `fake-mode: seq` (TECHNICAL.md:591-594: seq `ISN+1-len`,
  dup-ACK from the kernel, NAT-shift tolerance). WatTunnel additionally ships `ttl`, `sum`
  (bad checksum in-window), `seqsum`, `rst`, `synrst`, `none`, and `auto` probe with
  `TCP_INFO`-based verdict — strictly more than their one mode.
- **Verdict for B0: useless.** There is no flow to Kharej to inject into when the border is
  cut; SNI spoofing answers an SNI *allowlist*, not a routing *cut*. TECHNICAL.md:637-639
  already lists its real failure modes (checksum/seq-validating NATs, pure IP allowlists).
- **One genuinely importable idea:** they do the injection on **Windows** with WinDivert. Our
  fake-sni is Linux-only (`desync_other.go` refuses off Linux) and our shipped windows/amd64
  build has no ICMP either. If Windows clients matter for B1 hardening, a WinDivert-based
  desync injector is a real, demonstrated path (separate feature, not blackout work).

### masterking32/MasterDnsVPN — the benchmark and the B0 evidence

Go, MIT, ~7k stars, multi-language READMEs (incl. Farsi), actively maintained. TCP-over-DNS
through recursive resolvers to your authoritative NS. Their headline claims: custom protocol
with **~5–7 B transport overhead** (vs ~24 SlipStream, ~59 DNSTT), ARQ, multi-resolver
multipath with 8 balancing strategies, packet duplication, resolver health checks with
auto-disable and background reactivation, per-stream failover, MTU discovery, optional
compression, local SOCKS5 with reduced overhead, local DNS service with caching to resist
hijacking. Comparison table (their numbers, local bench): 10 MB down 0.27 s vs DNSTT 2.49 s.

What to copy conceptually for our `dns` carrier (most map to existing bond/governor pieces —
see §3): resolver health checks + auto-disable + reactivation, per-resolver failover with
cooldown, duplication for setup-critical chunks, compression above ~120 B payloads (we have
none in-wat today — evaluate last), a local DNS service so the OS itself uses the tunnel for
names (we have this: `dnslisten.go`).

What *not* to copy: their transport's ARQ is in the carrier because their protocol has no
session layer; ours does — keep the dns carrier dumb and let `Session` handle it, which is the
smaller diff and the house architecture.

Their deployment requirement is the same one we would inherit and must document for operators:
own a domain, delegate a subdomain via A+NS, keep names short (label budget), UDP+TCP 53 free
on Kharej, firewall open. Their Docker/MikroTik packaging and per-platform release matrix are
product decisions, not transport ones.

---

## 6. Idea 2 — DNS bulletin board: the cheap control channel to build first

Even before any bulk carrier, DNS via a resolver can move a few hundred bytes per exchange —
enough for coordination, which is what a blackout actually starves on first.

- **Path advertisement:** Kharej publishes a small signed blob as TXT under e.g.
  `_wt.t.example.com` — current best carrier/config, server IP/port, SNI, freshness timestamp,
  HMAC'd with a PSK-derived key (the `revive.go` derivation pattern, replay window included).
  Clients poll every N minutes through whatever resolver works.
- **What that buys in B1:** when the state blocks the Kharej IP, the operator moves the server,
  updates one DNS record, and every client follows with **no out-of-band channel**. Today an IP
  move requires redistributing configs by hand — exactly what you cannot do mid-blackout.
- **What it buys in B0:** an "is anyone alive" heartbeat both directions; a trigger to
  re-probe; and the bootstrap that tells clients the dns-carrier parameters in the first place
  (chicken-and-egg solved: one static resolver query discovers everything else).
- **Half of it exists:** `FormatDNSQuery`/`ParseDNSQueryKnock` (`revive.go`) already do
  authenticated uplink-in-qname and server-side parsing; the additions are a TXT response
  encoder on the server, a poller + verifier on the client, and freshness semantics.
- **MVP without touching the Go engine:** the operator publishes records on Kharej; a tiny
  verify tool (a `wattun` subcommand or a `wattun-manager` function using `dig`, which the
  manager already shells out to) polls and checks the HMAC. Days of work, not weeks.

---

## 7. Idea 3 — relay chain: the non-DNS half of B0, already designed

TECHNICAL.md:652 documents the two-hop chain (users → domestic relay → Kharej) with stock
wattun since 2.0. During a B0 cut the chain's second hop (relay → Kharej) becomes the
bottleneck: it needs whatever the relay's own line passes — and if only its DNS path crosses,
that hop is exactly the dns carrier from §4 (or a B2B international line that some Iranian
providers sell for business customers). The first hop (users → relay) rides the wide-open
domestic intranet and needs no new anything.

Gaps to close:

- `wattun-manager` automation (a `relay` wizard; today it is hand-edited dual configs with
  `WAT_PREFIX` sandboxes — TECHNICAL.md:676-678).
- Placement guidance in the docs: any Iranian VPS/friend's server/company host with a working
  foreign route; one relay serves many users; the relay sees only AEAD ciphertext (both hops
  are sealed sessions — TECHNICAL.md:670-671).
- A safety note worth writing down: the relay operator is the exposed party; that is a human
  risk decision, not a technical one.

---

## 8. Idea 4 — "cockroach mode": posture, not transport

Above the carriers, a blackout is a *detection and failover* problem, and most of the
machinery exists:

- The client continuously, at low rate, probes every wire it has: ICMP (wprobe pattern),
  `udp-dns` direct, DNS-via-resolver (one bulletin-board query), relay reachability.
  `linkwatch.go` already logs "sending, hearing nothing"; `revive.go` already carries actions
  (reload listeners, reverse companion, flush limits) and replay-safe auth.
- Policy: when everything is silent, drop to the slowest probe cycle; the first wire that
  answers gets the session (bonding/revive machinery). When a fat carrier comes back, upgrade
  automatically. Users get best-effort messaging instead of silence, and no manual
  reconfiguration at 3 a.m.
- Manager side: `wattun-manager blackout NAME` already writes the B1 kit (fake-sni, TECHNICAL.md:628-632);
  extend it with a B0 profile (dns carrier + resolver list + bulletin polling) so one command
  switches regimes. Document as a playbook: which mode to try in which order, what each
  failure signature means (TECHNICAL.md's troubleshooting pattern).

---

## 9. Evaluated and rejected (so the next agent doesn't re-litigate)

- **NTP/other UDP mimicry to Kharej** — B1 only (same as `udp-dns`); needs a reachable foreign
  IP; dead in B0.
- **DoH/DoT to *foreign* resolvers as the B0 carrier** — the foreign resolver IP is unreachable
  in B0 by definition; only *domestic* resolver paths cross. DoH to a domestic resolver is a
  B1 hardening variant of §4 (worth a config flag, not a separate design).
- **IPv6** — Iranian deployment is negligible; not a path.
- **SMTP/email store-and-forward tunnel** (encrypted chunks via mailbox, IMAP polling) — the
  only other protocol that historically crosses cuts when whitelisted for business. KB/s,
  minutes of latency, needs SMTP/IMAP machinery and a mailbox trust boundary we don't have;
  wrong shape for a real-time port forwarder. Keep as the documented last-resort idea only.
- **Parasitizing whitelisted third-party services** (pastebin-style write APIs, open proxies on
  allowlisted IPs) — fragile, ToS-violating, dies the moment the third party notices; not worth
  engineering time.
- **Satellite/radio** — hardware, out of scope.

---

## 10. Recommended order

1. **Bulletin board + revive client sender** (§6; days) — always-on B0 control channel on
   existing crypto; immediately useful for IP rotation even in B1; solves the
   chicken-and-egg for everything else.
2. **`dns` carrier** (§4; weeks, testable on this Windows checkout against a fake resolver in
   the `wat/` suite) — the B0 data plane. Both ends new version; wire-compatible otherwise.
3. **Relay-chain automation in the manager** (§7; days, no engine changes) — the non-DNS half.
4. **Cockroach mode + manager playbook** (§8; days, after 1–2) — automatic degrade/upgrade.

Each step ships value alone; no step requires the next.

## 11. Open questions for the owner

1. Are operators willing to own and delegate a domain per deployment (A + NS records, UDP/TCP
   53 on Kharej)? Without that, no DNS carrier — it is the same prerequisite MasterDnsVPN has.
2. Is messaging/SSH-grade throughput (tens of kbps) an acceptable explicit "blackout mode",
   documented as such? Or must v1 chase the aggressive end (TCP-53 fallback, EDNS, compression)?
3. Priority between B0 lifeline (`dns` carrier) and the one new B1 idea found (WinDivert
   fake-sni for Windows clients, §5)? They are separate efforts.
4. Should the client resolver list include DoH-to-domestic endpoints in v1, or plain UDP 53
   only (simplest thing that provably crosses)?

## 12. Sources

- https://github.com/patterniha/SNI-Spoofing — README, `injecter.py`, `fake_tcp.py`,
  `config.json` (read 2026-10-30). Windows/WinDivert local proxy; wrong-seq fake ClientHello;
  dup-ACK confirmation. GPL-3.0.
- https://github.com/masterking32/MasterDnsVPN — README (EN, read 2026-10-30; FA/ES/IT/RU/ZH
  exist). DNS-tunnel VPN, multi-resolver, claims of surviving the 88-day Iran blackout. MIT.
- Prior art named in §2: DNSTT (github.com/dnstt-lab/dnstt), iodine, dns2tcp, godoh,
  SlipStream; 403.online (Iran DNS unblock service — background knowledge, unverified today:
  web search API was unavailable).
- This checkout: TECHNICAL.md:568-678 (fake-sni modes, relay chain), :982-1009 (udp-dns),
  `wat/revive.go`, `wat/dnsshape.go`, `wat/io.go`, `cmd/wattun/{echladder,dnslisten}.go`,
  `wat/server.go:421-430`.
