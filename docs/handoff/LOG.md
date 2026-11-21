# Handoff log

Shared notes between the implementing agent and the reviewing agent. The plan is `PLAN-go-manager.md`.
Append only, newest entry at the bottom. Never edit or delete an earlier entry. Add a new one that corrects it.

Entry format:

```
## YYYY-MM-DD HH:MM · <who: implementer | reviewer> · <task number or topic>
What was done / found, in plain sentences.
Files: path:line, ...
Tests: the command and its last lines of output (pass/fail counts).
Commit: <short hash> (or "none")
QUESTION: <only if blocked on something the code cannot answer>
```

---

## 2026-11-20 · reviewer · kickoff
Plan written. Start with task 1. The default stays bash until I sign off. Write every finding here.
Commit: none

## 2026-11-20 17:40 · implementer · task 1 — Iran accepts auto tokens
`wizardIran` no longer refuses `carrier=auto`: it calls the existing `autoIranFront` (auto.go:2087, the port of
bash `auto_iran_front` 5524), merges the chosen variant into the token fields exactly like bash `at_to_t` does
(carrier/peer/path/sni/rev), and carries the choice's `AT_EXTRA` lines (per-leg peers, disguise, tune, reverse
`listen-<car>`) into the yml; the original token is kept in `NAME.auto` (bash AUTO_TOKEN). Reverse carrier-port
checks now match bash 3431-3462: single-rpool uses the token peer's port, a reverse bond reads the
`listen-<car>` lines, both must be free (`listenBlocked` + `listenConflictDesc`) and unpublished. The
anti-censor profile ask is skipped for auto tokens (`t.Auto != ""`), as bash does via `[ -z "$T_AUTO" ]`.
Enablers found missing on the way, now included:
- `ni.go` (new): the bash `ni_parse` flag surface for kharej/iran (all flags validated with the bash validators),
  plus the `portEditor.run` NonInteractive branch (`--map` replaces the token prefill, else the prefill stays;
  Iran with no ports errors like bash). `mgr.Run` parses these flags for kharej/iran; the wizards read them
  (NI.Token as the token ask default, NI.Name, NI.Mbps opens the advanced block, NI.Pick/NI.Test in
  `autoIranFront`). `wizard_kharej_auto` now takes its options from the NI struct instead of `os.Getenv` (nothing
  ever set those env vars). This NI plumbing is shared with task 7's CI gate.
- Iran NI branch: presets/fake-sni/pool/ech/governor/dns-listen/src-ip applied with the bash validations and
  version gates; sessions/conns/mtu written into the yml with the bash guards (new `sessionsCarrierOK`,
  `iranParams.Sessions/Conns/MTU`); `LINK=up|down`/`TUNNEL=` epilogue with exit 1 when down; rports opened before
  the link check; heal timer enabled for any new tunnel; kreply offer on icmp+rev.
- Kharej NI branch (needed because task 7's gate drives `kharej --yes`): `pickCarrier` NI mode, `--udp-dns` with
  the 3.0.0 gate, `--ports` allow list, private-address warning, `--listen` blocked check, `TUNNEL=`/`TOKEN=`
  epilogue, kreply offer.
- **Real bug the new test caught**: the `autoTune*` constants held version strings (`"3.3.0"`) instead of the
  tuning grids, so `atTune`'s knob split panicked for every non-icmp variant — `auto-test` and the auto wizard
  would crash on any real choice. Now the bash `AUTO_TUNE_*` grids (wattun-manager 4982-4987).
Files: cmd/wattun/mgr/ni.go (new), wizards.go, tunnels.go (portEditor.run NI, vDomainOpt), mgr.go, ops.go,
auto.go (autoIranFront NI wiring, autoTune consts), wizards_test.go (new).
Tests: `go test -count=1 -run TestWizardIranAuto ./cmd/wattun/mgr/` → ok (2 tests: plain udp choice writes the
expected yml/key/.auto + LINK=/TUNNEL=; reverse tcp choice writes reverse+listen). Then `gofmt -l cmd wat
testbench` (empty), `go vet ./...` (clean), `go test -count=1 ./cmd/...` → ok (wattun 13.8s, mgr 0.5s, wprobe
0.05s). Not run: bash test-manager.sh (bash manager untouched this task); -race (Windows checkout, CI runs it).
Known gaps (logged, not fixed here): `iran --pick bond/rbond` paths untested beyond best; `--policy` parsed but
only consumed by auto-retest (out of scope); kharej `default_listen` has no cdn_mode port preference yet.
Commit: (this commit)

## 2026-11-20 17:52 · implementer · task 2 — Kharej auto end to end
`wizardKharejAuto` now runs against a temp conf in a test: `envRandOpenPort` stubbed to an incrementing port
picker, `envPublicIP` to 203.0.113.10, `envSystemdRun`/`envFWOpen` recorded (the real `EnableNow` path just fails
harmlessly without systemd), engine version pinned to 9.9.9. Options taken from the NI struct
(Name=ci1, Addr=127.0.0.1, Ports=18999).
Assertions: the yml (header, mode: server, `carrier: icmp+…`, `listen-udp/-tcp:` lines, `path: /api/…`,
metrics, `ports:` block with the --ports entry), the `.key` (exactly 40 chars, not the dev fallback), the
`.token` (parses with ReadToken, Carrier=auto, plan has `d=` and a separate `;r=`, peer and allow carried),
the returned Units start with the parent, firewall rules were opened, token starts with `wat1:`.
Files: cmd/wattun/mgr/auto_wizard_test.go (new).
Tests: `go test -count=1 -run TestWizardKharejAutoEndToEnd ./cmd/wattun/mgr/` → ok; then gofmt (empty), vet
(clean), full `go test -count=1 ./cmd/wattun/mgr/` → ok.
Commit: (this commit)

## 2026-11-20 18:03 · implementer · tasks 3 + 4 — dashboard number jump, auto Kharej stats
Task 3: the dashboard's 1-9 now calls `tunnelPage(dashN[num-1])` (status.go:678; the deck was never wired). The
RunDashboard loop re-renders when the deck returns, which is the bash main_menu redraw.
Task 4: the auto-Kharej branch of bash `tinfo` (1929-2032) is ported as `tinfoAutoKharej`: parent + hidden
helpers (`p1AutoHelpers` → `autoHelpers`, wired at status.go:73) summed — bytes in/out (with the pre-2.4.19
fallback), rate, sessions, streams, dgram flows; best (lowest) RTT and its min/loss over helpers that are alive
or carry sessions; state up when any helper is alive, unknown when an active helper's stats did not answer, down
otherwise, stopped when nothing is active; carrier rows: the parent's alive/muted carriers, the companion's
prefixed `r:`, each `NAME-e-<shape>` as one synthetic alive row (loss percent → fraction, share 1, like the
bash); `LivePick` = live carriers + `r:` picks + shapes, which `dashRow` already shows. The extended helpers read
`/stats?flat=1` (`p1StatsFlat` → new `statsFlatOf`, the port of bash stats_flat 589, JSON fallback included).
The degraded downgrade does not run in this branch (bash guards it on TI_AUTO=0).
Files: cmd/wattun/mgr/status.go, status_auto_test.go (new).
Tests: `go test -count=1 -run 'TestTinfoAutoKharej|TestStatsFlatOf' ./cmd/wattun/mgr/` → ok (aggregation sums,
best RTT, live pick, row prefixes, unknown/stopped states, flat+JSON forms); full mgr suite + gofmt + vet → ok.
Commit: (this commit)

## 2026-11-20 18:10 · implementer · task 5 — matrix apply
`applyMatrixVariant` (matrix.go:652) was already implemented through the real config writer (`SetValue`/
`UnsetValue`) plus a `p1Systemctl("restart", …)`; the TODO comment at matrix.go:617 was stale, so I dropped the
TODO and added the missing test (none existed). The test runs against a temp conf: apply replaces fake-sni,
writes the variant's fake-mode (fmDefault: an empty mode becomes `seq`, matching the engine default — my first
assertion expected `rst` for an empty mode and was wrong, the code is right), removes fake-ttl, keeps ech, and
restarts `wattun@t1`; the empty (baseline-won) variant clears the disguise keys; an ech-less variant does not
clobber an existing ech.
Files: cmd/wattun/mgr/matrix.go (comment only), matrix_apply_test.go (new).
Tests: `go test -count=1 -run TestApplyMatrixVariant ./cmd/wattun/mgr/` → ok; gofmt/vet/full mgr suite → ok.
Commit: (this commit)

## 2026-11-20 18:20 · implementer · task 6 — smaller TODOs
All five sites from the plan:
- status.go:629 (server side): now `p1ServerSide` → the real `serverSide()` (home.go:108, the port of bash
  server_side 6375: saved `.manager.conf` role first, else inferred from the tunnels' roles). The old
  `p1Cfg(".manager", "side")` read a tunnel conf that does not exist, so the side was always "".
- status.go:1398 (registerStatusScreens never called): called from routes.go's init() bootstrap — the "P1 tag"
  condition is met, status.go compiles untagged. Its four keys (status/logs/doctor/monitor) were dead aliases
  before; now they resolve. Nothing else in the tree dispatches those keys, so behaviour is unchanged; they are
  available for the tty menu paths.
- auto.go:44: `engineVer` already delegates to `BinVersion` (sysd.go); stale "share it" TODO dropped.
- matrix.go:73: `binVer` was a second copy of the `-version` parsing; it now delegates to `BinVersion`.
  `wattunBin()` stays (still used by atStart).
- auto.go:2009: `p1Speedtest`'s live form is already wired (sysd.go:57 → speedtestLive → fetchSpeedtest); the
  comment said it was only a stub. Comment corrected to describe the seam honestly.
Files: cmd/wattun/mgr/routes.go, status.go, auto.go, matrix.go.
Tests: gofmt -l cmd wat testbench → empty; go vet ./... → clean; `go test -count=1 ./cmd/wattun/mgr/` → ok.
Commit: (this commit)

## 2026-11-20 18:35 · implementer · task 7 — Linux CI gate
New `gomgr` job in .github/workflows/ci.yml (ubuntu-latest): builds ./wattun, then in an empty sandbox
(WAT_PREFIX=wtci, WAT_CONF/WAT_RUN under $RUNNER_TEMP, WAT_BIN=$PWD/wattun, WAT_GO_MGR=1):
1. `kharej --yes --carrier auto --name ci1 --addr 127.0.0.1` under a 300 MB cgroup cap
   (`sudo systemd-run --scope -p MemoryMax=300M`, prlimit --as=4G fallback if systemd-run is unavailable — the
   Go manager needs root exactly like the bash one, `id -u` check). Asserts exit 0, `TUNNEL=ci1`,
   `TOKEN=wat1:`, and ci1.yml/.key/.token written. A leak fails the job (OOM kill) instead of hanging it.
2. Keeps the Kharej engine listening: the wizard's own systemd unit (wtci@ci1, template written by
   ensureTemplate with WAT_BIN/WAT_CONF baked in) if it started, else the binary run directly with nohup — so
   "systemd units may fail in CI" stays true without weakening the test.
3. `iran --yes --token <that> --map 18999:18999/tcp --name ci1-iran --pick best --test normal`: exit code is
   tolerated as 0 or 1 (a failed unit start gives LINK=down and rc 1), but the auto check itself must have
   really run: no "not ported"/"not available in this build" refusal, at least one check-mark row in the ranked
   table (packets actually flowed through the tunnel on loopback), and ci1-iran.yml/.key/.auto written.
The Kharej auto wizard now prints the unattended epilogue `TUNNEL=`/`TOKEN=` after showToken (bash 4164 parity;
this is what the gate greps).
Cannot run here (Windows checkout, no systemd, manager root-gated); the plan expects CI to prove this job. The
non-interactive plumbing it drives was added in task 1's commit and is unit-tested there.
Files: .github/workflows/ci.yml, cmd/wattun/mgr/ops.go.
Tests: YAML parsed (6 jobs); gofmt/vet/mgr suite ok locally.
Commit: (this commit)

## 2026-11-20 18:47 · implementer · task 8 — sweep
`grep -rn "not ported|not available in this build|TODO" cmd/wattun/mgr --include=*.go` (tests skipped), before → after:
- matrix.go:608 comment "(set_value is TODO(P1): conf writer)" — stale (the writer is used); reworded.
- wizards.go:279 "The auto carrier needs the auto-plan writer (not ported yet)" — the fallback when
  `wizard_kharej_auto` is not registered. It is always registered (ops.go init, same package), so the branch was
  dead; removed and wizardKharej routes `auto` straight to the dispatch.
- mgr.go:15 comment describing the fallback — reworded (no sweep string).
Final list: `mgr.go:28` — dispatch's runtime "not available in this build" error stays. It is a programming-slip
safety net, not a menu path: every name runCommand/tunnels/decks dispatch is verified registered at init
(checked the full dispatch list this pass). No user-reachable screen is unported.
Files: cmd/wattun/mgr/matrix.go, wizards.go, mgr.go.
Tests: gofmt (empty), go vet (clean), `go test -count=1 ./cmd/...` → ok (wattun 13.8s, mgr 0.55s, wprobe 0.04s),
`bash test-manager.sh` → ALL OK (bash manager untouched, gate still green).
Commit: (this commit)

## 2026-11-20 18:55 · implementer · READY FOR REVIEW
All 8 plan tasks are implemented, logged above with test output, and committed (one commit each, in task order):
- 85a1c33 task 1 — Iran auto tokens (autoIranFront wired in, ni_parse plumbing, portEditor NI, kharej NI,
  Iran NI epilogue; autoTune panic bug fixed)
- 95a902b task 2 — wizardKharejAuto end-to-end test
- e3591e0 tasks 3+4 — dashboard 1-9 opens the deck; auto Kharej stats aggregation (tinfoAutoKharej, statsFlatOf)
- 6d62da6 task 5 — applyMatrixVariant test
- cfa3c40 task 6 — five small TODOs (serverSide, registry bootstrap, shared BinVersion, honest seam comments)
- b27561b task 7 — ci.yml `gomgr` sign-off job (auto round trip on Linux under a 300 MB cgroup cap)
- 5ad809c task 8 — sweep: dead fallback removed, stale comments cleared

Final gate status (local, Windows checkout):
- `gofmt -l cmd wat testbench` → empty
- `go vet ./...` → clean
- `go test -count=1 ./cmd/...` → ok (wattun 13.7s, mgr 0.57s, wprobe 0.04s)
- `bash test-manager.sh` → ALL OK
- NOT run here: `-race` (needs CI/Ubuntu), the `wat/` suite (engine untouched this pass), and the new `gomgr` CI
  job itself — it can only run on Linux CI.

What the reviewing agent should know:
- The engine (`wat/`) was not touched; the bash manager was not touched; `manager_unix.go` default still bash.
  Nothing to release yet — the version badge/release notes are yours if you sign off on flipping the default.
- Beyond the plan's literal tasks, the NI (unattended) surface for kharej/iran had to be ported for the gate to
  be drivable (task 1's commit) — flag set, validators and consumption mirror bash ni_parse + wizard branches.
  Known NI gaps, logged deliberately: `--policy` parses but is only consumed by auto-retest (as in bash);
  kharej `default_listen` has no cdn_mode port preference; `iran --pick bond/rbond` and the failed-variants
  (`f` key) path are unit-untested beyond best.
- The task-1 test exposed a real shipped bug: atTune's knob constants were version strings, so `auto-test`
  panicked for every non-icmp choice. Fixed with the bash grids.
- CI is NOT green yet for one reason only: the branch is not pushed (no push/tag/release without the owner).
  Owner: please push `main` (or a branch) so `.github/workflows/ci.yml` runs; the `gomgr` job is the sign-off
  test. If it fails, its output is the next work item.
Commit: 5ad809c (head)

## 2026-11-20 · reviewer · review of tasks 1-8
Checked: all 8 commits are by JohnWatsoon with no AI trailer; `wat/`, `install.sh` and the default in
`manager_unix.go` are untouched; the `autoTune*` grids match bash `AUTO_TUNE_*` exactly; local gofmt/vet/
`go test ./cmd/...` (256) pass; `bash test-manager.sh` ALL OK.
CI on branch `gomgr-review`:
- The first push failed at load: `${{ runner.temp }}` is not allowed in job-level `env`. WAT_CONF/WAT_RUN now
  come from `$RUNNER_TEMP` inside each step.
- The second run reached the wizards. Kharej auto printed TUNNEL=/TOKEN= with no OOM, but the file checks failed:
  the sandbox conf is root-only (0700), so they now use `sudo test`/`sudo grep`.
- That run also exposed a real bug in both managers. `show_token` -> `refresh_token` treated an auto Kharej
  (`carrier: icmp+udp+...`) as an arm-blackout fortress bond and rewrote NAME.token into a bond token, dropping the
  auto plan. The Go wizard printed that wrong token first. In bash, opening a tunnel's token page (key t) did the
  same. This is the likely cause of the "token gone / auto test all red" reports. Fix: the fortress branch runs
  only when the token is not auto, or when called as `refresh_token NAME fortress`, which only arm-blackout does
  (bash + Go). Tests: `TestRefreshTokenKeepsAutoPlan` and two test-manager checks.
- Third run: `gomgr` PASSED (the Kharej auto -> token -> Iran auto test round trip on Linux under the 300 MB cap).
  `build` failed only on my new test-manager check, because `role()` is stubbed to Iran at that point. Fixed by
  setting role to Kharej around the check. Local ALL OK.
Verdict: the plan is done. The Go manager meets the sign-off gate. Flipping the default is the owner's call, with
a version bump and release notes. Nothing is field-tested on a real server.
Commit: see the next commit on gomgr-review

## 2026-11-20 · reviewer · kickoff handoff 2
New plan: `docs/handoff/PLAN-phase2.md` (Track A coded downlink, Track B Phantom/ptcp with hopping, Track C Split
only if A and B are done). Same log, same rules. Start with Track A.
Commit: none

## 2026-11-20 19:35 · implementer · phase 2 / A1 — read pass + baseline kill numbers
Read fec.go, the ACK path (wire.go frAck/appendAck, session.go ackEvery=6/2ms, late ACKs, pathAcked RTT
samples) and cc.go's loss machinery (lossTime = rtt*1.25+3 ms, PTO = 3*srtt+4*rttvar min 120 ms, delay-based
rate: loss never cuts the rate, only the opt-in loss-ceiling).

**Why today's per-block XOR does not fix the target path's tail:**
1. Coverage: `fecNoteSent` skips any packet whose plaintext > maxPlain-fecHdrMax — a full bulk packet is never
   covered. At 640 B MTU nearly every bulk packet is full; at 1400 B the same. The kill scenario (interactive
   stream next to bulk) is mostly uncovered: the parity only ever protects small packets.
2. Gate: the default loss gate (on at 2 %, off at 0.5 %) is CLOSED at the target's 0.2-2 % random loss — at
   1 % measured loss today's FEC sends no parity at all (that was F11's point: no overhead on a healthy path).
3. Even when parity flows: one XOR per group of <= 16 small packets, sent after the burst ends; a second loss
   in the group is unrepairable, and the parity packet itself is subject to the same loss with no recovery.
4. The retransmit path it would have to beat: sender-side detection needs lossTime (~1.25xRTT+3 ms = ~53 ms at
   40 ms RTT) of ACK silence after the send, then the resend costs another RTT — an echo whose downlink packet
   was lost lands at >= ~93 ms + queueing, exactly where the measurements put p90.

**Baseline kill numbers (today's code, new harness `wat/coded_test.go`, link model 20 ms one way, 10 MB/s,
100 ms max queue, seeds fixed):**
- Interactive 1-byte echo during a bulk download, 1 % loss, 40 ms RTT:
  - MTU 640: p50=42.2 ms, p90=93.6 ms, p99=132.9 ms, max=185.2 ms (retrans 1743)
  - MTU 1400: p50=42.1 ms, p90=91.9 ms, p99=122.0 ms, max=277.4 ms (retrans 1743)
  - p50 sits on the RTT floor (42 ms); the tail is the loss-repair round trips: p90 ~= 2.3xRTT (one
    loss+retransmit), p99 ~= 3xRTT (loss + lost retransmit or a lost ACK).
- Bulk download 8 MB, MTU 1400: 5.3 MB/s at 0 %, 5.2 MB/s at 0.5/1/2 % loss (retrans 0/67/144/290) — the
  delay-based CC holds the rate; loss costs only retransmits, so throughput headroom for a small repair
  overhead exists.
Kill criteria for the coded build: p99 clearly below ~120 ms at both MTUs without losing the 5.2-5.3 MB/s.
Files: wat/coded_test.go (new, measuring tests, no gate), wat/version.go (3.4.3 per plan).
Tests: `go test -count=1 -run TestKill -v ./wat/` → numbers above, both tests PASS (data intact);
`go vet ./wat/` clean.
Commit: (this commit)

## 2026-11-20 19:52 · implementer · A2 — sliding-window repair design (logged before coding)
New `wat/repair.go`, opt-in (`Config.Repair`, flag `-repair`, config `repair: true`; both ends 3.4.3+).
Separate from fec.go, which keeps its small-packet role unchanged.

**Sender** keeps a ring of the last W=32 data-packet plaintexts (pn + bytes; the copy is accepted because the
feature is opt-in). Every D data packets it sends ONE repair packet carrying r=1..2 symbols, INTERLEAVED with
the data (not after the burst — that is the latency difference from fecDue): a loss becomes repairable ~D
packets after it happened (milliseconds at bulk rate) instead of after lossTime+RTT (~93 ms).
- Symbol k (global monotone index, agreed implicitly) = XOR of the zero-padded plaintexts of every window
  packet pn with cover(pn,k) = high bit of (pn*0x9E3779B97F4A7C15 ^ k*0xC2B2AE3D27D4EB4F) — a deterministic
  pseudo-random half-subset; ~W/2 members per symbol, no coefficient table on the wire.
- Frame frRepair 0x0f, ALONE in its packet (an old peer stops at the type byte, like frFec/frEndpoint):
  base(uv) r(uv) L(uv) k0(uv) n(uv) then n×(pnOff uv, len uv) member headers, then r×L parity bytes. The
  lengths ride along because the symbol is zero-padded to L=max member length and the true length of a LOST
  packet is unknowable from the parity alone; n headers cost ~4 B/packet amortized.
- Repair packets are paced and counted (cc.tokens, stats) but never tracked in s.sent: never acked, never
  retransmitted, like frFec.
- D adapts to measured loss: overhead target o = clamp(2×lossEWMA + 0.5 %, 0.5 %, 10 %), D = 1/o; lossEWMA
  from the same onAck/onLoss-class signals fec uses (EWMA over lost/sent from the loss-marking path).
  At 0 % loss D=200: one repair packet per 200 data packets (~0.5 %) — the 0 %-loss throughput criterion.

**Receiver** keeps the mirrored ring while any hole < W old. On frRepair: for each symbol, XOR out the arrived
members (zero-padded), leaving equations over the holes only; solve the GF(2) system (r equations × e
unknowns, Gaussian elimination, e ≤ 32 — trivial CPU); when rank = e, reconstruct each lost plaintext, trim to
its header length, and deliver exactly the way onFec delivers a rebuilt packet (rxRing replay marking,
rxRanges.add — so the next ACK reports it and the sender never retransmits it — then parse()).
Rank < e (unrecoverable): fall through, the normal retransmit path still owns the hole. Correctness never
depends on repair.

**Negotiation**: frRepairCap 0x10 (one byte, alone in its packet or last — old peers ignore it). Each end sends
it ~1/s with ACK/ping traffic while repair is enabled; a end sends repair symbols ONLY after seeing the peer's
frRepairCap. Mixed pair both ways: no cap seen → no repair sent → byte-for-byte today's behavior (the frame
never appears on the wire). This is the same degradation shape as frEndpoint.

**ACK cadence unchanged in v1** (the plan's "a few status packets per second" goal): repair already removes the
retransmit pressure; cutting ackEvery too needs feedback-starvation analysis. Logged as a deliberate scope cut.

CPU: one symbol = XOR of ~16×1400 B ≈ 22 KB ≈ ~3 µs, one per D=25..200 packets — noise. GF(256) rejected: no
need at these loss rates, XOR+GF(2) solve is sufficient and table-free.
Stats: RepairSent / RepairRecovered added to Stats.
Kill criteria: p99 < ~120 ms at both MTUs (baseline 133/122), bulk stays 5.2-5.3 MB/s at 0-2 %.
Commit: none yet (design only)

## 2026-11-21 00:15 · implementer · A2–A5 — sliding-window coded repair implemented, measured, wired (off by default)
**Built** (`wat/repair.go`, ~430 lines): exactly the logged design, plus two deviations the implementation
forced, both logged here:
1. **Chunked symbols**: a symbol's parity (L = window max plaintext ≈ 1350 B) + member table exceeds one
   datagram on a full bulk window, so each repair packet carries the shared header + a parity OFFSET
   (`base L k n members poff parity-to-end`) and the receiver stitches chunks by k. The frame layout in the
   A2 entry is superseded by this one (frRepair 0x0f still alone in its packet).
2. **Solve restructure**: the unknown set is collected while rows are built (a covered member that is neither
   in the receive ring nor deliverable is an unknown; members older than the 256-entry receive ring are
   refused), and Gauss-Jordan full-rank solves; a rank deficit leaves the hole to the retransmit path.
   The receiver keeps the last 8 symbols and solves jointly (two losses need two covering equations).
Adaptive spacing: `every = W/(1+3×lossEWMA×W)` from the same onAck/onLoss EWMA shape fec uses — one symbol
per 400 data packets on a clean link (~0.25 % bytes), per ~4 at 2 % loss.
Negotiation as designed: frRepairCap 0x10 sent ~1/s while repair is on (before frEndpoint), repair flows only
after seeing the peer's cap; boot change drops the decoder state. Stats RepairSent/RepairRecovered
(`/stats` `repair_sent`/`repair_recovered`); flag `-repair` / config key `repair` (keys are flag names).

**Bugs found and fixed on the way** (all caught by the new tests, worth remembering):
- The window clamp used `int64(lo) < 0`, which is TRUE for every server pn (server pns start at
  `dirServerBit = 1<<63`) — the window scan looped from 0 to ~9.2e18 and hung the pump with s.mu held.
- Holes were computed from the newest frame's member list only; older kept symbols' holes were invisible and
  their rows "invalid". Now the unknown set spans all kept symbols.
- A pn newer than rxLargest (tail loss) was refused by the rxLargest-pn underflow guard; guarded by
  `pn < rxLargest` now.

**A3 kill test** (`go test -count=1 -run TestKill -v ./wat/`, same harness/seeds, 120 samples/point,
link 20 ms one way, 10 MB/s, 40 ms RTT):
- Interactive p99 during bulk, 1 % loss:
  - MTU 1400: today p50=42.1 p90=101.2 p99=163.8 max=274.4 (retrans 3082) → repair p50=42.4 p90=87.6
    **p99=102.1** max=263.8 (retrans 1732). Clear win: −62 ms p99, retrans −44 %.
  - MTU 640: today p99=98.9 (this run; 132.9 in the baseline run — run noise ±30 ms) → repair p99=102.9.
    Within noise: no clear win at the legacy MTU.
- Bulk 8 MB, MTU 1400: today 5.3/5.2/5.2/5.2 MB/s at 0/0.5/1/2 % → repair 5.3/5.2/5.1/5.0. 0 % identical
  (criterion met); the 1-2 % cost is the parity's bytes on the fixed pipe (≤4 %).
- CPU (BenchmarkRepairCodec, 1340 B members, one symbol/16 packets): 6.3 µs per data packet amortized
  (ring copy + symbol + solve attempt) ≈ 2.5 % of one core at 5 MB/s.
**Verdict (honest, per the plan's rule): coded wins clearly at 1400 B MTU — the route's MTU since
2026-10-12 — and is inside run noise at 640 B; 0 %-loss throughput unchanged. Kept OFF by default; the
reviewer decides promotion.**

**A4 mixed versions** (`TestRepairMixedVersions`): new client/old server and old client/new server (old =
repair off, exactly a pre-3.4.3 peer's behavior with the new frames): both transfer 2 MB intact at 1 % loss
with ZERO repair frames sent (RepairSent=RepairRecovered=0). Wire compat: frRepair alone in its packet;
frRepairCap followed only by frames an old peer ignores (frEndpoint/frPad); parse stops at unknown types.

**A5 docs**: `docs/TECHNICAL.md` flag table row for `repair` (3.4.3 both ends, sim numbers labelled sim,
"not field-measured yet").

Tests: `go test -count=1 ./cmd/...` ok; **full `go test -count=1 -timeout 15m ./wat/` ok (539.8 s)**;
gofmt empty, vet clean. New: repair_test.go, repair_codec_test.go, BenchmarkRepairCodec; kill tests now run
both modes.
Commit: (this commit)

## 2026-11-21 01:20 · implementer · B — Phantom (`ptcp`) carrier built, wired, unit+loopback tested
**Built** (`wat/ptcp_linux.go` ~520 lines, `wat/ptcp_other.go` stub): the fieldprobe's proven shape as a
carrier. Client (PacketIO): raw SYN with Linux-shaped options (MSS 1460, SACK-permitted, timestamps, wscale
7) → SYN-ACK → ACK → the mimic ClientHello (`wat.FakeClientHello`, -sni shapes it) as the first data
segment → engine datagrams as PSH|ACK segments with moving seq/ack and timestamps. A new flow (fresh source
port 61000-64999, fresh ISN, full handshake) every -ptcp-hop..1.5x packets (default 12, under the measured
~30-packet cut); the retired flow gets FIN|ACK and stays readable hopGrace (500 ms) for in-flight downlink.
Server (RawIO): answers SYNs from any source with SYN-ACKs, swallows each flow's ClientHello flight, delivers
the rest as datagrams (src = ip:sport so SendTo replies down the same flow), pure ACK every 4th segment.
Both ends ACK every 4 segments of the other direction. Profile{MTU: 1340, InitBps: 8e6, Spread: true}
(one datagram per segment; Spread: each flow takes a fresh port, like Wraith).
- **Kernel RSTs**: the fieldprobe way — at startup an iptables OUTPUT rule drops our RSTs for the carrier's
  ports (client: the source-port range; server: the listen port) plus an INPUT ACCEPT; each rule is deleted
  before insertion (a crashed run's stale rule is cleaned by the next start) and deleted at exit. A crash
  leaves the rule behind: it matches only our own RSTs on those ports, harmless to other traffic, and the
  next start removes it. No iptables → a warning, the carrier still runs (RSTs leak).
- **Reverse mode refused, deliberately**: the 2026-11-14 field run measured Kharej->Iran cuts nothing, so the
  reverse direction gains nothing over a plain tcp carrier; -reverse fails loudly like gre/ipip. This is a
  scope cut against the plan's bullet 2 "reverse mode", with the field evidence as the reason.
- IPv4 only (the pair's IPv6 is dead — PLAN-carriers.md); not in the auto test set (per plan).

**Wiring**: engine dispatch `case "ptcp"` in cmd/wattun (client `-peer host[:port]` default port 443, server
`-listen`), flag `-ptcp-hop` (12). Manager: carrier accepted in bash `carrier_ok` + `carrier_min_ver`
(3.4.3), MGR_VERSION → 2026112101; Go mgr `carrierMinVer`, the "more transports" picker (own gates: 3.4.3 +
Linux), VCarrierList/`carrier_ok` messages list ptcp. `repair`/`ptcp-hop` declared CFG_FILE_ONLY in the bash
manager (the wizards do not write them yet — known gap, logged). TECHNICAL.md: carriers table row, peer row,
flag row, root-carrier list. CI: TestPTCP joined the root `icmp` job's regex.
**Tests** (`wat/ptcp_linux_test.go`): segment codec (checksum verifies on SYN/data, options MSS/SACK/TS/wscale
present and placed, seq/ack/flags/payload round-trip, TSecr echo) — runs on any Linux;
`TestPTCPLoopback` (root, joins the CI root job): 30 uplink datagrams with hop=4 → all 30 delivered, 10
downlink via SendTo delivered, ≥4 flows used, max packets per flow < 30 (the hop rule the plan asked for).
Cannot execute here (Windows checkout); `GOOS=linux go build/vet ./...` clean, so compile is proven, the
run is CI's (the same position as the gomgr job). No wire change to existing carriers; nothing default.
Tests: `go test -count=1 ./cmd/...` ok; `bash test-manager.sh` ALL OK (after the CFG_FILE_ONLY fix the
coverage check demanded); gofmt empty; vet clean both GOOS.
Commit: (this commit)

## 2026-11-21 01:35 · implementer · C — Split: already covered by Bifrost ":up"/":down" legs (3.3.9); nothing to build
Split was "a send-only bond leg: carries data one way, liveness from ACKs arriving on another path".
`wat/bond.go` + `wat/paths.go` (3.3.9) already implement exactly that:
- A `udp:down` leg is send-only from the server's side: the client never sends data on it (only the NAT
  knock/announce; bond.go:172-190 guards it), the server pushes downlink to the port the client announced
  with frEndpoint (0x0e). A `:up` leg is the mirror (client sends, the server never replies on it).
- Liveness from other paths: the session ACKs name packet numbers, not paths — session.go pathAcked maps an
  acked packet to the LANE it was sent on and feeds PathFeedback.OnAck/OnLoss for that lane, whatever path
  the ACK itself arrived on. A `:down` leg is measured alive by ACKs returning on the other legs, which is
  Split's definition.
- Mixed-version degradation and the security invariant (the announced port binds to the authenticated
  source) are documented at wire.go frEndpoint and covered by the Bifrost tests.
The one gap vs a fully general Split is documented in paths.go:47: in 3.3.9 a ":down" leg is restricted to
the udp carrier (a quiet bound socket). A ":down" leg of another carrier (e.g. icmp:down) would need that
carrier's quiet-receive form — a separate, small feature if the owner ever wants it; nothing about Split's
mechanism is missing.
Per the plan's instruction ("if it is covered, write that and stop"): written, stopping.
Commit: (this commit)

## 2026-11-21 01:45 · implementer · READY FOR REVIEW (handoff 2)
All three tracks done, one commit each in order:
- f23b3f7 A1 — kill harness + baseline numbers (version bumped to 3.4.3)
- efdfc90 A2 — sliding-window repair design (logged before coding, per plan)
- cf870b1 A2–A5 — repair implemented, measured (p99 163.8→102.1 ms at 1400 MTU / 1 % loss; 0 % throughput
  unchanged; mixed-version zero-frame both ways; CPU 6.3 µs/packet), wired (-repair, /stats keys,
  TECHNICAL.md). OFF BY DEFAULT — the honest verdict (clear win at 1400, inside noise at 640) is in the log;
  promotion is the reviewer's call.
- ef3cdd4 B — Phantom (ptcp) raw-TCP carrier with built-in hopping, RST-drop iptables handling, both
  managers' lists (MGR_VERSION 2026112101), CI root-job tests. Reverse refused with the field reason. Not
  field-measured (docs say so); not in the auto set.
- 5915b4a C — Split: already covered by Bifrost :up/:down (written, stopped, per plan).

Final local gate status (Windows checkout):
- gofmt -l cmd wat testbench → empty; go vet ./... and GOOS=linux go vet → clean
- go test -count=1 ./cmd/... → ok; FULL `go test -count=1 -timeout 15m ./wat/` → ok (539.8 s, includes the
  repair suite and both kill modes); bash test-manager.sh → ALL OK
- NOT runnable here: the ptcp loopback test and the Linux CI jobs (gomgr, icmp+TestPTCP) — GOOS=linux
  build/vet is clean; the runs are CI's once pushed. No push/tag/release (owner pushes).

Known gaps, all deliberate and logged above: repair's 640 MTU result is noise-level; `repair`/`ptcp-hop` are
file-only keys (no wizard prompt yet); a general (non-udp) ":down" leg would be new work if ever wanted;
ptcp carrier not field-measured; the plan's ACK-rate reduction goal for Track A was cut in v1 (logged in the
A2 entry).
Commit: 5915b4a (head)

## 2026-11-21 09:30 · implementer · post-review audit — what the review commit fixed, and what was still left
Read the review commit `999ef51` end to end and re-audited both tracks with fresh eyes.

**The review's two fixes are correct and verified here** (both real bugs in what I shipped):
1. frRepairCap shared a packet with frEndpoint: a 3.3.9-3.4.2 peer (knows frEndpoint, not the cap) stopped
   at the cap and never learned the ":down" leg's port — a wire-compat break of Bifrost on mixed pairs with
   -repair on. The fix (cap and endpoint never share a packet; endpoint retries on the next build, which
   appendEndpoint already supports without touching epAt) is right; `TestRepairCapNeverHidesEndpoint` passes.
2. The ptcp client INPUT rule `--sport 443 -j ACCEPT` accepted from ANY host; now pinned to the peer and the
   source-port range. Correct.

**Leftover issues found in this audit (fixed / documented now):**
- `repairNoteSent` copied every data packet's plaintext into the tx ring even when the peer never announced
  frRepairCap — a mixed pair (old peer, -repair on) paid a per-packet copy for nothing, forever. The copy now
  waits for peerOK (the receive ring still fills from the first packet: the peer's symbols may arrive any
  time after OUR cap goes out). `TestRepairRoundTrip`/`Mixed`/`Kill` re-run green after the change.
- The ptcp SERVER-side RST drop cannot be destination-pinned (many peers), so a real TCP service on the same
  port would lose its legitimate RSTs. Documented as a caveat in the TECHNICAL.md ptcp row (pick a dedicated
  -listen port); not a code fix — there is nothing safe to pin it to.
- Cosmetic, logged not fixed: the ptcp client's ack field only advances when the every-4-segments ACK fires,
  so outgoing segments can carry a stale ack between ACKs. The fake server ignores ack numbers; only a
  middlebox reading acks could notice.

**Kill-test verdict correction**: the reviewer's 3-run re-measurement (docs edit, previously uncommitted,
committed with this entry) shows NO p99 gain — 101-104 ms both modes at both MTUs. My single-run
"163.8 → 102.1 at 1400" was an outlier run (its today-side retrans=3082 was the anomaly I noted and
dismissed). The honest state: repair is EXPERIMENTAL, no measured sim gain, off by default; the docs now say
exactly that. My earlier A3 log entry's "clear win at 1400" claim is superseded by this one.

Gates: gofmt empty; go vet + GOOS=linux go vet clean; `go test -count=1 -run 'TestRepair|TestBifrost|TestKillInteractiveP99|TestKillBulkThroughput' ./wat/` → ok.
Commit: (this commit)

## 2026-11-21 11:05 · implementer · spray carrier — raw-UDP 5-tuple rotation shipped as an engine carrier
- **What:** `case "spray"` carrier next to ptcp: client = one bound SOCK_RAW/IPPROTO_UDP socket, self-built UDP header with a real checksum, sport AND dport rotate every -spray-hop..1.5x packets (default 16), sendmmsg batches; server = one BPF-filtered raw socket on the dport range, replies to the NEWEST observed client sport. wat/spray{,_linux,_other}.go, tests, main.go wiring, both managers (MGR_VERSION 2026112102), TECHNICAL.md rows, CI root-job regex + TestSpray.
- **Reason:** the 2026-11-20 field run proved the rotation itself (98.7% delivery, no tuple over 20 packets, 15k tuples, no block); this wraps it in the production engine for the 3.4.3 release.
- **Decisions:** server -listen "41000" means 41000-41999 (base port spans +999, default = probe's range); range low port doubles as the server's fixed downlink source port so the client's BPF can match it; real UDP checksum instead of the probe's legal 0; client raw socket bound to the source IP so kernel-built IP header matches the checksummed pseudo-header; -reverse refused (downlink rotation rides the client's hops).
- **Tests:** go build/vet + GOOS=linux build/vet clean; gofmt empty; go test ./cmd/... ok; TestParseSprayPorts pass; bash -n + test-manager.sh ALL OK. NOT run here: TestSprayPacketCodec/Rotation/Loopback and the full wat suite (Linux-only; CI runs them).
- **Commit:** (this commit)

## 2026-11-21 12:10 · supervisor · P1 spray carrier — review verdict
Reviewed `1bcd0a4` end to end: BPF jump tables hand-verified (every false path lands on the drop — the probe's
F7 lesson), checksum + bind reasoning sound (real UDP checksum, socket bound so the kernel-built IP header
matches the pseudo-header), rotation bounds correct (N..1.5N, asserted in the loopback test), buffer/pool
lifetimes follow the udpHop pattern, sendmmsg uses the RawSockaddrInet4 form (the probe's historical
"family 0" bug avoided). Wiring complete in both managers; honest field wording kept.
One limitation found, accepted and recorded: `SprayServer.peers` is keyed by client IP only, so two clients
behind one NAT IP would aim each other's downlink at the newest sport (the wrong session's datagrams then
fail AEAD silently). Single client per source IP — the production shape — is unaffected; a (ip, live-port
set) demux would need the encrypted session id, which the carrier cannot see. Documented here rather than
fixed.
Gates re-run by the supervisor: build/vet/gofmt clean both GOOS, `go test -count=1 ./cmd/...` ok.
Commit: none (review only; the limitation note rides in this entry)

## 2026-11-21 14:40 · implementer · auto test presets: fast + reverse in both managers
- **What:** two new test-mode presets next to normal/anti, identical in the bash wattun-manager and the Go
  cmd/wattun/mgr port: `fast` = the anti grid cut to rst/synrst x {mci.ir, irancell.ir, cloudflare.com} on every
  direct pool carrier (6 rows/carrier instead of ~28) on top of the plain direct/CDN rows; `reverse` = only the
  plan's r= rows (direct/CDN/anti skipped entirely). Menu (at_preset_ask / atPresetAsk) now draws Enter/f/a/r/d/q
  with per-preset time estimates; `--test` accepts exactly normal|anti|fast|reverse in both ni parsers.
- **Why:** the owner-approved menu — the full anti grid costs 15-40 min, fast answers in ~4-6, and routes where
  only reverse passes waste every direct probe.
- **How:** grids are local test policy only — the fast rows are ordinary av_anti variants and the reverse rows the
  existing r= rows, so the ranked table, the 8% rank margin, Enter-applies-best and at_to_t/atToT's
  fake-sni/fake-mode lines all work unchanged (no new apply code; the "measured-apply default" is the existing
  best-row Enter). Time estimates are static strings in one comment table (rows x ~20 s, rounded); MGR_VERSION →
  2026112103. No engine (wat/) change, nothing on the wire, no new config keys. wat/version.go stays 3.4.3
  (unreleased cycle).
- **Tests:** Go atpreset_test.go pins the fast grid (only rst/synrst x the 3 SNIs, atToT writes the fake-* lines),
  the reverse-only grid and the four --test values; test-manager.sh pins the same grids bash-side (19-row fast
  count, r-only kinds) plus ni_parse accept/reject. Gates run here: go build/vet/gofmt clean, `go test -count=1
  ./cmd/...` ok, `bash -n` all three scripts, full `bash test-manager.sh` ALL OK (1003 ok). Not run: ./wat/ suite
  (no engine change) and the live presets (need a Linux Iran/Kharej pair; grid shapes are pinned by tests).
- **Commit:** (this commit)

## 2026-11-21 16:30 · implementer · repair v2 — receiver-driven NACK (frRepairAsk) built, kill-tested, verdict: keep OFF
**What** (`wat/repair.go`, `wat/wire.go`, `wat/session.go`, tests): Config.RepairAsk (default OFF, no flag yet —
promotion is the harness verdict's call) adds a NACK layer on top of the periodic coded repair:
- frRepairAsk 0x11: up to 8 absolute missing pns, oldest first; LAST frame of its packet; NEVER shares a packet
  with frEndpoint — the same slot rule the review (999ef51) imposed on frRepairCap, extended in build() (the ask
  rides after the cap in the cap's slot or takes the slot itself; the endpoint waits either way).
- Receiver: repairKeep rescans the rxRanges gaps each packet; holes >4 received packets old enter the ask queue;
  one ask per 40 ms (repairAskEvery), each hole at most twice (askN), then the retransmit path owns it. No asks
  when repair is off or peerOK is false (TestRepairMixedVersions extended: zero asks both directions).
- Sender: repairOnAsk answers with ONE targeted symbol covering every asked pn (k searched upward from
  max(r.k, kAsk), bound 64) plus the covered current window; the periodic schedule (pending/every/k counter) is
  untouched. Chunked like periodic symbols; drains through the existing queue/pump.

**Two real bugs found on the way, both fixed:**
1. **repairCover was degenerate.** The v1 form took the TOP BIT of pn*C1^k*C2 — but any single bit of x^y is
   bit(x)^bit(y), so cover(pn,k) = A(pn)^B(k): only TWO distinct subsets existed across all k, and two pns in
   different halves were NEVER jointly covered (half of all loss pairs unrecoverable by construction — the v1
   codec double-loss tests had happened to pick cross-half pairs). Fixed with a second multiply to spread the
   bits; pinned by a new joint-coverage assertion in TestRepairCoverProperties. Not a wire change (cover is
   computed, never sent); 3.4.3 unreleased so no deployed peer computes the old subsets.
2. **The 32-packet tx window cannot answer an ask.** At bulk rate the window scrolls past a hole in ~9 ms; an
   ask is ~60 ms stale (40 ms throttle + 20 ms flight). Measured: with v1 retention every ask missed (29/29,
  TestRepairAskRoundTrip). Fix: a 1024-entry askTx retention ring (≈1.4 MB/direction/session, opt-in, only
   while peerOK), targeted member offsets up to repairOffMax in onRepair, and the solver's reach bound moved
   from the 128-entry rx ring to repairOffMax (a delivered-but-aged member now refuses its row instead).

**Kill harness (coded_test.go, three modes: today / repair / repair+ask), 3 runs of TestKillInteractiveP99
(120 samples, 1 % loss, 40 ms RTT) and TestKillBulkThroughput (8 MB, 1400 MTU), Windows checkout, 2026-11-21:
- p99 (ms), 640 MTU: today 103.9/98.5/140.9 · repair 103.1/147.3/102.0 · repair+ask 177.7/103.0/104.1
- p99 (ms), 1400 MTU: today 102.7/106.5/104.0 · repair 196.2/102.3/103.2 · repair+ask 105.9/101.9/100.8
- bulk MB/s at 0/0.5/1/2 %: today 5.3/5.2/5.2/5.1 · repair 5.3/5.2/5.0/5.0 · repair+ask 5.3/5.2/5.1/5.0
  (one earlier ask run printed 4.5 at 2 % — a single-run outlier, not reproduced).
**Verdict (honest, per the plan's rule): NO clear p99 win at both MTUs.** All three modes sit at ~100-105 ms
median p99 with ±40 ms run-to-run noise; the ~2.5×RTT tail is present mode-independent, i.e. it is set by
something repair cannot touch (the interactive echo's own loss-detect+retransmit path, scheduling), not by
coverage. 0 %-loss throughput is unchanged (5.3 across modes) — that criterion holds — but the kill rule needs
the CLEAR p99 win too. **RepairAsk stays OFF (experimental, no flag, no promotion); the honest result is the
valid finish the plan allowed.** The cover fix and the ask machinery land anyway: correct, tested, and the
diagnosis (window-vs-latency, cover degeneracy) is now on record for any future attempt.
Tests: codec (ask round-trip/codec/throttle/cover-search, bare sessions), sim TestRepairAskRoundTrip
(asks=29, askHit=51, askMiss=3), extended mixed-version zero-frame/zero-ask both ways.
Commit: (this commit)

## 2026-11-21 14:05 · supervisor · P2 repair v2 — review verdict
Reviewed `0d8790e` end to end: the ask layer follows the reviewer's 999ef51 slot rule exactly (the ask extends
the cap's slot; frEndpoint still never shares a packet with a frame an old peer stops at), parseRepairAsk is
bounded (≤8 pns), the 1024-entry askTx retention ring is peerOK-gated and opt-in, and the two bug finds are
both real:
- the degenerate `repairCover` (the high bit of x^y is bit(x)^bit(y), so v1 had only two distinct coverage
  subsets across all k) is very likely the TRUE root cause of v1's no-gain — my earlier "adaptive spacing"
  explanation in the A3 entry is superseded by this;
- the 32-packet ring scroll-past (asks ~60 ms stale, 29/29 measured misses) — the retention ring is the
  right fix and its ~1.4 MB/direction/session cost is acceptable for an opt-in layer.
Verdict endorsed: repair stays OFF in every form (v1, v2, combined all sit ~100-105 ms p99 with ±40 ms run
noise; 0 %-loss throughput unchanged). Config.RepairAsk ships as a compile-time seam with no flag — dead
until a future promotion proves itself, and the honest finish the plan allows.
Carried into P3's brief: if working recovery (askHit=51/3) does not move the tail, the tail is probably not
retransmit-latency-bound — P3 carries a diagnosis mandate (clean-sample p99) alongside the fast-rtx
experiment, so the next null result at least names the real cause.
Supervisor gates re-run: build/vet/gofmt clean both GOOS, repair+bifrost subsets ok, ./cmd/... ok.
Commit: none (review only; this note rides with the P3 commit)

## 2026-11-21 18:20 · implementer · P3 — fast retransmit (-fast-rtx) + the tail diagnosis: the p99 tail is NOT loss
**Built (Part A)**: Config.FastRtx / flag `-fast-rtx` / config key `fast-rtx` (off by default, sender-local,
no wire change — an old peer needs nothing, either end alone can enable it). In afterAck's loss scan
(wat/session.go), every unacked packet below the acked largest is a gap in that ACK; sentPkt.gaps counts
consecutive gap sightings and the 3rd consecutive one declares the packet lost at once (s.lose) instead of
waiting out lossTime. Gated `!s.cc.reliable` (reliable/direct carriers keep age-only loss — spurious resends
were costly there, cc.go relLossMul history). The counter dies with done (ack or loss), so no reset path
exists. wattun-manager: `fast-rtx` declared CFG_FILE_ONLY, MGR_VERSION → 2026112104. Version stays 3.4.3
(unreleased). TECHNICAL.md flag row added.
Tests: wat/fastrtx_test.go — gap counter (2 acks no loss, 3rd loses all skipped packets; asserted via
Retrans because compact()/freeSent recycle the records at once), off-by-default, reliable-carrier never
fast-loses, sim transfer intact at 2 % loss.

**Diagnosis (Part B)**: killLatency now snapshots both ends' Retrans (and the client's RepairRecovered)
around each echo sample and classifies it clean / downlink-loss / uplink-loss / other
(classifyKill, pinned by TestKillClassify); the harness logs p99 overall, p99 of the clean subset and the
class counts. Modes today / fast-rtx / repair+ask+fast, 3 runs, 120 samples, 1 % loss, 40 ms RTT:

- p99 ms (overall · clean subset), 640 MTU: today 101.5·102.0 / 166.4·194.3 / 104.5·109.2 · fast-rtx
  101.1·101.6 / 103.1·103.6 / 135.6·139.3 · r+a+f 102.9·103.5 / 102.1·102.6 / 103.0·107.0
- p99 ms, 1400 MTU: today 103.1·132.0 / 113.9·120.5 / 146.0·161.5 · fast-rtx 102.6·103.0 / 163.5·163.5 /
  107.0·112.5 · r+a+f 102.2·163.1 / 103.7·105.8 / 131.9·175.0
- classes per 120 samples (typical): clean 24-34, down 83-96, up 0-1, other 0-2.
- bulk MB/s at 0/0.5/1/2 %: today 5.3/5.2/5.2/5.2, fast-rtx identical with byte-identical retrans
  counters (67/144/290), r+a+f 5.3/5.2/5.1/5.0.

**Findings:**
1. **The clean subset carries the same tail.** Samples where NO retransmit or repair counter moved on
   either end still sit at p50 ≈ 85-90 ms and p99 ≈ 102-194 ms — the same ~2.5xRTT shape as the whole run
   (overall p50 42 ms). The tail is queueing/scheduling/pacing-bound (the echo queues behind bulk at the
   pacer), not retransmit-latency-bound. Repair v1, repair v2 and fast-rtx were all correctly doomed:
   they optimize a path the tail does not take. Caveat recorded: at 1 % loss a 50-100 ms sample window
   usually contains an ambient BULK retransmit, so the "down" class measures link activity, not the echo's
   own loss — the clean subset is the informative signal, and it is the slow one.
2. **fast-rtx is a near-no-op on this path**: the existing `largest-pn >= 4` rule (unreliable, non-spread)
   already fires as early as the ACKs allow; the deterministic bulk runs show identical retrans counts
   (67/144/290). Its remaining scope is spread carriers (udp-hop/spray, where the 4-behind rule is off)
   and slow-ACK paths.
**Verdict (honest, per the kill rule): NO clear p99 win — fast-rtx ships OFF by default** (the flag exists
for spread-carrier experiments); the diagnosis above is the deliverable. Next tail attack, if any, should
target scheduler/pacer queueing of interactive echoes during bulk, not loss recovery.
Tests: gofmt empty, vet clean, `go test -count=1 ./cmd/...` ok, full `go test -count=1 -timeout 15m ./wat/`
ok, `bash -n wattun-manager` + `bash test-manager.sh` ALL OK.
Commit: (this commit)

## 2026-11-21 15:40 · supervisor · P3 fast retransmit + tail diagnosis — review verdict
Reviewed `95c8e58`: the gap counter lives on sentPkt and dies with done (no map to leak), increments exactly
when an ACK names a larger pn while the packet is unacked, fast-loses at 3 with the !cc.reliable gate, and the
pre-existing loss rules are untouched below it. Harness classification and the three-mode loop are as briefed.
Verdict endorsed: -fast-rtx ships OFF (all modes inside the same noise band; near-no-op on non-spread paths
where the existing largest-pn>=4 rule fires first — its honest scope is spread carriers).
THE DIAGNOSIS IS THE SESSION'S MAIN RESULT: the clean subset (zero retrans/repair activity on either end)
carries the same ~2.5xRTT tail (clean p50 ≈ 87 ms vs run p50 42 ms, clean p99 102-194 ms). The interactive
tail during bulk is queueing/scheduling/pacing-bound — NOT loss-recovery latency. Repair v1, v2 and fast-rtx
were all correctly doomed; any future tail work attacks the scheduler/pacer's treatment of interactive
echoes during bulk instead.
Supervisor gates re-run: build/vet/gofmt clean, fast-rtx + kill subsets ok, ./cmd/... ok.
Commit: none (review only; this note rides with the P4 commit)

## 2026-11-21 20:05 · implementer · P4 — ptcp iptables rules tagged + race-safe; /stats/history ring; doctor hooks
**Item 1 — ptcp firewall rules** (`wat/ptcp_linux.go`): every rule the carrier inserts (client OUTPUT RST-drop,
client INPUT ACCEPT, server OUTPUT RST-drop, server INPUT ACCEPT) now carries `-m comment --comment
wattun-ptcp` and every iptables invocation passes `-w` (waits for the xtables lock — a boot-time insert can no
longer race systemd/ufw). The delete-before-insert idempotence is unchanged; the `-D` carries the byte-identical
spec (comment included) so it still matches. `-m comment` is standard on every distro; if the `-I` fails anyway
the carrier logs the same warning and runs (unchanged).
**Doctor hooks**: `wattun-manager` `test_tunnel` (top of Checks, so a STOPPED unit also reports — the crash
case) and the Go manager's `Doctor` both list `iptables -w -S OUTPUT` rules tagged `wattun-ptcp` when the unit
being diagnosed is not a live ptcp tunnel, with the advice "restart a ptcp tunnel or delete each by re-running
it with -D". Report only, never auto-delete. The Go side got a real slot: `DoctorIO.FwPTCP` mirrors the existing
`FwICMP` hook (injectable for tests; `ptcpLeftovers` in status.go). MGR_VERSION → 2026112105. TECHNICAL.md's
ptcp row now mentions the tag.
**Item 2 — `/stats/history`** (`cmd/wattun/history.go`, ~70 lines): while the metrics server runs, a sampler
records every 5 s (unix `t`, `rate_bps`, `srtt_ms`, `loss_pct` when the CC has measured an interval — pointer,
omitted while 0/unmeasured — `streams`, `alive`) into a 60-entry ring (5 min, oldest dropped). `GET
/stats/history` serves the ring oldest-first as a JSON array (`[]` before the first sample). The samples reuse
the SAME totals closure `/stats` uses (`stats()`/`alive()` in main.go — server-mode multi-session aggregation
included); no second aggregation exists. Handler sits next to `/stats` under the same `guard`, server stays
loopback-only (unchanged rule). TECHNICAL.md Metrics section documents it (5 s cadence, 60 samples,
localhost-only). No wire change, no config key, version stays 3.4.3.
Tests: `cmd/wattun/history_test.go` — ring bounded at 60 with oldest dropped, exact JSON shape (loss_pct
omitted when unset, empty case `[]`), handler round-trip via httptest.
Gates (Windows checkout): gofmt empty; `go build`/`go vet` and `GOOS=linux go build`/`go vet` clean (ptcp
loopback tests cannot run here — the Linux compile is the proof, the run is CI's); `go test -count=1
./cmd/...` ok; `bash -n wattun-manager` ok; `bash test-manager.sh` ALL OK.
Commit: (this commit)

## 2026-11-21 16:20 · supervisor · P4 review verdict + READY FOR REVIEW (supervised pass)
P4 `91fae93` reviewed and approved: every fwRules invocation carries -w and the wattun-ptcp comment tag with
the identical spec on -D; the doctor leftover check runs before the stopped-unit early return (the crash case
IS a stopped unit — good catch); /stats/history reuses the /stats totals closures (no second aggregation),
sits behind the loopback guard with the other handlers, and its JSON shape (including the empty ring) is
pinned by tests. MGR_VERSION 2026112105.

SUPERVISED PASS SUMMARY (owner approved all packages 2026-11-21; five foxes, each reviewed and gate-checked
by the supervisor before the next dispatch):
- P1 `1bcd0a4` spray carrier — raw-UDP 5-tuple rotation, the field-proven shape as a shipped carrier
  (rotation numbers: 98.7-98.8 % delivery, ≤20 pkt/tuple, 15k tuples, 2026-11-20); NAT-shared-IP limitation
  recorded; CI root-job tests.
- P5 `329eb04` auto-test presets — fast (rst/synrst × mci/irancell/cloudflare, ~4-6 min, measured best row
  applies) and reverse-only (~1-2 min) in both managers; --test takes normal|anti|fast|reverse.
- P2 `0d8790e` repair v2 NACK (frRepairAsk 0x11) — implemented, two real bugs found and fixed on the way
  (degenerate repairCover = v1's true no-gain root cause; tx-ring scroll-past made 29/29 asks miss), honest
  verdict: repair stays OFF in every form.
- P3 `95c8e58` -fast-rtx (3-consecutive-gap early retransmit, off by default) + THE PASS'S MAIN RESULT: the
  interactive p99 tail during bulk is QUEUEING/SCHEDULING-BOUND, not loss — clean samples (zero retrans/
  repair) carry the same ~2.5xRTT tail. Future tail work attacks the scheduler/pacer, not recovery.
- P4 `91fae93` — wattun-ptcp-tagged lock-safe iptables rules + doctor orphan check (both managers);
  /stats/history (5 s, 60 entries, loopback-only).
- Review-verdict entries: 5c73d10 (P1), 83c87a9 (P2), b29c621 (P3), this one (P4).

FINAL GATES (supervisor, this checkout): gofmt -l cmd wat testbench empty; go vet ./... and GOOS=linux
build+vet clean; go test -count=1 ./cmd/... ok (wattun 14.0s, mgr 0.8s, wprobe 0.1s); FULL
go test -count=1 -timeout 15m ./wat/ → ok 594.7 s; bash test-manager.sh ALL OK (fox-verified at 2026112105).
NOT runnable here: the Linux-only carriers' loopback tests (ptcp, spray) and the CI jobs (gomgr, icmp root)
— GOOS=linux compile+vet clean; the runs are CI's once the owner pushes. No push/tag/release (owner rule).
Version 3.4.3 (unreleased) now carries: Go-manager completion, coded repair (off), ptcp + spray carriers,
fast-rtx (off), test presets, doctor/fw-tag ops, /stats/history. The release is the owner's call.
Commit: (this commit)

## 2026-11-21 18:30 · supervisor · speed-swarm phase 1 — three diagnostics synthesized; P3 conclusion corrected
Three parallel diagnostic foxes (diagcc / diagprof / diagsched, all read-only on existing files, new test
files only) delivered:
- diagcc: the bulk cap at 0 % loss is the delay-AIMD equilibrium (growth ×1.10 / cut ×0.93 oscillation,
  token-limited 100 % of steady ticks), not any hard limit; wire ceiling ~9.4-9.7 MB/s; InitBps 8e6 → 7.9-8.2,
  +slack 50 ms → 8.3-8.6; MaxBps/Paths/Hedge/WinMax measured no-ops; ACK pressure ~1 % of reverse.
- diagprof: engine CPU is not the ceiling — 75-77 MB/s in-process (145k pkt/s), 0 allocs/pkt steady, 0 GC in
  5 s, s.mu contention 0.56 %, crypto ~11 %; at the field's ~27 MB/s the whole pair costs 5-8 % of one core.
  Only CPU-side shippable: WAT_BATCH-style sendmmsg for the plain udp carrier (opt-in), deferred seals for
  fec/repair under s.mu when those features field-run.
- diagsched: **the P3 "queueing-bound" conclusion was a harness bug** — killLatency sorted latencies after
  appending the class labels, destroying the sample↔class pairing, so "clean" positions indexed the sorted
  slowest third. With pairing fixed (measured, interleaved, identical packet streams): clean echoes during
  bulk p50 40.7 ms / p99 41.3 ms = the no-bulk floor; the echo never queues behind tokens; cross-session
  isolation already works. The REAL tail: (a) token-burst dumps (cc.refill cap rate*0.005+64 KB lets a late
  tick dump ~94 KB; link-queue p99 60 ms, present at 0 % loss), (b) loss-recovery samples (aligned p99
  ~103 ms = lossTime+RTT).
This entry supersedes the P3 "queueing-bound" conclusion: the tail is loss-recovery latency plus
self-induced pacing dumps — both directly attackable. Synthesis and dispatch: harness fix first (unblocks
honest judgement), then the cc.go burst-cap knob (opt-in) and the AIMD equilibrium tune, each judged by the
fixed harness with numbers; ICMP untouched; full wat suite the gate.
Diag files (diagcc_test.go, diagprof_test.go, diagsched_test.go) committed as permanent measurement tools —
all green (`go test -count=1 -run 'DiagCC|DiagSched|DiagProf' ./wat/`), gofmt clean.
Commit: (this commit)
