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
