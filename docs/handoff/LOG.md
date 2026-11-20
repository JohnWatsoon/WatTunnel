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
