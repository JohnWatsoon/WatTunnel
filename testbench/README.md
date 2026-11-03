# testbench — fake-SNI injection bench

Answers one question: **does a given fake-SNI injection mode (`-fake-mode`) let a simulated large-ClientHello-
dropping / non-TLS-dropping / throttling DPI carry the tunnel's data, and at what rate?**

The bench is three moving parts, all on the local machine:

```
 wattun client ──tcp──▶ emulate_dpi.py ──tcp──▶ wattun server
 (metrics :19720)        (the "censor")          (metrics :19721)
```

`emulate_dpi.py` is a userspace TCP proxy that applies a configurable censor rule set to every flow and models
what the censor would see for each `-fake-mode`. `measure.sh` starts the server, the emulator and the client,
waits for the tunnel, runs the built-in `/speedtest` down and up through it, reads `/stats`, and prints one CSV row
per (mode, rule profile). `deploy.sh` is the same measurement on the owner's live pair (Iran client → Kharej
server) and is run by the Lead, not by this bench.

## Quick start

```sh
# Git Bash on Windows (from the repo root), or any POSIX shell on Linux:
testbench/measure.sh > testbench/out/measured.csv
```

That runs `none seq ttl sum seqsum rst` against the five default rule profiles and prints:

```
mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans
seq,www.example.com,base,31.323,29.823,1,1
seq,www.example.com,wincheck,0.000,0.000,0,1
...
```

- `mode` — the `-fake-mode` being modelled (`none` = no fake, the control).
- `dpi_rule` — the emulator rule profile (see below).
- `mb_per_s_down` / `mb_per_s_up` — the client's `/speedtest?dir=down|up` result through the tunnel.
- `alive` — the client `/stats` `alive` field: 1 means the tunnel carried data through the emulator.
- `retrans` — the client `/stats` `retrans` counter at collection time (`-1` if `/stats` was unreachable).

Useful variants:

```sh
testbench/measure.sh -m "seq sum" -r "base throttle"   # two modes, two profiles
testbench/measure.sh -s www.example.com -n 8           # fake SNI, 8 MB per speedtest direction
testbench/measure.sh -r all -m "none seq ttl sum seqsum rst split" -n 2
```

Everything is sequential: one server + emulator + client at a time, on fixed loopback ports
(`SERVER_PORT=38443`, `EMU_PORT=38444`, client metrics `19720`). Override them through the environment when two
runs must share a machine.

### Prerequisites

- `python3` (or `python`; the script finds a working one), `curl`, and a POSIX `sh`.
- The wattun binary: `measure.sh` uses `dist/wattun-windows-amd64.exe` on MSYS/MinGW/Cygwin and
  `dist/wattun-linux-amd64` elsewhere, and builds it with `build.sh` when missing (`BIN=...` overrides).
- Go only for `testbench/hello_dump`, which dumps the exact `wat.FakeClientHello` bytes for the emulator. Without
  Go the emulator builds an equivalent ClientHello itself.
- **No root and no CAP_NET_RAW** are needed for the local bench: the client runs *without* `-fake-sni` and the
  emulator models the DPI's view of the fake (see “What this bench does not prove”).

## Files

| file | what it is |
|---|---|
| `emulate_dpi.py` | the censor: TCP proxy + rules + per-mode injection model + JSONL flow log + `--self-test` |
| `measure.sh` | one-command driver: server → emulator → client → `/stats` + `/speedtest` → CSV |
| `deploy.sh` | build + scp + `systemd-run` + collect on the live Iran/Kharej pair (Lead runs this) |
| `hello_dump/main.go` | prints `sni <base64>` lines of the real `wat.FakeClientHello` for the emulator |
| `out/` | logs, per-flow JSONL verdicts, raw `/stats` and `/speedtest` JSON, `measured*.csv` (git-ignored) |

## The emulator: rules

Every rule is switchable, so the same tunnel run can be replayed against different middlebox classes. Defaults
model the allowlist DPI class from the 2026-01/10 field reports (it parses the first flight, it does not validate
sequence numbers or checksums, and it drops flows it cannot parse).

| rule | flag / default | what it does on the wire |
|---|---|---|
| large ClientHello | `--max-hello 1000` | drops a flow whose TLS ClientHello record is longer than N bytes. Models a filter that drops big hellos outright (the `-tls-small-ch` finding). |
| non-TLS payload | on by default (`--allow-nontls` turns it off) | drops a flow whose first client payload is not a parseable TLS ClientHello. This is what kills a raw `tcp`/`ws`/`h2c` carrier tunnel without a fake. |
| SNI allowlist | `--whitelist www.example.com` (`--no-whitelist` off) | allows a ClientHello whose SNI is listed, and exempts it from the other rules; drops a ClientHello whose SNI is not listed. |
| throttle | `--throttle-bps 0` off, `--throttle-after 2`, `--throttle-dir c2s` | after M seconds of a flow, paces client→server (or both) bytes to K B/s. |
| window check | `--window-check` off | a DPI that validates TCP sequence numbers and so discards a marker below the stream start. |
| checksum check | `--checksum-check` off | a DPI that validates the TCP checksum and so discards an in-window marker with a damaged checksum. |
| no reassembly | `--no-reassemble` off | a DPI that parses only the first TCP segment, so a hello split around the SNI is unparseable. |

Order of evaluation: injected-mode verdict → else first payload → non-TLS / large-hello / SNI allowlist. The
throttle applies to every allowed flow.

## The emulator: what each `-fake-mode` looks like to the DPI

`--inject-fake MODE` makes the emulator decide per flow whether the marker that mode emits survives the enabled
validation rules; if it does, the DPI classifies the flow from the fake ClientHello (exact `wat.FakeClientHello`
bytes via `--fake-hello`), otherwise it falls back to the real first payload. This is a model of the *wire view of
the censor*, not of the injector code (the injector needs Linux + CAP_NET_RAW; see below).

| `-fake-mode` | what the DPI sees | classified as TLS-to-allowed when |
|---|---|---|
| `none` | the real first payload (non-TLS on the raw tcp carrier) | never (the non-TLS rule drops it) |
| `seq` | full fake ClientHello with a valid checksum, sequence below the stream start | the DPI does not validate sequence numbers (`--window-check` off) |
| `ttl` | same wire bytes as `seq`, fake TTL dies before the server; the censor's hop still sees it | the DPI does not validate sequence numbers |
| `sum` | full fake ClientHello, in-window sequence, damaged TCP checksum | the DPI reads payloads before checksum validation (`--checksum-check` off) |
| `seqsum` | both markers ~1 ms apart (below-window valid-checksum + in-window bad-checksum) | the DPI fails to drop at least one of them |
| `rst` | a RST|ACK with a damaged checksum; no ClientHello at all | never — this mode clears middlebox state, it cannot whitelist the flow. A checksum-validating DPI ignores the RST and the real payload decides; a trusting one forgets the flow and inspects the real payload as if fresh (dropped by the non-TLS rule unless censorship is off) |
| `split` | the fake hello in several TCP segments (1-byte first segment) | the DPI reassembles the stream *and* does not validate sequence numbers |

## Rule profiles used by `measure.sh`

| profile | emulator flags | middlebox it models |
|---|---|---|
| `base` | defaults | allowlist DPI: parses the first flight, no window/checksum validation (the common MCI/Irancell-class filter) |
| `wincheck` | `--window-check` | DPI that discards out-of-window segments |
| `cksumcheck` | `--checksum-check` | DPI that validates TCP checksums |
| `strict` | `--window-check --checksum-check --no-reassemble` | fully validating DPI (all three markers defeated) |
| `throttle` | `--throttle-bps 262144 --throttle-after 0` | allowlist DPI that throttles an allowed flow's upload to 256 KiB/s (per flow) |
| `open` | `--allow-nontls --no-whitelist` | no censorship: the harness's own ceiling |
| `smallhello` | `--max-hello 256` | DPI that drops any ClientHello over 256 B, allowlist or not |

`--throttle-after` is 0 in the `throttle` profile because a 1 MB local upload finishes in ~0.1 s, long before a
2 s delay would end; M only decides when pacing starts, the cap is the same.

## Outputs

`out/` keeps, per (mode, profile):

- `emu-<mode>-<profile>.log` — `DPI_READY` line with the active rules, one `DPI_FLOW {...}` JSON line per flow with
  the verdict (`allow`/`block`), the rule that decided it, the parsed SNI and the fake length, one `DPI_END` line per
  flow with byte counts, and a `DPI_SUMMARY` line.
- `flows-<mode>-<profile>.jsonl` — the same flow records as JSONL, for assertions:
  `grep -c '"verdict":"allow"' out/flows-seq-base.jsonl`.
- `stats-…json`, `down-…json`, `up-…json` — raw `/stats` and `/speedtest` responses.
- `self-test.log` — the emulator's classifier self-test (29 asserts, 33 with a hello dump; `measure.sh` refuses to run if it fails).

`measure.sh` prints only the CSV on stdout; progress goes to stderr.

## Self-test and one-off verdict checks

```sh
python3 testbench/emulate_dpi.py --self-test
go run ./testbench/hello_dump -sni www.example.com | python3 testbench/emulate_dpi.py --self-test --fake-hello /dev/stdin
```

The self-test asserts the hello parser, every rule, and the per-mode verdicts (29 checks without a hello dump, 33
with one). Watch `DPI_FLOW` lines for per-flow verdicts: run the emulator with `--inject-fake MODE` and read them.

## What this bench proves, and what it does not

Proves, locally and repeatably: the data path through a real wattun server/client pair works or dies according to
a documented, inspectable censor rule set, and the per-mode verdict is logged; the exact `wat.FakeClientHello`
bytes parse as a modern TLS ClientHello with the right SNI and are small enough (359–360 B for the tested SNIs) for
a 1000 B hello limit but not for a 256 B one.

Does **not** prove: that the raw-socket injector (`wat/desync_linux.go`, AF_PACKET) is correct, or that the real
Iranian filter behaves like any profile. Injection needs Linux + CAP_NET_RAW; on Windows `wat.NewDesync` fails at
startup by design, so the local client here runs without `-fake-sni` and the emulator supplies the per-mode
verdict. Run `deploy.sh` on the live pair for the real thing; measurements are recorded in `docs/TECHNICAL.md`
("Field numbers"), and this bench is a model, not the injector.

## Live-pair run (Lead)

`deploy.sh` builds `dist/wattun-linux-amd64`, scp's it plus a generated config to both hosts, starts the units
with `systemd-run --unit=wat-bench-{server,client} --collect`, and reads `/stats` + `/speedtest` through an ssh
`curl` to the client's loopback metrics address. It never commits, pushes, or builds on a host.

```sh
export SSH_KEY=$HOME/.ssh/id_ed25519 IRAN=192.0.2.10 KHAREJ=198.51.100.20 PSK='...'
testbench/deploy.sh build
testbench/deploy.sh server
testbench/deploy.sh client seq
testbench/deploy.sh collect seq          # one CSV row, dpi_rule=live
testbench/deploy.sh all                  # seq ttl sum seqsum rst in one CSV
testbench/deploy.sh stop
```

For `-fake-mode ttl`, set `FAKE_TTL=<hop count>` (the emulator's `--window-check` note applies: `ttl` mode also
uses a below-window sequence number, so it needs a DPI that does not validate windows, plus a TTL that expires one
hop before the server). `CARRIER=tcp|tls|ws|wss|h2|grpc` selects the pool carrier; the fake-SNI layer covers all
of them on Linux.
