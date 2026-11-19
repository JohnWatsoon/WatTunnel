#!/usr/bin/env python3
"""emulate_dpi.py - a userspace censorship middlebox (DPI) emulator for the WatTunnel fake-SNI bench.

It is a TCP proxy between a wattun client and a wattun server that applies four censor rules to every flow and,
optionally, models what the censor would see when a fake-SNI injection mode fires. The point is to answer one
question: does a given -fake-mode let a simulated large-ClientHello-dropping / non-TLS-dropping / throttling DPI
carry the tunnel's data, and at what rate? Per-flow verdicts are logged to stderr (and optionally a JSONL file) so
a shell test can assert on them.

Rules (each switchable):

  large-hello   a TLS ClientHello record longer than --max-hello bytes is dropped.
  non-TLS       a flow whose first client payload is not a parseable TLS ClientHello is dropped.
  sni-allowlist a ClientHello whose SNI is in --whitelist is allowed (and exempt from large-hello/non-TLS);
                a ClientHello whose SNI is not in the list is dropped. --no-whitelist turns the list off.
  throttle      after --throttle-after seconds, client->server (or both) bytes are paced to --throttle-bps.

DPI validation knobs (a "dumb" middlebox leaves them off, on the target Iranian paths most of them are off):
  --window-check     a fake data segment below the flow's stream start is discarded (kills seq/ttl/split markers)
  --checksum-check   a packet with a bad TCP checksum is discarded (kills sum/seqsum's sum marker, rst)
  --no-reassemble    the DPI only parses the first TCP segment, not a reassembled stream (kills split)

Injection simulation (--inject-fake MODE): the client in this bench cannot inject raw packets on Windows or
without CAP_NET_RAW, so the emulator plays the DPI's part: it decides, per mode, whether the marker this mode emits
survives the DPI's validation knobs. If it survives, the flow is classified from the fake hello (see below); if it
does not, the flow is classified from the real first payload (which for the raw tcp carrier is not TLS -> blocked).
Modes modelled: none, seq, ttl, sum, seqsum, rst, split. This is a model of the wire, not the injector itself; the
injector is exercised only on Linux with CAP_NET_RAW (testbench/deploy.sh on the live pair).

Hello bytes: --fake-hello FILE reads "sni <base64>" lines dumped from the real wat.FakeClientHello builder by
testbench/hello_dump, so the emulator classifies the exact bytes wat emits. Without it the emulator builds an
equivalent ClientHello itself (self-test checks it parses back).

Usage:
  python3 testbench/emulate_dpi.py --listen 127.0.0.1:18444 --target 127.0.0.1:18443 \
      --inject-fake seq --fake-sni www.example.com --whitelist www.example.com \
      --json-log testbench/out/flows.jsonl
Self-test (asserts on the classifiers; exit 1 on failure):
  python3 testbench/emulate_dpi.py --self-test
"""

import argparse
import asyncio
import base64
import itertools
import json
import struct
import sys
import time

# ----------------------------------------------------------------------------------------------- TLS ClientHello

TLS_HANDSHAKE = 0x16


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def _u24(b, i):
    return (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]


def build_client_hello(sni):
    """Build a modern TLS 1.3 ClientHello record with the same extension set as wat.FakeClientHello.

    It does not need to be byte-identical to the Go one (data/hello_*.b64 from testbench/hello_dump is, and
    --fake-hello uses it); it exists so the emulator and its self-test work without a Go toolchain.
    """
    name = sni.encode()
    ext = b""
    # server_name (0x0000)
    sn = b"\x00" + struct.pack(">H", len(name)) + name
    body = struct.pack(">H", len(sn)) + sn
    ext += struct.pack(">H", 0) + struct.pack(">H", len(body)) + body
    # supported_versions (0x002b): TLS 1.3, TLS 1.2
    ext += b"\x00\x2b" + struct.pack(">H", 5) + b"\x04\x03\x04\x03\x03"
    # alpn (0x0010): h2, http/1.1
    alpn = b"\x00\x0c\x02h2\x08http/1.1"
    ext += b"\x00\x10" + struct.pack(">H", len(alpn)) + alpn
    # supported_groups (0x000a): x25519, secp256r1, secp384r1
    ext += b"\x00\x0a" + struct.pack(">H", 8) + b"\x00\x06\x00\x1d\x00\x17\x00\x18"
    # key_share (0x0033): x25519
    ks = b"\x00\x24\x00\x1d\x00\x20" + b"\x11" * 32
    ext += b"\x00\x33" + struct.pack(">H", len(ks)) + ks
    # signature_algorithms (0x000d)
    ext += b"\x00\x0d" + struct.pack(">H", 8) + b"\x00\x06\x04\x03\x08\x04\x04\x01"
    # psk_key_exchange_modes (0x002d)
    ext += b"\x00\x2d" + struct.pack(">H", 2) + b"\x01\x01"
    # encrypted_client_hello GREASE (0xfe0d), like wat.FakeClientHello
    ech = b"\x00" + b"\x00\x01\x00\x01" + b"\x00" + b"\x00\x20" + b"\x22" * 32 + b"\x00\x60" + b"\x33" * 96
    ext += b"\xfe\x0d" + struct.pack(">H", len(ech)) + ech

    body = b"\x03\x03" + b"\x44" * 32  # version + random
    body += b"\x20" + b"\x55" * 32  # session id
    suites = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x23"
    body += struct.pack(">H", len(suites)) + suites
    body += b"\x01\x00"  # compression: null
    body += struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return bytes([TLS_HANDSHAKE, 3, 1]) + struct.pack(">H", len(hs)) + hs


def parse_client_hello(data):
    """Parse the start of a client payload as a TLS ClientHello record.

    Returns None when it is not a TLS handshake record; otherwise
    {"record_len": int, "complete": bool, "sni": str|None, "error": str|None}.
    """
    if len(data) < 5:
        return None
    if data[0] != TLS_HANDSHAKE or data[1] != 3:
        return None
    rec_len = _u16(data, 3)
    out = {"record_len": rec_len, "complete": False, "sni": None, "error": None}
    if len(data) < 5 + rec_len:
        out["error"] = "short-record"
        return out
    hs = data[5:5 + rec_len]
    if len(hs) < 4 or hs[0] != 1:
        out["error"] = "not-clienthello"
        return out
    hs_len = _u24(hs, 1)
    if len(hs) < 4 + hs_len:
        out["error"] = "short-handshake"
        return out
    p = 4 + 2 + 32
    if len(hs) < p + 1:
        out["error"] = "truncated"
        return out
    p += 1 + hs[p]  # session id
    if len(hs) < p + 2:
        out["error"] = "truncated"
        return out
    cs = _u16(hs, p)
    p += 2 + cs
    if len(hs) < p + 1:
        out["error"] = "truncated"
        return out
    p += 1 + hs[p]  # compression methods
    if len(hs) < p + 2:
        out["error"] = "truncated"
        return out
    ext_len = _u16(hs, p)
    p += 2
    end = min(p + ext_len, len(hs))
    off = p
    while off + 4 <= end:
        typ = _u16(hs, off)
        sz = _u16(hs, off + 2)
        if typ == 0:  # server_name
            q = off + 4
            if q + 5 <= len(hs):
                nl = _u16(hs, q + 3)
                if q + 5 + nl <= len(hs):
                    out["sni"] = hs[q + 5:q + 5 + nl].decode("ascii", "replace")
                    out["complete"] = True
                    return out
            out["error"] = "bad-server-name"
            break
        off += 4 + sz
    # no server_name extension: a valid TLS hello, just without an SNI
    out["complete"] = True
    out["error"] = "no-sni"
    return out


# ----------------------------------------------------------------------------------------------- rules

def load_fake_hellos(path):
    hellos = {}
    if not path:
        return hellos
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                raise SystemExit(f"{path}: want 'sni base64' lines, got {line!r}")
            hellos[parts[0]] = base64.b64decode(parts[1])
    return hellos


def fake_hello_for(args, sni):
    if sni in args.fake_hellos:
        return args.fake_hellos[sni]
    return build_client_hello(sni)


def classify_payload(data, args):
    """Classify a first client payload under the censor rules. Returns (verdict, rule, sni)."""
    ch = parse_client_hello(data)
    if ch is None:
        return ("block" if args.drop_nontls else "allow"), "non-tls", None
    if ch["record_len"] > args.max_hello:
        return "block", "large-hello", ch.get("sni")
    if not ch["complete"]:
        return ("block" if args.drop_nontls else "allow"), "truncated-hello", None
    sni = ch["sni"]
    if args.whitelist is not None:
        if sni in args.whitelist:
            return "allow", "sni-whitelist", sni
        return ("block" if args.drop_nontls else "allow"), "sni-not-whitelisted", sni
    return "allow", "tls", sni


def sim_marker_survives(mode, args):
    """Does a fake marker of this mode survive the DPI's packet validation? None = the client sent no fake
    (mode none), or the fake is discarded so the DPI classifies the real first payload instead. "clear" = the fake
    was honoured: a stateful middlebox forgets the flow and inspects its first payload again (rst/synrst)."""
    if mode == "none":
        return None
    if mode in ("rst", "synrst"):
        # RST+ACK / SYN|RST with a damaged checksum: a checksum-validating DPI drops it and nothing changes; a
        # DPI that trusts it clears the flow's state, so the next payload is inspected as if fresh.
        return "clear" if not args.checksum_check else None
    if mode in ("seq", "ttl", "hlen0"):
        return not args.window_check
    if mode == "sum":
        return not args.checksum_check
    if mode == "seqsum":
        # two markers: below-window valid-checksum and in-window bad-checksum; a filter must drop both.
        return not args.window_check or not args.checksum_check
    if mode == "split":
        # segments split around the SNI: the marker is below the stream start (seq trick) and the SNI sits in
        # a later segment, so both reassembly and window checking decide it.
        return not args.window_check and not args.no_reassemble
    if mode == "ff":
        # fragmented F&F record+segment plan: every ff sequence number is BELOW the stream start the
        # server holds (wat/desync.go fireFFLocked), so a window-checking middlebox discards the
        # segments outright — reassembly alone does not save it (2026-11-20 review F11; the old model
        # let ff survive a window-checking DPI the real markers cannot).
        return not args.window_check and not args.no_reassemble
    if mode in ("fakeip", "paws"):
        # separate SYN/hello to a whitelisted IP or valid-checksum stale-TSval segment: survives window & checksum.
        return True
    if mode == "all":
        # all four markers (seq, sum, hlen0, ff) are below-window or bad-checksum, so window+checksum
        # DPI blocks it regardless of reassembly (2026-11-20 review F12: the old third term stood for
        # ff, which is window-sensitive like seq — see F11).
        return not args.window_check or not args.checksum_check
    raise SystemExit(f"emulate_dpi.py: unknown --inject-fake mode {mode!r} "
                     "(modelled: none seq ttl sum seqsum rst split hlen0 fakeip synrst paws ff all)")


def decide(flow, data, args):
    """Return (verdict, rule, sni, fake_len). Reads no args state except the rules."""
    mode = args.inject_fake
    survives = sim_marker_survives(mode, args)
    if survives == "clear":
        verdict, rule, sni = classify_payload(data, args)
        return verdict, "rst-cleared/" + rule, sni, 0
    if survives:
        hello = fake_hello_for(args, args.fake_sni)
        verdict, rule, sni = classify_payload(hello, args)
        rule = "fake-" + mode if rule in ("sni-whitelist", "tls") else "fake-" + mode + "/" + rule
        return verdict, rule, sni, len(hello)
    verdict, rule, sni = classify_payload(data, args)
    if mode != "none":
        rule = "no-fake/" + rule
    return verdict, rule, sni, 0


# ----------------------------------------------------------------------------------------------- proxy

class Flow:
    def __init__(self, fid, peer, args):
        self.fid = fid
        self.peer = peer
        self.args = args
        self.started = time.monotonic()
        self.c2s = 0
        self.s2c = 0
        self.verdict = None
        self.rule = None
        self.sni = None
        self.fake_len = 0
        self.first_len = 0
        # token bucket, serialized across directions when --throttle-dir both
        self.tokens = 0.0
        self.last = self.started
        self.throttled = False
        self._pace_lock = asyncio.Lock()

    def log(self, verdict, rule, sni, fake_len, note=""):
        self.verdict, self.rule, self.sni, self.fake_len = verdict, rule, sni, fake_len
        rec = {
            "flow": self.fid, "peer": self.peer, "mode": self.args.inject_fake,
            "verdict": verdict, "rule": rule, "sni": sni,
            "fake_len": fake_len, "first_len": self.first_len,
            "elapsed_ms": int((time.monotonic() - self.started) * 1000),
        }
        if note:
            rec["note"] = note
        line = "DPI_FLOW " + json.dumps(rec, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        if self.args.json_log:
            with open(self.args.json_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def log_end(self):
        rec = {"flow": self.fid, "verdict": self.verdict, "c2s_bytes": self.c2s, "s2c_bytes": self.s2c,
               "elapsed_ms": int((time.monotonic() - self.started) * 1000), "throttled": self.throttled}
        line = "DPI_END " + json.dumps(rec, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        if self.args.json_log:
            with open(self.args.json_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    async def pace(self, n):
        """Throttle bytes: K bytes/s after M seconds, measured from flow start."""
        if self.args.throttle_bps <= 0:
            return
        if time.monotonic() - self.started < self.args.throttle_after:
            return
        async with self._pace_lock:
            self.throttled = True
            rate = self.args.throttle_bps
            while n > 0:
                now = time.monotonic()
                self.tokens = min(rate * 0.5, self.tokens + rate * (now - self.last))
                self.last = now
                if self.tokens < 1:
                    await asyncio.sleep(0.01)
                    continue
                use = min(n, self.tokens)
                self.tokens -= use
                n -= use


class DPI:
    def __init__(self, args):
        self.args = args
        self.ids = itertools.count(1)
        self.flows = 0
        self.allowed = 0
        self.blocked = 0
        self.throttled = 0

    async def handle(self, creader, cwriter):
        peer = cwriter.get_extra_info("peername")
        peer = f"{peer[0]}:{peer[1]}" if peer else "?"
        flow = Flow(next(self.ids), peer, self.args)
        self.flows += 1
        thost, tport = self.args.target
        try:
            treader, twriter = await asyncio.open_connection(thost, tport)
        except OSError as e:
            flow.log("block", "target-unreachable", None, 0, note=str(e))
            self.blocked += 1
            cwriter.close()
            return
        state = {"decided": False, "stop": False}

        async def c2s():
            while True:
                data = await creader.read(65536)
                if not data:
                    try:
                        twriter.write_eof()
                    except OSError:
                        pass
                    return
                if not state["decided"]:
                    state["decided"] = True
                    flow.first_len = len(data)
                    verdict, rule, sni, fake_len = decide(flow, data, self.args)
                    flow.log(verdict, rule, sni, fake_len)
                    if verdict == "block":
                        self.blocked += 1
                        state["stop"] = True
                        try:
                            cwriter.close()
                            twriter.close()
                        except OSError:
                            pass
                        return
                    self.allowed += 1
                flow.c2s += len(data)
                await flow.pace(len(data))
                if state["stop"]:
                    return
                twriter.write(data)
                try:
                    await twriter.drain()
                except OSError:
                    return

        async def s2c():
            while True:
                try:
                    data = await treader.read(65536)
                except OSError:
                    return
                if not data:
                    try:
                        cwriter.write_eof()
                    except OSError:
                        pass
                    return
                flow.s2c += len(data)
                if self.args.throttle_bps > 0 and self.args.throttle_dir == "both":
                    await flow.pace(len(data))
                if state["stop"]:
                    return
                cwriter.write(data)
                try:
                    await cwriter.drain()
                except OSError:
                    return

        try:
            await asyncio.gather(c2s(), s2c(), return_exceptions=True)
        finally:
            if flow.throttled:
                self.throttled += 1
            flow.log_end()
            try:
                cwriter.close()
                twriter.close()
            except OSError:
                pass

    def summary(self):
        print(f"DPI_SUMMARY flows={self.flows} allowed={self.allowed} blocked={self.blocked} "
              f"throttled={self.throttled}", file=sys.stderr, flush=True)


async def amain(args):
    host, port = args.listen
    dpi = DPI(args)
    server = await asyncio.start_server(dpi.handle, host, port)
    rules = []
    if args.max_hello:
        rules.append(f"large-hello>{args.max_hello}")
    if args.drop_nontls:
        rules.append("drop-non-tls")
    if args.whitelist is not None:
        rules.append("sni-allowlist=" + ",".join(sorted(args.whitelist)))
    if args.window_check:
        rules.append("window-check")
    if args.checksum_check:
        rules.append("checksum-check")
    if args.no_reassemble:
        rules.append("no-reassemble")
    if args.throttle_bps:
        rules.append(f"throttle={args.throttle_bps}B/s-after-{args.throttle_after}s-{args.throttle_dir}")
    rules.append("inject=" + args.inject_fake)
    print(f"DPI_READY listen={host}:{port} target={args.target[0]}:{args.target[1]} rules=[{'; '.join(rules)}]",
          flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        dpi.summary()


def _split_addr(s):
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest.lstrip(":")
        return (host or "::1"), int(port)
    host, _, port = s.rpartition(":")
    if not host:
        host = "127.0.0.1"
    return host, int(port)


class _Args:
    pass


def parse_args(argv):
    ap = argparse.ArgumentParser(description="userspace DPI emulator for the WatTunnel fake-SNI bench")
    ap.add_argument("--listen", default="127.0.0.1:18444")
    ap.add_argument("--target", default="127.0.0.1:18443")
    ap.add_argument("--max-hello", type=int, default=1000, help="drop ClientHellos with a record longer than this")
    ap.add_argument("--whitelist", default="www.example.com",
                    help="comma-separated allowlisted SNIs (the fake hello must carry one of these)")
    ap.add_argument("--no-whitelist", action="store_true", help="no SNI allowlist: any parseable TLS hello passes")
    ap.add_argument("--allow-nontls", action="store_true", help="do not drop non-TLS-looking client payloads")
    ap.add_argument("--throttle-bps", type=int, default=0, help="pace bytes/s on allowed flows (0 = off)")
    ap.add_argument("--throttle-after", type=float, default=2.0, help="seconds after flow start before pacing")
    ap.add_argument("--throttle-dir", choices=["c2s", "both"], default="c2s")
    ap.add_argument("--inject-fake", default="none",
                    choices=["none", "seq", "ttl", "sum", "seqsum", "rst", "split", "hlen0", "fakeip", "synrst", "paws", "ff", "all"],
                    help="fake-SNI mode the DPI is asked to model")
    ap.add_argument("--fake-sni", default="www.example.com")
    ap.add_argument("--fake-hello", default="", help='"sni base64" lines from testbench/hello_dump')
    ap.add_argument("--window-check", action="store_true")
    ap.add_argument("--checksum-check", action="store_true")
    ap.add_argument("--no-reassemble", action="store_true")
    ap.add_argument("--json-log", default="")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.no_whitelist:
        a.whitelist = None
    else:
        a.whitelist = {s.strip() for s in a.whitelist.split(",") if s.strip()}
    a.drop_nontls = not a.allow_nontls
    a.listen = _split_addr(a.listen)
    a.target = _split_addr(a.target)
    a.fake_hellos = load_fake_hellos(a.fake_hello)
    return a


# ----------------------------------------------------------------------------------------------- self-test

def self_test(args):
    """Assert-based check of the classifier and every modelled mode. Exit code 1 on the first failure."""
    checks = 0

    def ok(cond, msg):
        nonlocal checks
        checks += 1
        if not cond:
            print(f"SELFTEST FAIL: {msg}", file=sys.stderr)
            sys.exit(1)

    built = build_client_hello("www.example.com")
    ch = parse_client_hello(built)
    ok(ch is not None and ch["complete"] and ch["sni"] == "www.example.com", "built hello parses with its SNI")
    ok(len(built) == 5 + _u16(built, 3), "built hello record length matches its payload")
    ok(len(built) < 1000, f"built hello is small ({len(built)} B)")
    ok(parse_client_hello(b"\x57\x41\x54\x01\x00") is None, "wattun wire header is not TLS")

    if args.fake_hellos:
        for sni, hello in args.fake_hellos.items():
            ch = parse_client_hello(hello)
            ok(ch is not None and ch["complete"] and ch["sni"] == sni,
               f"wat.FakeClientHello({sni}) parses back with its SNI (is the dumped file stale?)")
            ok(len(hello) <= args.max_hello, f"wat.FakeClientHello({sni}) is under --max-hello ({len(hello)} B)")

    # allowed / blocked classifier
    verdict, rule, _ = classify_payload(built, _mkargs(whitelist={"www.example.com"}))
    ok(verdict == "allow" and rule == "sni-whitelist", "allowlisted SNI -> allow")
    verdict, rule, _ = classify_payload(built, _mkargs(whitelist={"other.example"}))
    ok(verdict == "block" and rule == "sni-not-whitelisted", "non-allowlisted SNI -> block")
    verdict, rule, _ = classify_payload(built, _mkargs(whitelist={"www.example.com"}, max_hello=100))
    ok(verdict == "block" and rule == "large-hello", "large hello -> block even when allowlisted")
    verdict, rule, _ = classify_payload(built, _mkargs(whitelist=None, max_hello=100))
    ok(verdict == "block" and rule == "large-hello", "large hello -> block with no allowlist")
    verdict, rule, _ = classify_payload(built, _mkargs(whitelist=None))
    ok(verdict == "allow" and rule == "tls", "small TLS hello with no allowlist -> allow")
    verdict, rule, _ = classify_payload(b"A" * 64, _mkargs(whitelist={"www.example.com"}))
    ok(verdict == "block" and rule == "non-tls", "non-TLS payload -> block")
    verdict, rule, _ = classify_payload(b"A" * 64, _mkargs(whitelist={"www.example.com"}, drop_nontls=False))
    ok(verdict == "allow" and rule == "non-tls", "non-TLS payload with --allow-nontls -> allow")
    ok(parse_client_hello(built[:-10])["complete"] is False, "truncated hello is not complete")

    # mode semantics: what the DPI sees under each validation knob
    base = dict(whitelist={"www.example.com"}, max_hello=1000, drop_nontls=True,
                window_check=False, checksum_check=False, no_reassemble=False, inject_fake="none")
    m = _mkargs(**base)

    def mode_verdict(mode, **kw):
        a = _mkargs(**{**base, **kw, "inject_fake": mode})
        return decide(None, b"A" * 64, a)  # real payload is non-TLS

    ok(mode_verdict("none")[0] == "block", "none: DPI sees non-TLS wire -> block")
    ok(mode_verdict("seq")[0] == "allow", "seq marker read by a DPI without window checks -> allow")
    ok(mode_verdict("seq", window_check=True)[0] == "block", "seq marker discarded by window-checking DPI")
    ok(mode_verdict("ttl")[0] == "allow", "ttl marker is seen at the censor hop -> allow")
    ok(mode_verdict("ttl", window_check=True)[0] == "block", "ttl marker is still below the window")
    ok(mode_verdict("sum")[0] == "allow", "sum marker read before checksum validation -> allow")
    ok(mode_verdict("sum", checksum_check=True)[0] == "block", "sum marker discarded by checksum-validating DPI")
    ok(mode_verdict("seqsum", checksum_check=True)[0] == "allow", "seqsum survives a checksum-only DPI")
    ok(mode_verdict("seqsum", window_check=True)[0] == "allow", "seqsum survives a window-only DPI")
    ok(mode_verdict("seqsum", window_check=True, checksum_check=True)[0] == "block",
       "seqsum dies on a DPI that checks both")
    ok(mode_verdict("rst")[0] == "block" and mode_verdict("rst")[1].startswith("rst-cleared/"),
       "rst: a trusting DPI clears the flow, the real non-TLS payload is then dropped -> block")
    ok(mode_verdict("rst", checksum_check=True)[0] == "block",
       "rst: checksum-checking DPI ignores the RST, but there is no hello -> block")
    ok(mode_verdict("rst", drop_nontls=False, whitelist=None)[0] == "allow",
       "rst under no censorship: state cleared, nothing blocks the real payload -> allow")
    ok(mode_verdict("split")[0] == "allow", "split: reassembling DPI parses the hello -> allow")
    ok(mode_verdict("split", no_reassemble=True)[0] == "block", "split: non-reassembling DPI -> block")
    ok(mode_verdict("split", window_check=True)[0] == "block", "split: below-window segments are discarded")
    ok(mode_verdict("seq", whitelist={"other.example"})[0] == "block",
       "seq with a non-allowlisted fake SNI -> block")
    ok(mode_verdict("hlen0")[0] == "allow" and mode_verdict("hlen0", window_check=True)[0] == "block",
       "hlen0 dies under window checks")
    ok(mode_verdict("ff")[0] == "allow" and mode_verdict("ff", no_reassemble=True)[0] == "block",
       "ff relies on reassembly")
    ok(mode_verdict("ff", window_check=True)[0] == "block",
       "ff: below-window segments die under window checks (F11)")
    ok(mode_verdict("paws", window_check=True, checksum_check=True)[0] == "allow",
       "paws survives window + checksum validation")
    ok(mode_verdict("fakeip", window_check=True, checksum_check=True)[0] == "allow",
       "fakeip survives window + checksum validation")
    ok(mode_verdict("synrst")[0] == "block" and mode_verdict("synrst")[1].startswith("rst-cleared/"),
       "synrst clears flow when checksum unchecked")
    ok(mode_verdict("all", window_check=True, checksum_check=True)[0] == "block",
       "all: window+checksum DPI blocks every marker incl. ff (F12)")
    ok(mode_verdict("all", window_check=True, checksum_check=True, no_reassemble=True)[0] == "block",
       "all: still blocked with reassembly off")
    ok(_split_addr("[::1]:18444") == ("::1", 18444), "_split_addr handles bracketed IPv6")

    print(f"SELFTEST OK ({checks} checks)")
    return 0


def _mkargs(**kw):
    a = _Args()
    a.whitelist = kw.get("whitelist", {"www.example.com"})
    a.max_hello = kw.get("max_hello", 1000)
    a.drop_nontls = kw.get("drop_nontls", True)
    a.window_check = kw.get("window_check", False)
    a.checksum_check = kw.get("checksum_check", False)
    a.no_reassemble = kw.get("no_reassemble", False)
    a.inject_fake = kw.get("inject_fake", "none")
    a.fake_sni = kw.get("fake_sni", "www.example.com")
    a.fake_hellos = kw.get("fake_hellos", {})
    a.throttle_bps = kw.get("throttle_bps", 0)
    a.throttle_after = kw.get("throttle_after", 2.0)
    a.throttle_dir = kw.get("throttle_dir", "c2s")
    a.json_log = ""
    a.listen = ("127.0.0.1", 18444)
    a.target = ("127.0.0.1", 18443)
    return a


def main():
    args = parse_args(sys.argv[1:])
    if args.self_test:
        sys.exit(self_test(args))
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
