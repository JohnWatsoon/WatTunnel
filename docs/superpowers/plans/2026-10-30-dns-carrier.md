# DNS Carrier (Blackout Lifeline) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `dns` carrier and a DNS bulletin board so the tunnel crosses a full blackout (B0: no foreign IP reachable) via domestic recursive resolvers → the Kharej server as authoritative NS.

**Architecture:** One new carrier pair in the house style of `carrier_udp.go`/`dnsshape.go`: the client sends sealed session packets fragmented into base32 qname labels as TXT queries to a rotating resolver list; the Kharej server answers each query with one queued downlink fragment (pull-based: downlink only rides responses, idle clients poll). All reliability stays in the existing `Session` (ARQ/FEC/CC/dedup) — the carrier is a dumb lossy pipe. The same UDP-53 listener serves a signed `_wt` TXT bulletin for path advertisement. **No existing `wat/` file is modified** (only `cmd/wattun/main.go`, `wat/version.go`, docs gain edits) — old peers and all other carriers are untouched.

**Tech Stack:** Go 1.26 stdlib only (hand-rolled RFC 1035 codec, like `dnsshape.go`; no miekg/dns, no new deps). Tests run on Windows (pure UDP sockets, no raw socket, no root).

**Spec:** `docs/RESEARCH-blackout.md` — §4 (dns carrier), §6 (bulletin board), §10 (order). The plan implements spec items 1 and 2 of its recommended order; items 3–4 (relay-chain automation, cockroach mode) are deliberately out of scope.

## Global Constraints

- Wire compatibility: the session wire is untouched; `dns` is a per-deployment carrier choice. Both ends of a dns deployment need 3.2.0; interop with older peers is unaffected (no shared-code edits).
- No new module dependencies (`go.mod` stays as is).
- Bump `wat/version.go` `3.1.2` → `3.2.0` (Task 6). No tag/push/release in this plan — owner's call after review.
- README.md and README.fa.md stay content-synced; Farsi README is written natively (`<div dir="rtl">` prose blocks, code blocks outside them, Persian digits in prose). Benchmark figures in docs must come from real measurements — this plan claims no field numbers.
- Test commands (from AGENTS.md): `go build ./... && go vet ./...`, `go test -count=1 ./cmd/...`, `go test -count=1 ./wat/` (minutes), single: `go test -count=1 -run TestName ./wat/`.
- Every commit: owner's git identity only, no AI attribution, subject line in house style (`wat: ...`, `cmd: ...`, `docs: ...`).
- Shell scripts stay LF; not touched here.
- This checkout is Windows: dns tests must pass on Windows (they can — plain UDP). `gofmt -l` may list CRLF files; that is expected.

## Review Focus

The five input classes most likely to bite, each pinned to a test in the owning task:

1. **Hostile/malformed DNS bytes from any resolver** (the server socket is public): parser must reject, never panic or block. → Task 1 malformed-query table, Task 4 `TestDNSServerMalformed`.
2. **Forged or hijacked responses** (a MITM resolver inventing downlink data): carrier drops garbage; the session AEAD is the real gate. → Task 5 `TestDNSHijackedResponse`.
3. **Duplicate and reordered fragments** (resolvers retry queries): reassembler dedups, session dedups packets. → Task 2 `TestFragReassemblerDuplicate`, Task 5 `TestDNSSessionLossyResolver`.
4. **Flood/overflow** (open NS, many sids, lost clients): every queue bounded, drop-oldest, no unbounded growth. → Task 2 `TestFragReassemblerBound`, Task 4 `TestDNSServerQueueOverflow`.
5. **Idle-downlink deadlock** (server has data, client has nothing to send): pull queries must fetch it. → Task 5 `TestDNSIdlePull`.

Plus one policy line: **foreign-zone queries get REFUSED** (we are an authoritative NS, not an open relay) → Task 4 `TestDNSServerForeignZone`.

---

### Task 1: DNS wire codec (`wat/dnsmsg.go`)

Minimal RFC 1035 query/TXT-response build and parse, the same hand-rolled style as `dnsshape.go`. Case-preserving label decode (resolvers randomize 0x20 case); chunk encoders elsewhere emit lowercase only.

**Files:**
- Create: `wat/dnsmsg.go`
- Test: `wat/dnsmsg_test.go`

**Interfaces:**
- Produces (used by Tasks 2, 3, 4, 5):
  - `func dnsBuildQuery(id uint16, labels []string, qtype uint16) []byte` — header (RD=1, qdcount=1) + question; panics-free: returns nil if any label is empty or >63 chars, or the name would exceed 255 wire octets.
  - `func dnsParseQuery(p []byte) (id uint16, labels []string, qtype uint16, ok bool)` — ok=false on: short buffer, qdcount≠1, QR set, label length 0 mid-name or >63, name >255 octets, truncated question, pointer compression in the question (we never send one; refuse it).
  - `func dnsBuildTxtResponse(query []byte, txt []byte, rcode uint8) []byte` — echoes the question bytes verbatim, QR=1, one TXT answer when txt != nil (TTL 0, one string), no answers when txt == nil. `txt` must be ≤255 bytes.
  - `func dnsParseTxtResponse(p []byte) (labels []string, txt []byte, ok bool)` — QR=1 required; `labels` are the echoed question's labels (the client reads its sid from `labels[0]`); `txt` is the first TXT answer's string bytes (nil when there are no answers — a valid pull answer); ok=false when not a response, no question echo, or the answer section is malformed (including a TXT string length that runs past the message).
  - Constants: `dnsQtypeTXT uint16 = 16`, `dnsRcServfail uint8 = 2`, `dnsRcRefused uint8 = 5`. Reuse `dnsHdr` (12) from `dnsshape.go`.

- [ ] **Step 1: Write the failing tests**

```go
// wat/dnsmsg_test.go
func TestDNSQueryRoundTrip(t *testing.T) {
	q := dnsBuildQuery(0x1234, []string{"aaaaaaaaaaaaa", "bbbb", "com"}, dnsQtypeTXT)
	id, labels, qt, ok := dnsParseQuery(q)
	if !ok || id != 0x1234 || qt != dnsQtypeTXT || len(labels) != 3 || labels[0] != "aaaaaaaaaaaaa" {
		t.Fatalf("round trip: ok=%v id=%x qt=%d labels=%v", ok, id, qt, labels)
	}
}

func TestDNSQueryCaseFlipsPreserved(t *testing.T) {
	q := dnsBuildQuery(7, []string{"abcdef"}, dnsQtypeTXT)
	// a resolver may flip case on the way: flip every alphabetic byte in the name
	for i := dnsHdr; i < len(q); i++ {
		if q[i] >= 'a' && q[i] <= 'z' { q[i] -= 32 }
	}
	_, labels, _, ok := dnsParseQuery(q)
	if !ok || labels[0] != "ABCDEF" { t.Fatalf("case-flipped name lost: ok=%v %v", ok, labels) }
}

func TestDNSQueryRejects(t *testing.T) { // every entry must parse as not-ok, no panic
	cases := [][]byte{
		nil, make([]byte, 11), make([]byte, 12),
		append(append([]byte{}, make([]byte, 12)...), 0),                    // qdcount 0
		append([]byte{0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 'c', 'o', 'm', 0}, 0, 16, 0, 1)[:16], // cut mid-question
		{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64, 'a'},                        // label len 64
		{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'a', 0xc0, 0x0c, 0, 16, 0, 1}, // compression pointer
	}
	for i, c := range cases {
		if _, _, _, ok := dnsParseQuery(c); ok {
			t.Errorf("case %d parsed ok, want reject", i)
		}
	}
}

func TestDNSQueryOversizeNameRefused(t *testing.T) {
	long := strings.Repeat("a", 63)
	if dnsBuildQuery(1, []string{long, long, long, long, "com"}, dnsQtypeTXT) != nil {
		t.Fatal("built a name over 255 octets")
	}
}

func TestDNSTxtResponseRoundTrip(t *testing.T) {
	q := dnsBuildQuery(0xabcd, []string{"x", "example", "com"}, dnsQtypeTXT)
	r := dnsBuildTxtResponse(q, []byte("hello"), 0)
	labels, txt, ok := dnsParseTxtResponse(r)
	if !ok || string(txt) != "hello" || len(labels) != 3 || labels[0] != "x" {
		t.Fatalf("txt=%q labels=%v ok=%v", txt, labels, ok)
	}
	// empty answer is a valid response the caller must distinguish from garbage
	r = dnsBuildTxtResponse(q, nil, 0)
	if labels, txt, ok = dnsParseTxtResponse(r); !ok || txt != nil || len(labels) != 3 {
		t.Fatalf("empty answer: txt=%q labels=%v ok=%v", txt, labels, ok)
	}
}

func TestDNSTxtResponseRejects(t *testing.T) {
	q := dnsBuildQuery(1, []string{"a", "b"}, dnsQtypeTXT)
	bad := dnsBuildTxtResponse(q, []byte("xy"), 0)
	bad[2] &^= 0x80 // clear QR: now it is a query, not a response
	if _, _, ok := dnsParseTxtResponse(bad); ok { t.Fatal("accepted a non-response") }
	bad = dnsBuildTxtResponse(q, []byte("xy"), 0)
	bad[len(bad)-3] = 200 // txt string length runs past the message end
	if _, _, ok := dnsParseTxtResponse(bad); ok { t.Fatal("accepted an overlong TXT string") }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -count=1 -run TestDNS ./wat/`
Expected: FAIL — `dnsBuildQuery` etc. undefined.

- [ ] **Step 3: Implement `wat/dnsmsg.go`**

Straight RFC 1035 byte assembly, no compression, no allocation beyond the output. `dnsParseQuery` walks length-prefixed labels with the bounds checks listed in the interface; `dnsParseTxtResponse` finds the answer's RDLENGTH and reads the one TXT string length byte. One comment at the top: why hand-rolled (house style, `dnsshape.go`, zero deps) and why pointers are refused (we never emit them; a public socket must not accept them).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -count=1 -run TestDNS ./wat/`
Expected: PASS (all Task-1 tests).

- [ ] **Step 5: Commit**

```bash
git add wat/dnsmsg.go wat/dnsmsg_test.go
git commit -m "wat: dns wire codec for queries and TXT responses"
```

---

### Task 2: Fragment codec and reassembler (`wat/dnschunk.go`)

`Config.MaxPayload` has a 256-byte floor (`session.go:315`), but one DNS qname carries only ~118 bytes of sealed packet after the sid label and domain. So one sealed packet = N queries, each carrying a self-identifying fragment, reassembled on receipt. The session above treats the carrier as one lossy datagram pipe; fragment loss = packet loss = normal ARQ repair.

**Every query name carries a random nonce label.** Not optional: a session retransmit re-seals nothing — same packet number, same ciphertext, same labels — and a caching resolver would then answer the retransmit from cache forever, so the server would never see it and the ARQ would never make progress (livelock). The nonce makes every query name unique; a cached answer only returns a stale downlink fragment, which the reassembler and the session's dedup already tolerate.

**Budget, pinned** (do not rederive): fragment wire = 10-byte header (packet number 8 + index 1 + count 1) + up to `dnsFragData` = 118 data bytes = 128 bytes → base32hex = 205 chars in ≤4 labels (≤63 each) = ≤209 wire octets. Plus the sid label (13 chars = 14 octets), a nonce label (≤7 chars = 8 octets) and a 15-octet domain (`t.example.com`) and root: ≤247 of the 255-octet name cap, 8 octets of headroom.

**Files:**
- Create: `wat/dnschunk.go`
- Test: `wat/dnschunk_test.go`

**Interfaces:**
- Consumes: `b32Hex` (`revive.go:26`, lowercase encoding; decode after `strings.ToUpper`, the `ParseDNSQueryKnock` pattern).
- Produces (used by Tasks 4, 5):
  - Constants: `dnsChunkMTU = 256` (the carrier `Profile.MTU`), `dnsFragData = 118`, `dnsFragMax = 8` (packets up to 8×118 = 944 bytes; the session sends ≤256 with this profile).
  - `type fragHdr struct{ pn uint64; idx, count uint8 }`
  - `func fragEncode(pkt []byte) (frags [][]string, err error)` — one entry PER FRAGMENT; each entry is the 1–4 labels carrying that fragment (header + data, base32hex, packed to ≤63 chars per label). Error when `len(pkt) < 16+16` (header+tag alone), `> dnsFragMax*dnsFragData` (944), or the name budget would exceed 255 wire octets (with sid + nonce + a 15-octet domain).
  - `func fragDecode(frag []string) (h fragHdr, data []byte, ok bool)` — decodes ONE fragment given its labels; equivalent to joining the labels and calling `fragDecodeB32`. ok=false on bad base32, wrong header size, `idx >= count`, or `count > dnsFragMax`.
  - `func fragDecodeB32(s string) (h fragHdr, data []byte, ok bool)` — decodes one fragment from its whole base32hex string; this is what a TXT answer carries (205 chars fit one string) and what the client uses.
  - `func sidLabel(sid uint64) string` / `func sidOfLabel(l string) (uint64, bool)` — 13-char base32hex, case-insensitive decode.
  - `func nonceLabel(n uint32) string` — ≤7-char base32hex.
  - `func pullLabel(n uint32) string` — `"p" + nonceLabel(n)`; `func isPullLabel(l string) bool`.
  - `type dnsReassembler struct{...}` with `func (r *dnsReassembler) add(sid uint64, h fragHdr, data []byte) []byte` — returns the complete packet when the last fragment arrives, else nil. Bound: 64 pending packets, fragments older than 2 s are dropped (lazy sweep on every `add`; a `now time.Time` field is settable for tests). Duplicates by (sid, pn, idx) are ignored; `data` is copied in (the caller reuses its buffer).
- Query composition, shared by Tasks 4 and 5 (one line each side, keep them identical): data query labels = `[sidLabel(sid)] + frags[i] + [nonceLabel(n)] + domainLabels`; pull labels = `[sidLabel(sid), pullLabel(n)] + domainLabels`. Parse side: strip the domain labels (zone check), then `labels[0]` is the sid, `labels[len-1]` is the nonce on a data query, and a 2-label body (`sid`, `p…`) is a pull.

- [ ] **Step 1: Write the failing tests**

```go
// wat/dnschunk_test.go
func mustSealed(t *testing.T, sid, pn uint64, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 16+16+len(payload)) // plain header + AEAD tag room + payload
	binary.BigEndian.PutUint64(pkt[0:8], sid)
	binary.BigEndian.PutUint64(pkt[8:16], pn)
	copy(pkt[32:], payload)
	return pkt
}

func fragQueries(pkt []byte, domain []string) ([][]string, error) { // the shared composition, test-side copy
	frags, err := fragEncode(pkt)
	if err != nil { return nil, err }
	sid, _ := sidOfLabel(sidLabel(binary.BigEndian.Uint64(pkt[0:8])))
	var qs [][]string
	for i, f := range frags {
		qs = append(qs, append(append([]string{sidLabel(sid)}, f...), nonceLabel(uint32(i))))
		qs[i] = append(qs[i], domain...)
	}
	return qs, nil
}

func TestFragRoundTrip(t *testing.T) {
	pkt := mustSealed(t, 0x1122334455667788, 42, bytes.Repeat([]byte("u"), 200))
	qs, err := fragQueries(pkt, []string{"t", "example", "com"})
	if err != nil { t.Fatal(err) }
	var r dnsReassembler
	var got []byte
	for _, q := range qs { // feed all fragments; the last completes the packet
		h, data, ok := fragDecode(q[1 : len(q)-1]) // body between sid and nonce
		if !ok { t.Fatalf("fragment %v undecodable", q) }
		got = r.add(0x1122334455667788, h, data)
	}
	if got == nil || !bytes.Equal(got, pkt) { t.Fatalf("reassembled %v bytes", len(got)) }
	for _, q := range qs { // every name within the 255-octet wire budget
		if l := wireNameLen(q); l > 255 { t.Fatalf("name %d octets: %v", l, q) }
	}
}

func TestFragCount(t *testing.T) {
	frags, err := fragEncode(mustSealed(t, 1, 1, bytes.Repeat([]byte("x"), 224))) // whole packet = 256 bytes
	if err != nil { t.Fatal(err) }
	if len(frags) != 3 { t.Fatalf("%d fragments, want 3 (118+118+20)", len(frags)) }
}

func TestFragRejects(t *testing.T) {
	if _, err := fragEncode(mustSealed(t, 1, 1, nil)[:20]); err == nil { t.Fatal("tiny packet accepted") }
	if _, err := fragEncode(make([]byte, 945)); err == nil { t.Fatal("oversize packet accepted") }
	if _, _, ok := fragDecode([]string{"zzzz"}); ok { t.Fatal("garbage fragment accepted") }
	h, _, _ := fragDecode(nil) // zero-value path must not panic elsewhere
	_ = h
	if _, ok := sidOfLabel("nope"); ok { t.Fatal("bad sid label accepted") }
}

func TestFragReassemblerDuplicate(t *testing.T) {
	pkt := mustSealed(t, 7, 9, bytes.Repeat([]byte("d"), 100))
	frags, _ := fragEncode(pkt)
	var r dnsReassembler
	feed := func(order ...int) (out []byte) {
		for _, i := range order {
			h, data, ok := fragDecode(frags[i])
			if !ok { t.Fatal("undecodable") }
			out = r.add(7, h, data)
		}
		return out
	}
	if p := feed(1, 0, 2); p == nil || !bytes.Equal(p, pkt) { t.Fatal("out-of-order assembly failed") }
	if p := feed(0, 1, 2); p != nil { t.Fatal("duplicate completion returned a packet") }
	if p := feed(2, 2, 1, 0); p != nil { t.Fatal("second pass returned a packet") }
}

func TestFragReassemblerBound(t *testing.T) {
	var r dnsReassembler
	r.now = time.Now()
	pkt := mustSealed(t, 1, 0, nil)
	for i := 0; i < 80; i++ { // 80 distinct first-fragments: pending stays ≤ 64
		binary.BigEndian.PutUint64(pkt[8:16], uint64(i))
		frags, _ := fragEncode(pkt)
		h, data, _ := fragDecode(frags[0])
		r.add(1, h, data)
	}
	if len(r.pending) > 64 { t.Fatalf("pending grew to %d", len(r.pending)) }
	r.now = r.now.Add(3 * time.Second) // expiry sweep on the next add
	binary.BigEndian.PutUint64(pkt[8:16], 999)
	frags, _ := fragEncode(pkt)
	h, data, _ := fragDecode(frags[0])
	r.add(1, h, data)
	if len(r.pending) != 1 { t.Fatalf("expired fragments not swept: %d", len(r.pending)) }
}

func TestPullAndNonceLabels(t *testing.T) {
	if !isPullLabel(pullLabel(5)) { t.Fatal("pull label not recognized") }
	if isPullLabel(nonceLabel(5)) { t.Fatal("nonce label taken for a pull") }
	if len(nonceLabel(0xffffffff)) > 7 { t.Fatal("nonce label over budget") }
	if sid, ok := sidOfLabel(sidLabel(0x1122334455667788)); !ok || sid != 0x1122334455667788 { t.Fatal("sid label") }
	// 0x20: a resolver may flip case; every decode is case-insensitive
	if sid, ok := sidOfLabel(strings.ToUpper(sidLabel(1))); !ok || sid != 1 { t.Fatal("case-flipped sid label") }
}
```

`wireNameLen` (sum of 1 + len per label, +1 root) is a test helper here; if the implementation wants it exported for the budget check in `fragEncode`, keep it unexported in `dnschunk.go` and test it through `fragEncode`'s error instead.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -count=1 -run TestFrag ./wat/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement `wat/dnschunk.go`**

Fragment header: pn (8, big-endian, copied from `pkt[8:16]`), index (1), count (1), then data. `fragEncode` slices `dnsFragData` bytes per fragment, base32hex-encodes header+data (one 205-char string), splits it into labels of ≤63 (the qname form); the TXT form is the same string unsplit — `fragDecode` = join + `fragDecodeB32`. `fragDecodeB32` uppercases before `b32Hex.DecodeString` (0x20-safe). The reassembler key is (sid, pn); store `[][]byte` indexed by fragment index plus first-seen time. One comment: why fragments exist (the 256-byte `MinPayload` floor vs the ~118-byte qname budget), and `shortcut: fragments cap at dnsFragMax=8, raise only if MinPayload ever drops below 256`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -count=1 -run 'TestFrag|TestPull' ./wat/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add wat/dnschunk.go wat/dnschunk_test.go
git commit -m "wat: qname fragment codec, dns carriers share it"
```

---

### Task 3: Bulletin board (`wat/bulletin.go`)

A signed, freshness-stamped note the server publishes as `_wt.<domain>` TXT; clients poll it through any resolver to learn the current path/config with no out-of-band channel. Crypto follows `revive.go` exactly: HMAC-SHA256 under a PSK-derived key, truncated tag. No replay ring — the bulletin is public information; replaying it is harmless (comment this why).

**Files:**
- Create: `wat/bulletin.go`
- Test: `wat/bulletin_test.go`

**Interfaces:**
- Consumes: `b32Hex`.
- Produces (used by Tasks 4, 6):
  - `const BulletinFresh = 7 * 24 * time.Hour`
  - `func NewBulletin(psk []byte) *Bulletin` — key = HMAC-SHA256(psk, "wat-bulletin-auth"), the `NewReviveEngine` derivation.
  - `func (b *Bulletin) Sign(note []byte, now time.Time) []byte` — blob: `"WBLT"` (4) + version 1 (1) + unix seconds (4, big-endian) + note length (1) + note + HMAC tag (14). Errors are impossible by construction; notes over 120 bytes are truncated to 120 (blob ≤144 bytes → base32hex ≤231 chars, fits one TXT string).
  - `func (b *Bulletin) Verify(blob []byte, now time.Time) ([]byte, error)` — checks magic, version, tag (`hmac.Equal`), freshness (±`BulletinFresh`); returns the note.

- [ ] **Step 1: Write the failing tests**

```go
// wat/bulletin_test.go
func TestBulletinRoundTrip(t *testing.T) {
	b := NewBulletin([]byte("psk"))
	blob := b.Sign([]byte("move to 203.0.113.99:443 tls"), time.Unix(1770000000, 0))
	note, err := b.Verify(blob, time.Unix(1770000600, 0))
	if err != nil || string(note) != "move to 203.0.113.99:443 tls" { t.Fatalf("%v %q", err, note) }
	if len(blob) > 144 { t.Fatalf("blob %d bytes, over the TXT budget", len(blob)) }
}

func TestBulletinTamperAndStale(t *testing.T) {
	b := NewBulletin([]byte("psk"))
	blob := b.Sign([]byte("note"), time.Unix(1770000000, 0))
	blob[len(blob)-1] ^= 1
	if _, err := b.Verify(blob, time.Unix(1770000060, 0)); err == nil { t.Fatal("tampered blob verified") }
	blob = b.Sign([]byte("note"), time.Unix(1770000000, 0))
	if _, err := b.Verify(blob, time.Unix(1770000000+int64(BulletinFresh/time.Second)+10, 0)); err == nil {
		t.Fatal("stale blob verified")
	}
	if _, err := NewBulletin([]byte("other")).Verify(b.Sign([]byte("n"), time.Unix(5, 0)), time.Unix(6, 0)); err == nil {
		t.Fatal("wrong key verified")
	}
}

func TestBulletinNoteTruncates(t *testing.T) {
	b := NewBulletin([]byte("psk"))
	note := bytes.Repeat([]byte("x"), 200)
	if got := b.Sign(note, time.Unix(1, 0)); len(got) != 4+1+4+1+120+14 {
		t.Fatalf("note not truncated: %d", len(got))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -count=1 -run TestBulletin ./wat/`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `wat/bulletin.go`**

Per the interface; ~60 lines including the header comment (what it is for: spec §6, IP rotation during blackouts).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -count=1 -run TestBulletin ./wat/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add wat/bulletin.go wat/bulletin_test.go
git commit -m "wat: signed dns bulletin, path ads through any resolver"
```

---

### Task 4: DNS server carrier (`wat/carrier_dns.go`, server half)

The Kharej side: one UDP socket (an authoritative NS for `domain`), `RawIO` for the session `Server`, plus the pull-queue that turns client queries into downlink opportunities. Pull-based: `SendTo` never writes a packet; it fragments and queues; the answer to the next query from that session carries one fragment.

**Files:**
- Create: `wat/carrier_dns.go` (both halves live here; this task adds the server)
- Test: `wat/carrier_dns_test.go`

**Interfaces:**
- Consumes: Task 1 (`dnsBuildQuery`, `dnsParseQuery`, `dnsBuildTxtResponse`, `dnsQtypeTXT`, rcodes), Task 2 (`fragEncode`, `fragDecode`, `fragDecodeB32`, `fragHdr`, `isPullLabel`, `sidOfLabel`, `sidLabel`, `nonceLabel`, `pullLabel`, `dnsReassembler`, `dnsChunkMTU`), Task 3 (`NewBulletin`, `Sign`).
- Produces (used by Tasks 5, 6):
  - `type DNSServer struct{...}`
  - `func NewDNSServer(addr, domain string, psk []byte, note func() []byte) (*DNSServer, error)` — `addr` like `NewUDPServer` (`"0.0.0.0:53"`); `domain` the delegated zone (`"t.example.com"`); `note` may be nil (bulletin answers with an empty note) and is called per bulletin query.
  - `func (s *DNSServer) Addr() net.Addr`
  - Implements `RawIO`: `Recv() (p []byte, lane int, src net.Addr, err error)` / `SendTo(p []byte, lane int, dst net.Addr) error` / `Close() error`; and `Profile() Profile` → `{MTU: dnsChunkMTU, InitBps: 12e3}`.
  - Internal policy (pinned, tests below):
    - Zone check: the query name's trailing labels (case-insensitive) must equal `domain`'s labels → else REFUSED (rcode 5) with no answer.
    - First label `"_wt"` → TXT answer = base32hex of `bulletin.Sign(note(), now)`; not handed up.
    - First label otherwise = sid (`sidOfLabel`). A 2-label body whose second label `isPullLabel` → pull: answer carries the oldest queued fragment for that sid (or empty NOERROR); not handed up.
    - Longer body → data query: last label is the nonce (ignored), the middle labels are one fragment → `fragDecode` → `reassembler.add`; on completion hand the packet up (`Recv` returns it, `src` = the querying resolver's address) AND answer with the oldest queued fragment for that sid (or empty).
    - Malformed in-zone query → SERVFAIL (rcode 2), continue.
    - `SendTo` extracts the sid from `p[0:8]`, fragments via `fragEncode`, appends each fragment's base32hex string to that sid's queue — cap 16 fragments per sid, drop oldest; total 256 sids, entries expire after 60 s (lazy sweep on insert). `dst`/`lane` are ignored (one comment: answers go to whoever next asks; the sid in the packet header is the address).
    - Response size: header 12 + question echo + one TXT (≤205 chars) always ≤ 512 bytes; never set TC, no EDNS.

- [ ] **Step 1: Write the failing tests** (a plain UDP socket plays a resolver)

```go
// wat/carrier_dns_test.go (server half)
func newDNSRig(t *testing.T) (*DNSServer, *net.UDPConn) {
	t.Helper()
	s, err := NewDNSServer("127.0.0.1:0", "t.example.com", []byte("psk"), func() []byte { return []byte("note-here") })
	if err != nil { t.Fatal(err) }
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { s.Close(); pc.Close() })
	return s, pc.(*net.UDPConn)
}

func dnsAsk(t *testing.T, pc *net.UDPConn, addr net.Addr, labels []string) []byte {
	t.Helper()
	q := dnsBuildQuery(uint16(rand.IntN(65536)), labels, dnsQtypeTXT)
	if _, err := pc.WriteTo(q, addr); err != nil { t.Fatal(err) }
	buf := make([]byte, 1024)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := pc.Read(buf)
	if err != nil { t.Fatal(err) }
	return buf[:n]
}

func TestDNSServerForeignZone(t *testing.T) {
	s, pc := newDNSRig(t)
	go func() { for { if _, _, _, err := s.Recv(); err != nil { return } } }()
	r := dnsAsk(t, pc, s.Addr(), []string{"aaa", "other", "zone"})
	if r[3]&0x0f != dnsRcRefused { t.Fatalf("rcode %d, want REFUSED", r[3]&0x0f) }
}

func TestDNSServerBulletin(t *testing.T) {
	s, pc := newDNSRig(t)
	go func() { for { if _, _, _, err := s.Recv(); err != nil { return } } }()
	r := dnsAsk(t, pc, s.Addr(), []string{"_wt", "t", "example", "com"})
	_, txt, ok := dnsParseTxtResponse(r)
	if !ok { t.Fatal("no txt answer") }
	note, err := NewBulletin([]byte("psk")).Verify(mustB32Decode(t, txt), time.Now())
	if err != nil || string(note) != "note-here" { t.Fatalf("%v %q", err, note) }
}

func TestDNSServerDataAndDownlink(t *testing.T) {
	s, pc := newDNSRig(t)
	got := make(chan []byte, 8)
	go func() {
		for {
			p, _, src, err := s.Recv()
			if err != nil { return }
			got <- p
			// the session's reply: queue one downlink packet for this sid
			if err := s.SendTo(mustSealed(t, binary.BigEndian.Uint64(p[0:8]), 5, []byte("down")), 0, src); err != nil {
				t.Error(err)
			}
		}
	}()
	const sid = 0x1122334455667788
	up := mustSealed(t, sid, 9, bytes.Repeat([]byte("u"), 200))
	frags, err := fragEncode(up)
	if err != nil { t.Fatal(err) }
	// one query per fragment (sid + fragment labels + nonce + domain);
	// the completed packet must come up exactly once
	var ups int
	for i, f := range frags {
		q := dnsAsk(t, pc, s.Addr(), append(append([]string{sidLabel(sid)}, f...),
			append([]string{nonceLabel(uint32(i))}, "t", "example", "com")...))
		_ = q // a queued downlink fragment may already ride an answer
		select {
		case p := <-got:
			if !bytes.Equal(p, up) { t.Fatalf("packet mismatch: %d bytes", len(p)) }
			ups++
		default:
		}
	}
	if ups != 1 { t.Fatalf("%d completions, want 1", ups) }
	// a pull for the same sid must return one downlink fragment
	r := dnsAsk(t, pc, s.Addr(), []string{sidLabel(sid), pullLabel(1), "t", "example", "com"})
	_, txt, ok := dnsParseTxtResponse(r)
	if !ok || txt == nil { t.Fatal("pull returned no downlink fragment") }
	if _, _, ok := fragDecodeB32(string(txt)); !ok { t.Fatal("downlink txt is not a decodable fragment") }
}

func TestDNSServerQueueOverflow(t *testing.T) {
	s, _ := newDNSRig(t)
	sid := uint64(1)
	p := mustSealed(t, sid, 1, nil)
	for i := 0; i < 40; i++ { // 40 packets = 120 fragments >> cap 16
		if err := s.SendTo(p, 0, nil); err != nil { t.Fatal(err) }
	}
	if n := len(s.queue[sid]); n > 16 { t.Fatalf("queue holds %d fragments", n) }
}

func TestDNSServerMalformed(t *testing.T) {
	s, pc := newDNSRig(t)
	recvErr := make(chan error, 1)
	go func() { for { if _, _, _, err := s.Recv(); err != nil { recvErr <- err; return } } }()
	for _, garbage := range [][]byte{nil, []byte{1}, []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a', 'b'}} {
		if _, err := pc.WriteTo(garbage, s.Addr()); err != nil { t.Fatal(err) }
	}
	select {
	case err := <-recvErr:
		t.Fatalf("server died on garbage: %v", err)
	case <-time.After(300 * time.Millisecond): // still alive: each got SERVFAIL/REFUSED
	}
}
```

Helpers `mustSealed` (a fake 16-byte header + payload; the server never decrypts — only `p[0:8]` matters, so any bytes work) and `mustB32Decode` go in this test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -count=1 -run TestDNSServer ./wat/`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement the `DNSServer` in `wat/carrier_dns.go`**

One receive loop goroutine started by `NewDNSServer`: read → `dnsParseQuery` → policy ladder (zone → `_wt` → pull → data) → build the response with `dnsBuildTxtResponse` → write back to the source → completed packets to a channel that `Recv` reads. `SendTo` never blocks on the socket (queue only). File header comment: the B0 story (spec §4), why downlink is pull-based, and `shortcut: one fragment per response, no EDNS/TCP-53 — a TXT answer is ≤ ~320 bytes and never truncates`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -count=1 -run TestDNSServer ./wat/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add wat/carrier_dns.go wat/carrier_dns_test.go
git commit -m "wat: dns server carrier, pull-based downlink through resolvers"
```

---

### Task 5: DNS client carrier (`wat/carrier_dns.go`, client half) + session tests

The Iran side: one unconnected UDP socket, a rotating resolver list with a penalty box, a paced query loop that fragments outbound packets, and idle pull queries so server-queued downlink can arrive when the client has nothing to send.

**Files:**
- Modify: `wat/carrier_dns.go` (add the client half)
- Test: `wat/carrier_dns_test.go` (append)

**Interfaces:**
- Consumes: Tasks 1–2 (`dnsBuildQuery`, `dnsParseTxtResponse`, `fragEncode`, `fragDecodeB32`, `fragHdr`, `sidOfLabel`, `sidLabel`, `nonceLabel`, `pullLabel`, `dnsChunkMTU`).
- Produces (used by Task 6):
  - `type DNSClient struct{...}`
  - `func NewDNSClient(resolvers []string, domain string) (*DNSClient, error)` — resolvers as `host` or `host:port` (default `:53`), resolved to `*net.UDPAddr` at startup; error on an empty list or bad address; `domain` split into labels once.
  - Implements `PacketIO`:
    - `Send(p []byte, path int) error` — `fragEncode`, enqueue one query per fragment (labels composed exactly as in Task 2: sid + fragment + fresh random `nonceLabel`); error if the packet exceeds the fragment cap or the queue is full (64 packets).
    - `Recv() (p []byte, path int, src net.Addr, err error)` — read responses; `dnsParseTxtResponse` returns the echoed question's labels and the TXT bytes: `labels[0]` gives the sid, the TXT string goes through `fragDecodeB32` and `reassembler.add` (a completed packet is returned; empty-TXT or non-TXT responses are skipped and the loop continues — an idle pull's empty answer must NOT be returned as a zero-length packet).
    - `SetPeer(net.Addr)` — no-op. `Close() error` — closes the socket, unblocks `Recv`.
    - `Backlogged() bool` — queue over 32 packets (session holds back).
    - `Profile() Profile` → `{MTU: dnsChunkMTU, InitBps: 12e3}`.
  - Internal, pinned: `dnsQPS = 40` total query cap (token bucket — the delay-based CC ramps on stable RTT and would flood a resolver; loss never slows it by design, so the carrier caps instead); rotation = round-robin per query; penalty = a resolver with 3 consecutive queries unanswered for 2 s each (counted per resolver address; any response from that address resets it) is benched for 30 s, and a one-shot probe query every 5 s reactivates it; `var dnsPullEvery = 1 * time.Second` (package var so tests shorten it) — when the queue is empty and this long has passed since the last query, send a pull for the sid of the last outbound packet (or skip until the first packet defines one).
  - txid: random per query; **not** matched on receive (one comment: the session AEAD rejects forgeries, a stale txid only carries an old pn the reassembler deadline drops).

- [ ] **Step 1: Write the failing tests**

The session-level tests use a fake resolver: a goroutine with a UDP socket that forwards queries to the `DNSServer`, with knobs for drop-every-Nth and duplicate-every-Nth. Rig on top of the Task-4 rig: `newDNSPair(t, drop, dup func(n uint64) bool)` returns (`*DNSServer`, client `*Session`, server session channel), the client built with the fake resolver's address.

```go
func TestDNSSessionEcho(t *testing.T) {
	// session over DNSClient <-> fake resolver <-> DNSServer: udpEcho(t, cli, 60000, 3) passes
	// build like newUDPRig (carrier_udp_test.go:60): NewServer(Config{Key, MaxPayload: dnsChunkMTU}, s)
	// NewSession(Config{Key, MaxPayload: dnsChunkMTU}, c) — the Profile.MTU path is also fine (MaxPayload 0)
}

func TestDNSSessionLossyResolver(t *testing.T) {
	// fake resolver drops every 3rd query and duplicates every 5th: echo of 200 KB still completes
	// (retransmit repairs fragments; duplicates are ignored) — waitOrFail(t, &wg, 30*time.Second)
}

func TestDNSIdlePull(t *testing.T) {
	// client session open, nothing sent; server-side stream writes 4 KB to the client's stream;
	// the client must receive it within ~2×dnsPullEven (set dnsPullEvery = 100ms in the test,
	// restore with t.Cleanup) — this is the deadlock the pull exists to break
}

func TestDNSHijackedResponse(t *testing.T) {
	// the fake resolver itself injects a well-formed TXT response whose fragment bytes are
	// garbage for the live sid (a MITM resolver cannot be distinguished from a flaky one at the
	// carrier; the session AEAD is the gate): Recv must skip it, the session must stay alive,
	// and a following echo must still pass
}

func TestDNSResolverFailover(t *testing.T) {
	// two fake resolvers; the first blackholes every query (penalty: 3 strikes) with dnsPullEvery
	// shortened; the second forwards; an echo completes and the client's rotation skipped the
	// dead one (assert via the second resolver's query counter)
}

func TestDNSClientRejectsOversize(t *testing.T) {
	c, err := NewDNSClient([]string{"127.0.0.1:53"}, "t.example.com")
	if err != nil { t.Fatal(err) }
	defer c.Close()
	if err := c.Send(make([]byte, 945), 0); err == nil { t.Fatal("oversize packet accepted") }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -count=1 -run TestDNS ./wat/`
Expected: FAIL — `NewDNSClient` undefined (the server tests from Task 4 still pass).

- [ ] **Step 3: Implement the `DNSClient` in `wat/carrier_dns.go`**

One goroutine: token bucket (`dnsQPS`), pop queued query or send a pull when idle past `dnsPullEvery`; write to the current resolver. `Recv` reads the socket directly (the sender goroutine only writes — one socket, two goroutines, `net.UDPConn` supports concurrent read/write). Penalty box per the pinned semantics: on each query send, record (resolver, send time); a sweep (piggybacked on the sender loop, every 500 ms) counts queries unanswered for 2 s as strikes; any well-formed response from an address clears its strikes (a SERVFAIL still proves the path crosses — it resets too, the zone being broken is not the resolver's fault); 3 strikes benches the resolver 30 s; a one-shot probe every 5 s reactivates benched ones. ~250 lines with comments.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -count=1 -run TestDNS ./wat/`
Expected: PASS, including the session-level ones. Then the whole suite:
Run: `go test -count=1 ./wat/`
Expected: PASS (minutes; watch for flaky timeouts under `-race` later — throughput assertions are skipped there by design).

- [ ] **Step 5: Commit**

```bash
git add wat/carrier_dns.go wat/carrier_dns_test.go
git commit -m "wat: dns client carrier, resolver rotation and idle pulls"
```

---

### Task 6: Binary wiring and version (`cmd/wattun/main.go`, `wat/version.go`)

**Files:**
- Modify: `cmd/wattun/main.go` (flags near `udpDNS` at line ~78, the `build` switch at line ~357, a one-shot poll branch near startup)
- Modify: `wat/version.go` (`3.1.2` → `3.2.0`)
- Test: `cmd/wattun/config_test.go` (known keys), `cmd/wattun/tunnel_test.go` only if it enumerates carriers

**Interfaces:**
- Consumes: `wat.NewDNSServer`, `wat.NewDNSClient`, `wat.NewBulletin` (Tasks 3–5).
- Produces (config keys = flag names, house rule):
  - `-dns-domain string` — the delegated zone, both ends, required for `carrier: dns`.
  - `-dns-resolvers string` — comma-separated `host[:port]`, client only, required for `carrier: dns` on the client.
  - `-bulletin-file string` — server: file whose first ≤120 bytes are the note; read per query, on error keep the last good bytes.
  - `-bulletin-poll` — bool, client: query `_wt.<dns-domain>` TXT through every configured resolver until one verifies, print the note to stdout, exit 0; exit 1 with log lines when none do. Needs `-dns-domain`, `-dns-resolvers`, `-key-file`.
  - `build` case `"dns"`: server → `wat.NewDNSServer(listen, *dnsDomain, k, noteFunc)`; client → `wat.NewDNSClient(strings.Split(*dnsResolvers, ","), *dnsDomain)`; no reverse support — `log.Fatalf("carrier dns: -reverse is not supported")` when combined. Validations before construction: empty domain → fatal; client with empty resolvers → fatal.
  - The note func: `func() []byte { b, err := os.ReadFile(*bulletinFile); if err != nil { return lastNote }; lastNote = b[:min(len(b), 120)]; return lastNote }` (package-level `lastNote`, one comment).

- [ ] **Step 1: Write the failing test**

Extend the config test that pins known keys / parse round-trips (find the existing table in `config_test.go` and add rows): a config body with `dns-domain: t.example.com` and `dns-resolvers: "78.157.42.100,8.8.8.8"` parses, and the values come back through the same path other flags use. If `config_test.go` has no such table, add `TestDNSConfigKeys` that builds a `fileConfig` via `parseConfig` with the flags registered in an `init`-like helper mirroring main's — follow the file's existing pattern exactly.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -count=1 ./cmd/...`
Expected: FAIL on the new case.

- [ ] **Step 3: Implement the wiring**

Flags + `build` case + poll branch + version bump. The poll branch runs before any tunnel construction (right after config load): if `*bulletinPoll` → run and `os.Exit`. UDP socket per resolver, 2 s timeout, 2 attempts, sequential.

- [ ] **Step 4: Run tests and the build**

Run: `go build ./... && go vet ./... && go test -count=1 ./cmd/...`
Expected: build OK, vet clean, PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/wattun/main.go cmd/wattun/config_test.go wat/version.go
git commit -m "3.2.0: dns carrier and bulletin poll in the binary"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/TECHNICAL.md` — new `### DNS carrier (dns, 3.2.0)` section right after the `udp-dns` section (ends ~line 1009); a row in the carrier matrix (~line 1011): `| dns | yes | no | 3.2.0 |`; a `### DNS bulletin board` subsection.
- Modify: `README.md` and `README.fa.md` — feature bullet each, release badge `release-v3.2.0` at the top of both.
- Modify: `docs/RESEARCH-blackout.md` — one line under Status: `Plan: docs/superpowers/plans/2026-10-30-dns-carrier.md (implementing §4 + §6).`

**Content the sections must carry (from the spec and this plan — no invented numbers):**
- What B0 is and why `udp-dns`/`fake-sni` do not help there (spec §1–§2, two sentences).
- Prerequisites: the operator owns a domain; `A ns → KHAREJ_IP` and `NS t → ns` records (`DNS only`, not proxied); verify with `dig @ns.example.com t.example.com SOA` and `dig +short TXT _wt.t.example.com` via a domestic resolver; UDP 53 free on Kharej (bind an explicit address — the `systemd-resolved` note from the udp-dns section applies); short domain names leave more label room.
- Both-end config example (server `carrier: dns`, `listen: "KHAREJ_IP:53"`, `dns-domain: t.example.com`, `bulletin-file`; client `carrier: dns`, `dns-domain`, `dns-resolvers`, `ports`).
- Honest capacity: ~118 payload bytes per query, `dnsQPS` 40 cap, one fragment per response — messaging/SSH grade, not video; measured field numbers only when someone measures them.
- Limits: no reverse, no EDNS/TCP-53, do not set `-max-payload` with this carrier, the sid is visible in the qname like the plain session header (no `hdr-mask` interplay in 3.2.0), resolvers see query volume, and the terminal risk — if the state blocks recursion to the zone, only the relay chain (TECHNICAL.md:652) remains.
- Bulletin: `-bulletin-file` on the server, `-bulletin-poll` on the client (or plain `dig +short TXT _wt.t.example.com @RESOLVER` and a wattun verify), 7-day freshness window, note cap 120 bytes.

- [ ] **Step 1: Write the TECHNICAL.md section and matrix row**
- [ ] **Step 2: Write README.md and README.fa.md updates** (Farsi native: RTL div prose, Persian digits in prose, code blocks outside the divs — follow the file's existing patterns verbatim)
- [ ] **Step 3: Add the plan pointer line to RESEARCH-blackout.md**
- [ ] **Step 4: Verify nothing dangling**

Run: `go build ./... && go vet ./... && go test -count=1 ./cmd/... && bash -n wattun-manager`
Expected: all clean (no shell changes, the `-n` is a free guard).

- [ ] **Step 5: Commit**

```bash
git add docs/TECHNICAL.md README.md README.fa.md docs/RESEARCH-blackout.md
git commit -m "docs: dns carrier and bulletin, both readmes, blackout plan link"
```

---

## Out of scope (do not build in this plan)

Relay-chain automation and the cockroach-mode path oracle (spec §7–§8, separate plan); DoH-to-domestic-resolver client sockets; EDNS0 and TCP-53 fallback; reverse mode and bonding composition for `dns` (the bond machinery is generic and may work — untested, undocumented as supported); manager wizard/token support for `dns`; compression of qname labels; `hdr-mask` interplay.

## Measurement debt (honest, for whoever ships this)

No field numbers exist yet. Before release notes claim throughput, run a real Iran/Kharej pair and record: sustained qps per resolver before SERVFAIL, end-to-end echo throughput over 1/3/5 domestic resolvers, and pull latency on an idle session. Until then docs say "messaging/SSH grade" and nothing numeric.
