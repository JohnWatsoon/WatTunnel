package wat

import (
	mrand "math/rand/v2"
	"sync"
)

// DNS-shaped udp (3.0.0): with Config-level `udp-dns` every datagram of the udp carrier starts with a DNS message
// header and one question, and the session packet follows as if it were the rest of the message. It exists for
// routes that cut a UDP flow after its first datagrams unless it looks like an allowed protocol: measured on a fresh
// Iran/Kharej pair (2026-10-25), UDP to port 53 passes sustained 1400-byte datagrams in both directions when the first
// bytes are a valid DNS header and question, while the same bytes as random data are cut after three datagrams on every
// port. Run it on port 53 (or any port) of the server; both ends must enable it, an older peer cannot read the frame.
//
// udp-dns-edns (3.3.8, opt-in, both ends): the legacy frame is header + question + ciphertext with ANCOUNT=0, which a
// strict DNS parser rejects (no EDNS0 OPT above 512 B, no answer to the query). With the flag the query adds an EDNS0
// OPT additional record (ARCOUNT=1, advertised size 1232), and the server replies as a real answer: it echoes the
// query's id and question, sets ANCOUNT=1 and carries the session packet as the RDATA of one TXT answer
// (255-byte character-strings), then the same OPT. Mixed versions keep interoperating: the server answers in the style
// of the query it received (a legacy query gets the legacy reply), and the strip side detects the answer form by
// ANCOUNT, so a new receiver still parses a legacy reply. The server remembers the last query per client address
// (bounded map) only to build those echoes. Nothing in the legacy frame is constant except the shape of a DNS
// message; the id and the name are fresh for every datagram. Cost: 26-37 B legacy, 37-43 B (query) and ~21+len
// overhead in 255-byte chunks (answer) with the flag.
//
// Frame: id(2, random) flags(2) qdcount=1 ancount arcount, then one question (a random 5-14 character label plus a
// top-level label, type A or AAAA, class IN), then the payload (client, or legacy server) / one TXT answer RR + OPT
// (3.3.8 server). Client frames look like recursive queries (flags 0x0100), server frames like empty NOERROR answers
// (0x8180, or real ones with the flag).

const (
	dnsHdr         = 12
	dnsMaxFrame    = 100 // header + longest question + OPT (query) or header + echoed question + TXT answer RR + OPT (3.3.8)
	dnsQuery       = 0x0100
	dnsAnswer      = 0x8180
	dnsEdnsUDPSize = 1232 // EDNS0 class field: the advertised UDP payload size
	dnsQMax        = 4096 // bound on the server's remembered per-client queries (echo source)
)

var dnsTLD = [...]string{"com", "net", "org", "ir", "info", "io"}

const dnsAlpha = "abcdefghijklmnopqrstuvwxyz0123456789"

// dnsQueryEcho remembers one inbound query's id and raw question bytes: the 3.3.8 server reply echoes them.
// edns records whether the query itself carried the OPT (a legacy query gets the legacy reply).
type dnsQueryEcho struct {
	txid  uint16
	quest []byte // a copy: the receive buffer is reused
	edns  bool
}

// dnsQuest appends one question: a random 5-14 character label plus a TLD, type A or AAAA, class IN. r drives the
// choices and the label characters.
func dnsQuest(dst []byte, r *uint64) []byte {
	n := 5 + int(*r>>16)%10
	dst = append(dst, byte(n))
	for i := 0; i < n; i++ {
		*r = *r*6364136223846793005 + 1442695040888963407
		dst = append(dst, dnsAlpha[int(*r>>33)%len(dnsAlpha)])
	}
	tld := dnsTLD[int(*r>>20)%len(dnsTLD)]
	dst = append(dst, byte(len(tld)))
	dst = append(dst, tld...)
	qt := byte(1) // A
	if *r>>40&3 == 0 {
		qt = 28 // AAAA
	}
	return append(dst, 0, 0, qt, 0, 1)
}

// dnsOpt appends an EDNS0 OPT additional record advertising dnsEdnsUDPSize.
func dnsOpt(dst []byte) []byte {
	return append(dst, 0, 0x00, 0x29, byte(dnsEdnsUDPSize>>8), byte(dnsEdnsUDPSize&0xff), 0, 0, 0, 0, 0, 0)
}

// dnsFrame appends the legacy DNS prefix and payload to dst. resp selects the server-side (answer) flags.
func dnsFrame(dst, payload []byte, resp bool) []byte {
	return dnsFrameOpt(dst, payload, resp, nil, false)
}

// dnsFrameOpt frames with the 3.3.8 udp-dns-edns upgrades. On a query, edns adds the EDNS0 OPT. On a reply,
// q != nil with edns echoes the query's id and question and wraps the payload in one TXT answer RR; without a
// remembered query (or with the flag off) the reply is the legacy empty-NOERROR form, which is what keeps
// mixed-version pairs working.
func dnsFrameOpt(dst, payload []byte, resp bool, q *dnsQueryEcho, edns bool) []byte {
	if resp && (q == nil || !q.edns) {
		r := mrand.Uint64()
		dst = append(dst, byte(r), byte(r>>8), byte(dnsAnswer>>8), byte(dnsAnswer&0xff), 0, 1, 0, 0, 0, 0, 0, 0)
		dst = dnsQuest(dst, &r)
		return append(dst, payload...)
	}
	if resp {
		// full answer: echo id + question, one TXT answer RR with the payload as character-strings, then the OPT
		dst = append(dst, byte(q.txid>>8), byte(q.txid), byte(dnsAnswer>>8), byte(dnsAnswer&0xff), 0, 1, 0, 1, 0, 0, 0, 1)
		dst = append(dst, q.quest...)
		rd := len(payload) + (len(payload)+254)/255 // rdata = the 1-byte string lengths plus the payload
		dst = append(dst, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 0, byte(rd>>8), byte(rd))
		for s := 0; s < len(payload); s += 255 {
			e := s + 255
			if e > len(payload) {
				e = len(payload)
			}
			dst = append(dst, byte(e-s))
			dst = append(dst, payload[s:e]...)
		}
		return dnsOpt(dst)
	}
	r := mrand.Uint64()
	ar := uint16(0)
	if edns {
		ar = 1
	}
	dst = append(dst, byte(r), byte(r>>8), byte(dnsQuery>>8), byte(dnsQuery&0xff), 0, 1, 0, 0, 0, 0, byte(ar>>8), byte(ar))
	dst = dnsQuest(dst, &r)
	if edns {
		dst = dnsOpt(dst)
	}
	return append(dst, payload...)
}

// dnsStrip returns the payload of a frame made by dnsFrame/dnsFrameOpt, or nil when p is not one. It detects the
// 3.3.8 answer form by ANCOUNT and the 3.3.8 query form by ARCOUNT, so every mix of ends parses.
func dnsStrip(p []byte) []byte {
	pay, _ := dnsParse(p)
	return pay
}

// dnsParse also returns the inbound query's echo (id + raw question bytes), which the 3.3.8 server replies reuse.
func dnsParse(p []byte) ([]byte, *dnsQueryEcho) {
	if len(p) < dnsHdr+1 || p[4] != 0 || p[5] != 1 {
		return nil, nil
	}
	i := dnsHdr
	found := false
	for labels := 0; labels < 4; labels++ {
		l := int(p[i])
		if l == 0 {
			i += 1 + 4
			found = true
			break
		}
		if l > 63 {
			return nil, nil
		}
		i += 1 + l
		if i >= len(p) {
			return nil, nil
		}
	}
	if !found || i >= len(p) {
		return nil, nil
	}
	q := &dnsQueryEcho{txid: uint16(p[0])<<8 | uint16(p[1]), quest: append([]byte(nil), p[dnsHdr:i]...),
		edns: p[2]&0x80 == 0 && (p[10] != 0 || p[11] != 0)}
	if p[2]&0x80 != 0 { // reply
		an := uint16(p[6])<<8 | uint16(p[7])
		if an != 1 {
			return p[i:], q // legacy reply: the payload follows the question
		}
		// 3.3.8 answer: name 0xc00c, TXT (16), class IN, ttl 0, rdlength, character-strings
		if i+12 > len(p) || p[i] != 0xc0 || p[i+1] != 0x0c || p[i+2] != 0 || p[i+3] != 16 || p[i+4] != 0 || p[i+5] != 1 {
			return nil, nil
		}
		rd := int(uint16(p[i+10])<<8 | uint16(p[i+11]))
		i += 12
		if rd > len(p)-i {
			return nil, nil
		}
		out := make([]byte, 0, rd)
		for e := i + rd; i < e; {
			l := int(p[i])
			i++
			if l == 0 || i+l > e {
				return nil, nil
			}
			out = append(out, p[i:i+l]...)
			i += l
		}
		return out, q
	}
	// query: skip the additional records (our EDNS0 OPT) before the payload
	for ar := int(uint16(p[10])<<8 | uint16(p[11])); ar > 0; ar-- {
		if i+11 > len(p) || p[i] != 0 || p[i+1] != 0 || p[i+2] != 41 {
			return nil, nil
		}
		rd := int(uint16(p[i+9])<<8 | uint16(p[i+10]))
		i += 11 + rd
		if i > len(p) {
			return nil, nil
		}
	}
	return p[i:], q
}

var dnsBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// dnsFrames frames every packet of ps into one pooled buffer; call done when the send has returned.
func dnsFrames(ps [][]byte, resp bool) (out [][]byte, done func()) {
	return dnsFramesOpt(ps, resp, nil, false)
}

// dnsFramesOpt is dnsFrames with the 3.3.8 upgrades; q (may be nil) is the echoed query on a reply.
func dnsFramesOpt(ps [][]byte, resp bool, q *dnsQueryEcho, edns bool) (out [][]byte, done func()) {
	bp := dnsBufs.Get().(*[]byte)
	need := 0
	for _, p := range ps {
		need += len(p) + dnsMaxFrame
	}
	if cap(*bp) < need {
		*bp = make([]byte, 0, need)
	}
	buf := (*bp)[:0]
	out = make([][]byte, len(ps))
	for i, p := range ps {
		s := len(buf)
		buf = dnsFrameOpt(buf, p, resp, q, edns)
		out[i] = buf[s:len(buf):len(buf)]
	}
	return out, func() { *bp = buf[:0]; dnsBufs.Put(bp) }
}
