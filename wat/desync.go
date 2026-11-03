package wat

// Fake-SNI desync (client side; the raw-socket half is desync_linux.go). Right after a pool connection's TCP
// handshake completes, a raw packet carrying a fake TLS ClientHello with an allowlisted SNI is injected next to
// the real flow. A DPI that classifies flows by parsing the first TLS flight reads the fake and marks the flow as
// TLS to an allowlisted site; the real server drops the fake (out-of-window sequence number, or a TTL that dies at
// the censor's hop), so the relay then carries the session's own encrypted datagrams, which the DPI passes as TLS
// application data. Server-side changes: none. Reverse-engineered from patterniha/SNI-Spoofing (wrong-seq method,
// January 2026 whitelisting; see RESEARCH.md) with the trigger handling generalised after zapret's
// zero-stage/second-stage split: the fake can also be sent alongside (not only before) the real first flight.
//
// This file holds the OS-independent parts so the state machine is testable everywhere: the handshake tracker, the
// fake packet builder and the shared checksum helpers.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// htons swaps byte order for the socket option calls that take a network-order constant.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// csum is the internet checksum (also used by the ICMP carrier, icmp_linux.go).
func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// tcpChecksum computes the TCP checksum over the pseudo header, TCP header and payload.
func tcpChecksum(th, src, dst []byte) uint16 {
	if len(src) == 16 { // IPv6 pseudo header (RFC 8200 8.1): src, dst, 32-bit TCP length, three zero bytes, next header
		ph := make([]byte, 40, 40+len(th))
		copy(ph[0:16], src)
		copy(ph[16:32], dst)
		binary.BigEndian.PutUint32(ph[32:], uint32(len(th)))
		ph[39] = 6 // TCP
		return csum(append(ph, th...))
	}
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6 // TCP
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	return csum(append(ph, th...))
}

// DesyncConfig tunes the fake-SNI layer of the tcp, tls, wss, h2 and grpc carriers.
type DesyncConfig struct {
	SNI  string // allowlisted server name the fake ClientHello carries
	Mode string // "seq" (wrong sequence number, default), "ttl" (small TTL), "sum" (valid window, bad checksum),
	// "seqsum" (both markers per connection, ~1 ms apart; experimental, 2.8.0), "rst" (bad-checksum RST),
	// "split" (the fake hello cut across TCP segments), "hlen0" (F&F zero-length TLS record header),
	// "fakeip" (SYN + hello to a whitelisted CDN IP), "synrst" (SYN|RST, bad checksum), "ff" (the true F&F
	// record + segment plan: empty record, 104-byte record, 1-byte records, then ≤Split TCP pieces), or "all"
	// (seq + sum + hlen0 + ff markers, ~1 ms apart)
	TTL    int    // ttl mode: hop count of the fake packet; 0 = calibrate it from the server's inbound TTL
	FakeIP string // fakeip mode: whitelisted destination (v4 or v6) the fake flow names; must match the connection's
	// own family or the matching default is used instead ("" or a mismatched family = 104.16.0.1 for a v4
	// connection, 2606:4700::6810:1 for a v6 one, both Cloudflare edges)
	Split int // split/ff mode: TCP segment count (0 = 3 for split, 11 for ff)
}

// splitSNIs splits a comma-separated list of SNIs into trimmed domain names.
func splitSNIs(sni string) []string {
	var out []string
	for _, s := range strings.Split(sni, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// validateDesync checks a DesyncConfig the same way on every OS (NewDesync calls it before anything else).
func validateDesync(cfg DesyncConfig) error {
	snis := splitSNIs(cfg.SNI)
	if len(snis) == 0 {
		return fmt.Errorf("wat: desync: empty SNI")
	}
	for _, s := range snis {
		if strings.ContainsAny(s, " \t\r\n/") {
			return fmt.Errorf("wat: desync: invalid SNI %q", s)
		}
	}
	switch cfg.Mode {
	case "", "seq", "ttl", "sum", "seqsum", "rst", "split", "hlen0", "fakeip", "synrst", "ff", "all", "paws":
	default:
		return fmt.Errorf("wat: -fake-mode must be seq, ttl, sum, seqsum, rst, split, hlen0, fakeip, synrst, ff, all or paws, got %q", cfg.Mode)
	}
	if cfg.TTL < 0 || cfg.TTL > 255 {
		return fmt.Errorf("wat: -fake-ttl must be 0 (auto) or 1..255, got %d", cfg.TTL)
	}
	if cfg.FakeIP != "" && net.ParseIP(strings.TrimSpace(cfg.FakeIP)) == nil {
		return fmt.Errorf("wat: -fake-ip must be an IP address, got %q", cfg.FakeIP)
	}
	if cfg.Split != 0 && (cfg.Split < 2 || cfg.Split > 16) {
		return fmt.Errorf("wat: -fake-split must be 0 (default 3) or 2..16, got %d", cfg.Split)
	}
	return nil
}

// defaultFakeIP is what fakeip mode names when -fake-ip is unset and the connection is IPv4: 104.16.0.1 is a
// Cloudflare anycast edge, an address the censor's allowlist has to pass for the whole CDN to stay reachable.
// defaultFakeIP6 is its IPv6 twin (2606:4700::6810:1, the same Cloudflare prefix), used over IPv6 connections.
var (
	defaultFakeIP  = addr4([4]byte{104, 16, 0, 1})
	defaultFakeIP6 = ipAddr{0x26, 0x06, 0x47, 0x00, 12: 0x68, 13: 0x10, 15: 0x01}
)

// desyncFakeIP resolves cfg.FakeIP (validateDesync has already accepted it) to the family the connection needs:
// the configured address when it is of that family, else that family's default (a v4 flow cannot address a v6
// edge, nor the reverse). v4 says which family to resolve for.
func desyncFakeIP(cfg DesyncConfig, v4 bool) ipAddr {
	if a, ok := ipAddrOf(net.ParseIP(strings.TrimSpace(cfg.FakeIP))); ok && a.is4() == v4 {
		return a
	}
	if v4 {
		return defaultFakeIP
	}
	return defaultFakeIP6
}

// sumMirrorMode reports whether the mode mirrors the triggering segment in-window (base = the segment's own seq)
// instead of sitting below the stream start. rst/synrst also use the stream-start seq, but only the mirror
// family needs handleIP to record c.sumSeq for the late path.
func sumMirrorMode(mode string) bool {
	switch mode {
	case "sum", "seqsum", "rst", "all":
		return true
	}
	return false
}

// FakeClientHello builds an authentic 517-byte Chrome ClientHello carrying sni, matching patterniha/SNI-Spoofing.
// It includes realistic browser extensions (supported_versions TLS 1.3/1.2, ALPN h2/http/1.1, key_share X25519,
// supported_groups, signature_algorithms, and RFC 7685 padding to 512 bytes payload / 517 bytes record)
// without ECH GREASE (which triggers censor ECH-drop rules on Iranian middleboxes).
func FakeClientHello(sni string) []byte {
	if sni == "" {
		return nil
	}
	sniB := []byte(sni)
	if len(sniB) > 219 {
		return FakeClientHelloWithECH(sni)
	}

	// 11 bytes static header: record header (16 03 01 02 00) + handshake header (01 00 01 fc) + version (03 03)
	static1 := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	static2 := []byte{0x20} // session ID len = 32
	var sid [32]byte
	_, _ = rand.Read(sid[:])

	// static3 (44 bytes): cipher suites (18 suites, 36 B) + compression (1 B) + extensions total len (399 B) + server_name ext type (00 00)
	static3 := []byte{
		0x00, 0x24, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2f,
		0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x24, 0xc0, 0x28, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x9f, 0x00, 0x9e,
		0x00, 0x6b, 0x00, 0x67, 0x00, 0xff, 0x01, 0x00, 0x01, 0x8f, 0x00, 0x00,
	}

	// server_name extension: len(sni)+5, len(sni)+3, host_name(0), len(sni), sni
	sniExtLen := len(sniB) + 5
	sniListLen := len(sniB) + 3
	sniExt := []byte{
		byte(sniExtLen >> 8), byte(sniExtLen),
		byte(sniListLen >> 8), byte(sniListLen),
		0x00,
		byte(len(sniB) >> 8), byte(len(sniB)),
	}
	sniExt = append(sniExt, sniB...)

	// static4 (135 bytes): ec_point_formats, supported_groups, session_ticket, alpn, encrypt_then_mac,
	// extended_master_secret, signature_algorithms, supported_versions, psk_key_exchange_modes, key_share header
	static4 := []byte{
		0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d,
		0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
		0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08,
		0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
		0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
		0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
		0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b,
		0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
		0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
	}

	var keyShare [32]byte
	_, _ = rand.Read(keyShare[:])

	// padding extension (0x0015): 219 - len(sniB) zero bytes
	padLen := 219 - len(sniB)
	padExt := make([]byte, 4+padLen)
	padExt[0] = 0x00
	padExt[1] = 0x15
	padExt[2] = byte(padLen >> 8)
	padExt[3] = byte(padLen)

	res := make([]byte, 0, 517)
	res = append(res, static1...)
	res = append(res, rnd[:]...)
	res = append(res, static2...)
	res = append(res, sid[:]...)
	res = append(res, static3...)
	res = append(res, sniExt...)
	res = append(res, static4...)
	res = append(res, keyShare[:]...)
	res = append(res, padExt...)
	return res
}

// FakeClientHelloWithECH builds a realistic TLS 1.3/1.2 ClientHello carrying sni and an ECH GREASE extension (0xfe0d).
func FakeClientHelloWithECH(sni string) []byte {
	if sni == "" {
		return nil
	}
	sniB := []byte(sni)
	// 1. server_name extension: 0000 | ext_len | list_len | 00 (host name) | name_len | name
	ext := []byte{0, 0, byte((len(sniB) + 5) >> 8), byte(len(sniB) + 5), byte((len(sniB) + 3) >> 8), byte(len(sniB) + 3),
		0, byte(len(sniB) >> 8), byte(len(sniB))}
	ext = append(ext, sniB...)

	// 2. supported_versions: length 5 (list len 4: 0x0304 TLS 1.3, 0x0303 TLS 1.2)
	ext = append(ext, 0, 0x2b, 0, 5, 4, 0x03, 0x04, 0x03, 0x03)

	// 3. alpn: h2, http/1.1 (list len 12, ext len 14)
	ext = append(ext, 0, 0x10, 0, 14, 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1')

	// 4. supported_groups: x25519, secp256r1, secp384r1 (list len 6, ext len 8)
	ext = append(ext, 0, 0x0a, 0, 8, 0, 6, 0, 0x1d, 0, 0x17, 0, 0x18)

	// 5. key_share: group x25519 (0x001d), key exchange length 32 (list len 36, ext len 38)
	var keyShare [32]byte
	_, _ = rand.Read(keyShare[:])
	ext = append(ext, 0, 0x33, 0, 38, 0, 36, 0, 0x1d, 0, 32)
	ext = append(ext, keyShare[:]...)

	// 6. signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256 (list len 6, ext len 8)
	ext = append(ext, 0, 0x0d, 0, 8, 0, 6, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01)

	// 7. psk_key_exchange_modes: psk_dhe_ke (list len 1, ext len 2)
	ext = append(ext, 0, 0x2d, 0, 2, 1, 1)

	// 8. encrypted_client_hello (ECH GREASE, RFC 9460 §6.1 / RFC 8701 / draft-ietf-tls-esni-22):
	echData := make([]byte, 0, 138)
	echData = append(echData, 0x00)                   // outer
	echData = append(echData, 0x00, 0x01, 0x00, 0x01) // HKDF-SHA256, AES-128-GCM
	echData = append(echData, 0x00)                   // config_id
	var echEnc [32]byte
	_, _ = rand.Read(echEnc[:])
	echData = append(echData, 0x00, 32)
	echData = append(echData, echEnc[:]...)
	var echPayload [96]byte
	_, _ = rand.Read(echPayload[:])
	echData = append(echData, 0x00, 96)
	echData = append(echData, echPayload[:]...)

	ext = append(ext, 0xfe, 0x0d, byte(len(echData)>>8), byte(len(echData)))
	ext = append(ext, echData...)

	body := make([]byte, 0, 128+len(ext))
	body = append(body, 0x03, 0x03) // client version 1.2 in ClientHello body (RFC 8446)
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)

	// 32-byte session ID (RFC 8446 middlebox compatibility mode)
	var sid [32]byte
	_, _ = rand.Read(sid[:])
	body = append(body, 32)
	body = append(body, sid[:]...)

	// Cipher suites: TLS 1.3 (AES-128, AES-256, ChaCha20) + TLS 1.2 ECDHE (ECDSA/RSA)
	body = append(body, 0, 12,
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03, // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
		0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x23, // ECDHE-ECDSA-AES128-GCM, ECDHE-RSA-AES128-GCM, ECDHE-ECDSA-AES128-SHA256
	)
	body = append(body, 1, 0) // compression: null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

// parseSNIOf returns the SNI a ClientHello built by FakeClientHello carries (test helper).
func parseSNIOf(rec []byte) (string, error) {
	if len(rec) < 5 || rec[0] != 0x16 {
		return "", fmt.Errorf("not a handshake record")
	}
	l := int(rec[3])<<8 | int(rec[4])
	if len(rec) < 5+l {
		return "", fmt.Errorf("short record")
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		return "", fmt.Errorf("not a clienthello")
	}
	p := 4 + 2 + 32 // handshake header + client version + client random
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // skip session id
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	cs := int(hs[p])<<8 | int(hs[p+1])
	p += 2 + cs
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // compression methods
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	el := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	for off := 0; off+4 <= el && p+off+4 <= len(hs); {
		typ := int(hs[p+off])<<8 | int(hs[p+off+1])
		szl := int(hs[p+off+2])<<8 | int(hs[p+off+3])
		if typ == 0 { // server_name: list_len(2) | 00 (host name type) | name_len(2) | name
			q := p + off + 4
			if q+5 > len(hs) {
				break
			}
			nl := int(hs[q+3])<<8 | int(hs[q+4])
			if q+5+nl > len(hs) {
				break
			}
			return string(hs[q+5 : q+5+nl]), nil
		}
		off += 4 + szl
	}
	return "", fmt.Errorf("no sni")
}

// sniExtOffset returns the absolute offset of the server_name extension (its 2-byte type field) inside a record
// built by FakeClientHello, or 0 when the record cannot be walked. split mode cuts at this offset so the SNI
// extension never shares a TCP segment with the record header a DPI needs to start parsing a ClientHello.
func sniExtOffset(rec []byte) int {
	if len(rec) < 5 || rec[0] != 0x16 {
		return 0
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		return 0
	}
	p := 4 + 2 + 32 // handshake header + client version + client random
	if len(hs) < p+1 {
		return 0
	}
	p += 1 + int(hs[p]) // session id
	if len(hs) < p+2 {
		return 0
	}
	cs := int(hs[p])<<8 | int(hs[p+1])
	p += 2 + cs // cipher suites
	if len(hs) < p+1 {
		return 0
	}
	p += 1 + int(hs[p]) // compression methods
	if len(hs) < p+2 {
		return 0
	}
	el := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	for off := 0; off+4 <= el && p+off+4 <= len(hs); {
		typ := int(hs[p+off])<<8 | int(hs[p+off+1])
		szl := int(hs[p+off+2])<<8 | int(hs[p+off+3])
		if typ == 0 {
			return 5 + p + off
		}
		off += 4 + szl
	}
	return 0
}

// splitHello cuts a fake ClientHello into n TCP payload segments for split mode: the first record byte alone,
// then a boundary at the server_name extension so no single segment carries a parseable TLS record, then the rest
// divided evenly. A per-packet DPI never sees a complete ClientHello / SNI; the segments' seq numbers concatenate
// to the same below-window fake, so a reassembling receiver still gets the allowlisted name (and the server
// discards the lot as old duplicates). n<=0 means the default 3.
func splitHello(hello []byte, n int) [][]byte {
	if len(hello) == 0 {
		return nil
	}
	if n <= 0 {
		n = 3
	}
	if n > len(hello) {
		n = len(hello)
	}
	if n > 16 {
		n = 16
	}
	cuts := []int{0, 1}
	if off := sniExtOffset(hello); off > 1 && off < len(hello) && len(cuts) < n {
		cuts = append(cuts, off)
	}
	for len(cuts) < n { // split the widest gap until there are n segments (or no gap has room left)
		best, gap := 0, 0
		for i := 0; i+1 < len(cuts); i++ {
			if g := cuts[i+1] - cuts[i]; g > gap {
				best, gap = i, g
			}
		}
		if gap < 2 {
			break
		}
		mid := (cuts[best] + cuts[best+1]) / 2
		cuts = append(cuts, 0)
		copy(cuts[best+2:], cuts[best+1:])
		cuts[best+1] = mid
	}
	cuts = append(cuts, len(hello))
	segs := make([][]byte, 0, len(cuts)-1)
	for i := 0; i+1 < len(cuts); i++ {
		segs = append(segs, hello[cuts[i]:cuts[i+1]])
	}
	return segs
}

// fakeHelloZeroRecord returns a copy of hello whose TLS record length field is zeroed: the F&F tlshello-0-len
// mask. A stateful DPI that trusts the length field latches an empty handshake record (no SNI to match) and
// stops parsing the flow, while a per-packet sniffer that ignores the field still reads the allowlisted SNI from
// the bytes that follow the header. The packet keeps the plain seq-mode placement, so a server-side kernel that
// did read it would drop it as an old duplicate.
func fakeHelloZeroRecord(hello []byte) []byte {
	if len(hello) < 5 {
		return hello
	}
	out := make([]byte, len(hello))
	copy(out, hello)
	out[3], out[4] = 0, 0
	return out
}

// The true F&F ("Fragment + Fingerprint") plan of the Irancell preset, decoded in
// docs/SNI-SPOOFING-RESEARCH.md §3.3 from the owner's config (pattng-tlshello-0-len):
//
//	finalMask mask 1 — "tlshello", lengths [0,104,1]: reframe the ClientHello record into an RFC-violating
//	empty handshake record, then a first record carrying H[0:104], then one record per remaining handshake byte;
//	finalMask mask 2 — "1-1", lengths [114,1], maxSplit 11: write that stream as 114 B, then nine 1-byte
//	pieces, then the remainder (11 pieces max).
//
// H is the handshake body (the fake hello without its 5-byte record header). |R| = 114 + 6·(|H|−104), e.g.
// ~960 B for a 245 B hello, so the stream needs several segments and the last one is the ~4/5 of it.
const (
	ffChunk       = 104 // handshake bytes in the first non-empty record (mask 1's middle length)
	ffFirstSeg    = 114 // mask 2's first write: the 5-byte empty record + the 104-byte record
	ffDefaultSegs = 11  // mask 2's maxSplit, i.e. ff's default -fake-split
	// ffMaxPayload caps one injected IP packet's TCP payload. The preset's last piece is one application-level
	// write, which a real TCP stack would segment to the path MTU; a raw packet must stay under a standard
	// 1500-byte MTU (20 IP + up to 40 TCP options + payload), so a larger remainder is split into consecutive
	// TCP segments with contiguous sequence numbers.
	ffMaxPayload = 1440
)

// recordReframe rewrites a fake ClientHello (5-byte TLS record header + handshake body H) into the F&F
// "tlshello" record stream: [16 03 01 00 00] (empty handshake record), [16 03 01 00 68] H[0:104], then one
// [16 03 01 00 01] H[i] record per remaining handshake byte. Every field except the leading empty record's
// length is truthful, so a DPI that concatenates record payloads still reassembles the original ClientHello,
// while a DPI that triages the first record/segment sees no SNI. Only the DPI ever sees this: the fake is
// injected below the stream start and the server drops the run by sequence. Returns nil when H is shorter than
// ffChunk (the preset cannot be cut).
func recordReframe(hello []byte) []byte {
	if len(hello) < 5+ffChunk {
		return nil
	}
	hdr := hello[:3] // 16 03 01: the fake hello's record version
	body := hello[5:]
	out := make([]byte, 0, ffFirstSeg+6*(len(body)-ffChunk))
	out = append(out, hdr[0], hdr[1], hdr[2], 0, 0)                            // mask 1's "0": empty record
	out = append(out, hdr[0], hdr[1], hdr[2], byte(ffChunk>>8), byte(ffChunk)) // mask 1's "104"
	out = append(out, body[:ffChunk]...)
	for _, b := range body[ffChunk:] { // mask 1's "1": one record per remaining handshake byte
		out = append(out, hdr[0], hdr[1], hdr[2], 0, 1, b)
	}
	return out
}

// ffSegs cuts the F&F record stream into the preset's TCP segmentation plan: the first piece carries the empty
// and 104-byte records (ffFirstSeg bytes), the next split-2 pieces are one byte each (mask 2's lengths
// ["114","1"]), and the rest of the stream is the final piece (chunked to ffMaxPayload for the MTU reason
// above). split<=0 means the preset's 11; fewer pieces are produced when the stream runs out first.
func ffSegs(r []byte, split int) [][]byte {
	if len(r) == 0 {
		return nil
	}
	if split <= 0 {
		split = ffDefaultSegs
	}
	if split < 2 {
		split = 2
	}
	if len(r) <= ffFirstSeg {
		return [][]byte{r}
	}
	segs := [][]byte{r[:ffFirstSeg]}
	from := ffFirstSeg
	for ones := split - 2; ones > 0 && from < len(r); ones-- {
		segs = append(segs, r[from:from+1])
		from++
	}
	for from < len(r) {
		to := from + ffMaxPayload
		if to > len(r) {
			to = len(r)
		}
		segs = append(segs, r[from:to])
		from = to
	}
	return segs
}

// desyncPeerIP extracts the IP of a host:port peer (empty when unresolvable).
func desyncPeerIP(peer string) string {
	ip, _ := desyncPeerHostPort(peer)
	return ip
}

// desyncPeerHostPort splits a host:port peer into its IP address (v4 or v6; a literal passes straight through,
// a bracketed v6 literal unwrapped by SplitHostPort) and port (best effort, like desyncPeerIP). A hostname
// prefers whichever v4 answer DNS gives first, falling back to the first v6 one, since that was the historical
// behaviour for a dual-stack name; passing the edge's address as a literal (the fake-SNI recipes always do, v4
// or v6) skips this preference entirely.
func desyncPeerHostPort(peer string) (ip, port string) {
	if i := strings.IndexByte(peer, ','); i >= 0 {
		peer = strings.TrimSpace(peer[:i])
	}
	h, p, err := net.SplitHostPort(peer)
	if err != nil {
		h, p = peer, ""
	}
	if v := net.ParseIP(h); v != nil {
		return h, p
	}
	if addrs, err := net.LookupHost(h); err == nil && len(addrs) > 0 {
		for _, a := range addrs {
			if v := net.ParseIP(a); v != nil && v.To4() != nil {
				return a, p
			}
		}
		return addrs[0], p
	}
	return "", p
}

// desyncAllPeerIPs resolves all IP addresses (v4 and v6) for a peer string, including comma-separated peers.
func desyncAllPeerIPs(peer string) []ipAddr {
	var ips []ipAddr
	seen := map[ipAddr]bool{}
	for _, p := range strings.Split(peer, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		h, _, err := net.SplitHostPort(p)
		if err != nil {
			h = p
		}
		if v := net.ParseIP(h); v != nil {
			if a, ok := ipAddrOf(v); ok && !seen[a] {
				seen[a] = true
				ips = append(ips, a)
			}
			continue
		}
		if addrs, err := net.LookupHost(h); err == nil {
			for _, a := range addrs {
				if v := net.ParseIP(a); v != nil {
					if a, ok := ipAddrOf(v); ok && !seen[a] {
						seen[a] = true
						ips = append(ips, a)
					}
				}
			}
		}
	}
	return ips
}

// ipAddr holds an IPv4 or IPv6 address: 16 bytes always, IPv4 stored v4-mapped (::ffff:a.b.c.d, matching
// net.IP.To16), so desyncKey and the packet builders need no separate family-specific copies.
type ipAddr [16]byte

// ipAddrOf converts a parsed net.IP; false means ip was nil (not a valid address).
func ipAddrOf(ip net.IP) (ipAddr, bool) {
	var a ipAddr
	p := ip.To16()
	if p == nil {
		return a, false
	}
	copy(a[:], p)
	return a, true
}

// addr4 builds the ipAddr of four IPv4 address bytes.
func addr4(b [4]byte) ipAddr {
	a := ipAddr{10: 0xff, 11: 0xff}
	copy(a[12:], b[:])
	return a
}

// is4 reports whether the address is IPv4 (stored v4-mapped, ::ffff:0:0/96).
func (a ipAddr) is4() bool {
	for _, b := range a[:10] {
		if b != 0 {
			return false
		}
	}
	return a[10] == 0xff && a[11] == 0xff
}

// bytes is the address as it appears on the wire: 4 bytes for IPv4, 16 for IPv6.
func (a ipAddr) bytes() []byte {
	if a.is4() {
		return append([]byte(nil), a[12:]...)
	}
	return append([]byte(nil), a[:]...)
}

// desyncKey is one connection's outgoing 4-tuple (src = us). Inbound frames match the reversed key.
type desyncKey struct {
	srcIP ipAddr
	dstIP ipAddr
	srcPt uint16
	dstPt uint16
}

// ipHeader returns the IPv4 (20 B, DF set, header checksum filled) or IPv6 (40 B) header for tcpLen bytes of TCP
// following it, picking the family from the key's addresses (both sides of a key are always the same family).
func ipHeader(k desyncKey, ttl, tcpLen int) []byte {
	if k.dstIP.is4() {
		h := make([]byte, 20)
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(20+tcpLen))
		h[6] = 0x40 // Don't Fragment
		h[8] = byte(ttl)
		h[9] = 6 // TCP
		copy(h[12:16], k.srcIP[12:])
		copy(h[16:20], k.dstIP[12:])
		binary.BigEndian.PutUint16(h[10:], csum(h))
		return h
	}
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(tcpLen))
	h[6] = 6 // next header: TCP
	h[7] = byte(ttl)
	copy(h[8:24], k.srcIP[:])
	copy(h[24:40], k.dstIP[:])
	return h
}

// ipHdrLen is the length of a header ipHeader built, read back off the version nibble.
func ipHdrLen(pkt []byte) int {
	if pkt[0]>>4 == 6 {
		return 40
	}
	return 20
}

// fakePacketWithOptions builds the IP+TCP+options+payload packet of one fake ClientHello (IPv4 or IPv6, picked
// from k). When opts is non-empty (e.g. Linux kernel TCP timestamps NOP, NOP, TSval, TSecr), the segment
// mirrors standard kernel packet formatting (Data Offset > 5) so DPI appliances performing
// TCP option consistency validation cannot distinguish the injected marker from normal traffic.
func fakePacketWithOptions(k desyncKey, seq, ack uint32, ttl int, hello []byte, opts []byte) []byte {
	tcpHdrLen := 20 + len(opts)
	pad := (4 - (tcpHdrLen % 4)) % 4
	tcpHdrLen += pad
	dataOffset := byte(tcpHdrLen / 4)

	ih := ipHeader(k, ttl, tcpHdrLen+len(hello))
	hl := len(ih)
	pkt := make([]byte, hl+tcpHdrLen+len(hello))
	copy(pkt, ih)

	th := pkt[hl : hl+tcpHdrLen]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = dataOffset << 4
	th[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	if len(opts) > 0 {
		copy(th[20:], opts)
		for i := 20 + len(opts); i < tcpHdrLen; i++ {
			th[i] = 0x01 // TCP NOP option
		}
	}
	copy(pkt[hl+tcpHdrLen:], hello)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[hl:], k.srcIP.bytes(), k.dstIP.bytes()))
	return pkt
}

// fakePacket builds the IP+TCP+payload packet of one fake ClientHello without TCP options. Pure: the same inputs
// build the same packet, so the tests pin it byte for byte (seq arithmetic, TTL, ack, checksum).
func fakePacket(k desyncKey, seq, ack uint32, ttl int, hello []byte) []byte {
	return fakePacketWithOptions(k, seq, ack, ttl, hello, nil)
}

// fakeFlagPacket builds an IP+TCP header-only packet (no payload) carrying the given TCP flags. Pure: the same
// inputs build the same packet.
func fakeFlagPacket(k desyncKey, seq, ack uint32, ttl int, flags byte) []byte {
	ih := ipHeader(k, ttl, 20)
	hl := len(ih)
	pkt := make([]byte, hl+20)
	copy(pkt, ih)
	th := pkt[hl:]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:], 0)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[hl:], k.srcIP.bytes(), k.dstIP.bytes()))
	return pkt
}

// fakeRSTPacket builds an in-window TCP RST+ACK packet with no payload. Pure: the same inputs build the same packet.
func fakeRSTPacket(k desyncKey, seq, ack uint32, ttl int) []byte {
	return fakeFlagPacket(k, seq, ack, ttl, 0x14) // RST|ACK
}

// parseEthIP returns the IPv4 or IPv6 packet carried by an ethernet, VLAN, SLL, or raw frame, or nil.
func parseEthIP(frame []byte) []byte {
	// Standard Ethernet (14-byte header, EtherType 0x0800)
	if len(frame) >= 34 && binary.BigEndian.Uint16(frame[12:]) == 0x0800 && frame[14]>>4 == 4 {
		return frame[14:]
	}
	// Direct IPv4 (raw IP / tun / wg interfaces without L2 header)
	if len(frame) >= 20 && frame[0]>>4 == 4 {
		ihl := int(frame[0]&0x0f) * 4
		if ihl >= 20 && len(frame) >= ihl {
			return frame
		}
	}
	// 802.1Q VLAN tagged Ethernet (18-byte header)
	if len(frame) >= 38 && binary.BigEndian.Uint16(frame[12:]) == 0x8100 && binary.BigEndian.Uint16(frame[16:]) == 0x0800 && frame[18]>>4 == 4 {
		return frame[18:]
	}
	// Linux cooked mode (SLL, 16-byte header)
	if len(frame) >= 36 && binary.BigEndian.Uint16(frame[14:]) == 0x0800 && frame[16]>>4 == 4 {
		return frame[16:]
	}
	// The same four framings, IPv6 (EtherType/SLL protocol 0x86dd, a 40-byte fixed header to check the version
	// nibble): Ethernet, direct (tun/wg), VLAN, cooked mode.
	if len(frame) >= 14+40 && binary.BigEndian.Uint16(frame[12:]) == 0x86dd && frame[14]>>4 == 6 {
		return frame[14:]
	}
	if len(frame) >= 40 && frame[0]>>4 == 6 {
		return frame
	}
	if len(frame) >= 18+40 && binary.BigEndian.Uint16(frame[12:]) == 0x8100 && binary.BigEndian.Uint16(frame[16:]) == 0x86dd && frame[18]>>4 == 6 {
		return frame[18:]
	}
	if len(frame) >= 16+40 && binary.BigEndian.Uint16(frame[14:]) == 0x86dd && frame[16]>>4 == 6 {
		return frame[16:]
	}
	return nil
}

// desyncTracker is the portable handshake state machine of the fake-SNI layer. The Linux injector feeds it every
// IPv4 packet of the wire (as raw IP byte slices, no ethernet header); tests feed it synthetic handshakes.
//
// Two trigger paths cover every dial order, because Wrap can only register a connection after dial returns and
// the SYN/SYN-ACK may already be gone by then:
//
//	early: Wrap knows the ISN (read off the socket with the TCP_REPAIR probe, or from a re-SYN on a tracked
//	       key). The fake fires on the first outbound segment at or after the stream start: the final ACK of
//	       the handshake, or the first data segment if that already went out. The fake precedes (or rides
//	       next to) the real first flight.
//	late:  the ISN is unknown (probe unavailable). The fake fires on the first outbound DATA segment seen on
//	       the announced key, its own sequence number derived from that segment's: same-segment-bundle
//	       desync, the zapret "disorder"/"fake,split" family. The real ClientHello is already on the wire,
//	       so this needs the classifier not to re-read the flow after it accepted the fake — the documented
//	       behaviour of the allowlist middleboxes of January 2026.
//
// Inbound SYN-ACKs of a tracked key cross-check the ack against the ISN: a NAT that rewrote our sequence numbers
// updates it, so the fake still lands below the stream start as the server sees it (seq mode's known failure
// becomes survivable when the shift is uniform). The inbound TTL of the peer is learned from any SYN-ACK from
// the peer IP, which is what calibrates -fake-mode ttl with -fake-ttl 0.
type desyncTracker struct {
	cfg       DesyncConfig
	peerIP    ipAddr
	peerIPs   map[ipAddr]bool
	hello     []byte
	snis      []string // SNIs with a non-empty hello; pickHello rebuilds fresh bytes per fire
	helloIdx  atomic.Uint32
	send      func(pkt []byte) // set by the injector (raw socket) or a test (collector); nil = drop
	logf      func(string, ...any)
	mu        sync.Mutex
	conns     map[desyncKey]*desyncConn
	wait      map[desyncKey]chan struct{} // closed by fire, waited on by Wrap
	ackWait   map[desyncKey]chan struct{} // closed by duplicate ACK from server, waited on by Wrap
	recent    map[desyncKey]*desyncHS     // handshakes toward the peer seen before Wrap announced them (see announce)
	peerTTLv  uint8
	firedN    int
	miss      int
	missNoted bool
	closed    bool
}

type desyncConn struct {
	synSeq    uint32   // the ISN as the wire sees it (updated when a NAT rewrite is detected)
	isnKnown  bool     // early mode: the ISN is known before any data fires
	synAckSeq uint32   // seq of the server's SYN-ACK
	synAckAck uint32   // ack field of the server's SYN-ACK (== ISN+1)
	sumSeq    uint32   // sum/seqsum: seq of the outbound data segment being mirrored (0 = none yet)
	tcpOpts   []byte   // kernel TCP options observed on outbound non-SYN segments (e.g. timestamps)
	fakeSent  bool     // fake packet has been injected
	waitAck   uint32   // duplicate ACK expected from server (isn+1 / SND.NXT)
	sent      [][]byte // needsAck modes: the markers sent at once on fire, kept for one retransmit (resend)
	at        time.Time
}

// desyncHS is what the sniffer saw of one handshake toward the peer before anyone announced it.
type desyncHS struct {
	isn     uint32 // our SYN's seq
	srvSeq  uint32 // the SYN-ACK's seq
	srvAck  uint32 // the SYN-ACK's ack field (our ISN+1 as the server sees it, so a NAT rewrite is followed)
	haveSyn bool
	haveSA  bool
	opts    []byte // kernel TCP options of our first non-SYN segment (timestamps)
	at      time.Time
}

// hopTTL turns the TTL a packet arrived with into the TTL that makes our packet die one hop short of that peer:
// the sender started from the smallest common initial TTL at or above what arrived (32, 64, 128 or 255), so the
// path length is the difference. (Using the arrived TTL minus one, as 2.7.0-2.10.7 did, sends a packet that still
// reaches the server.)
func hopTTL(arrived uint8) int {
	init := 255
	for _, i := range []int{32, 64, 128} {
		if int(arrived) <= i {
			init = i
			break
		}
	}
	return max(init-int(arrived)-1, 1)
}

// newDesyncTracker prepares the state machine for one peer IP. Only SNIs that produce a hello are
// kept; pickHello rebuilds the hello per fire from these.
func newDesyncTracker(cfg DesyncConfig, peerIP ipAddr) *desyncTracker {
	snis := splitSNIs(cfg.SNI)
	good := make([]string, 0, len(snis))
	var hello []byte
	for _, s := range snis {
		if h := FakeClientHello(s); len(h) > 0 {
			good = append(good, s)
			if hello == nil {
				hello = h
			}
		}
	}
	return &desyncTracker{cfg: cfg, peerIP: peerIP, peerIPs: map[ipAddr]bool{peerIP: true}, hello: hello, snis: good,
		conns: map[desyncKey]*desyncConn{}, wait: map[desyncKey]chan struct{}{}, ackWait: map[desyncKey]chan struct{}{}, recent: map[desyncKey]*desyncHS{}}
}

func (t *desyncTracker) addPeerIP(ip ipAddr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.peerIPs == nil {
		t.peerIPs = map[ipAddr]bool{}
	}
	t.peerIPs[ip] = true
}

func (t *desyncTracker) isPeer(ip ipAddr) bool {
	return ip == t.peerIP || (t.peerIPs != nil && t.peerIPs[ip])
}

func (t *desyncTracker) needsAck() bool {
	switch t.cfg.Mode {
	case "", "seq", "seqsum", "split", "synrst", "all", "ff", "paws":
		return true
	}
	return false
}

func (t *desyncTracker) ackChan(k desyncKey) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ackWait[k]
}

// pickHello builds a FRESH FakeClientHello per fire (round-robining the SNIs when several are
// configured). A cached hello replays byte-identical randoms (client random, session id, key share,
// ECH) on every connection from this process — two connections from one IP then carry matching
// synthetic hellos, a one-glance censor signature (audit 2026-10-21). FakeClientHello is ~1 µs.
func (t *desyncTracker) pickHello() []byte {
	if len(t.snis) == 0 {
		return t.hello
	}
	s := t.snis[0]
	if len(t.snis) > 1 {
		s = t.snis[int(t.helloIdx.Add(1)-1)%len(t.snis)]
	}
	if h := FakeClientHello(s); len(h) > 0 {
		return h
	}
	return t.hello
}

// announce registers a connection Wrap is waiting for and returns its channel. known says the ISN is exact
// (from the socket probe); with known=false the tracker fires late, off the first data segment.
// Optional rcvNxt passes the server's sequence number (from TCP_RECV_QUEUE), allowing immediate injection
// without relying on sniffer packet capture.
func (t *desyncTracker) announce(k desyncKey, isn uint32, known bool, rcvNxt ...uint32) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := make(chan struct{})
	if t.closed {
		close(ch)
		return ch
	}
	now := time.Now()
	if len(t.conns) > 16 {
		for ck, c := range t.conns {
			if now.Sub(c.at) > 30*time.Second {
				t.abandonLocked(ck)
			}
		}
	}
	if t.peerIPs == nil {
		t.peerIPs = map[ipAddr]bool{}
	}
	t.peerIPs[k.dstIP] = true
	t.wait[k] = ch
	t.ackWait[k] = make(chan struct{})
	c := &desyncConn{synSeq: isn, isnKnown: known, at: now}
	t.conns[k] = c
	var rcv uint32
	if len(rcvNxt) > 0 {
		rcv = rcvNxt[0]
	}
	if known && rcv > 0 {
		c.synAckAck = isn + 1
		c.synAckSeq = rcv - 1
		if m := t.recent[k]; m != nil {
			delete(t.recent, k)
			c.tcpOpts = m.opts
		}
		if sumMirrorMode(t.cfg.Mode) {
			c.sumSeq = isn + 1
		}
		t.fireLocked(k, c, isn+1, rcv)
	} else if m := t.recent[k]; m != nil && m.haveSA {
		delete(t.recent, k)
		if m.srvAck > 0 {
			c.synSeq = m.srvAck - 1
		} else {
			c.synSeq = m.isn
		}
		c.isnKnown = true
		c.synAckSeq, c.synAckAck, c.tcpOpts = m.srvSeq, m.srvAck, m.opts
		if sumMirrorMode(t.cfg.Mode) {
			c.sumSeq = m.srvAck
		}
		t.fireLocked(k, c, m.srvAck, m.srvSeq+1)
	}
	return ch
}

// noteHandshake remembers the packets of handshakes toward the peer that nobody announced (yet); mu held.
func (t *desyncTracker) noteHandshake(out, in desyncKey, d, s ipAddr, th []byte, off int, seq, ackv uint32, syn, ackf bool, payload int, now time.Time) {
	isDstPeer := t.isPeer(d)
	isSrcPeer := t.isPeer(s)
	switch {
	case isDstPeer && syn && !ackf && payload == 0:
		if len(t.recent) > 64 {
			for k, m := range t.recent {
				if now.Sub(m.at) > 20*time.Second {
					delete(t.recent, k)
				}
			}
		}
		t.recent[out] = &desyncHS{isn: seq, haveSyn: true, at: now}
	case isSrcPeer && syn && ackf && payload == 0:
		if m := t.recent[in]; m != nil && m.haveSyn {
			m.srvSeq, m.srvAck, m.haveSA = seq, ackv, true
		}
	case isDstPeer && !syn && off > 20:
		if m := t.recent[out]; m != nil && len(m.opts) == 0 {
			m.opts = append([]byte(nil), th[20:off]...)
		}
	}
}

// abandonLocked drops a connection (caller holds t.mu).
func (t *desyncTracker) abandonLocked(k desyncKey) {
	if ch := t.wait[k]; ch != nil {
		delete(t.wait, k)
		close(ch)
	}
	if ackCh := t.ackWait[k]; ackCh != nil {
		delete(t.ackWait, k)
		close(ackCh)
	}
	delete(t.conns, k)
}

// keep records a marker for resend (mu held; only modes that wait for the duplicate ACK resend). Delayed markers
// are recorded when they are scheduled, so a resend repeats the whole set in order.
func (t *desyncTracker) keep(c *desyncConn, p []byte) {
	if t.needsAck() && t.send != nil {
		c.sent = append(c.sent, append([]byte(nil), p...))
	}
}

// resend fires the markers of k once more (Wrap, when the duplicate ACK did not come back within an RTT: the
// marker itself may have been lost). It reports whether anything was sent.
func (t *desyncTracker) resend(k desyncKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.conns[k]
	if c == nil || len(c.sent) == 0 || t.send == nil {
		return false
	}
	for _, p := range c.sent {
		t.send(p)
	}
	return true
}

// abandon drops a connection whose Wrap timed out (handshake never observed).
func (t *desyncTracker) abandon(k desyncKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.abandonLocked(k)
}

func (t *desyncTracker) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		for k, ch := range t.wait {
			close(ch)
			delete(t.wait, k)
		}
		for k, ackCh := range t.ackWait {
			close(ackCh)
			delete(t.ackWait, k)
		}
		t.conns = map[desyncKey]*desyncConn{}
	}
}

// fired reports how many fakes have been sent.
func (t *desyncTracker) fired() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.firedN
}

// peerTTL reports the learned inbound TTL of the peer (0 = not seen yet).
func (t *desyncTracker) peerTTL() uint8 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peerTTLv
}

// parseIPTCP extracts what handleIP needs from an IPv4 or IPv6 packet: source and destination address, the
// TTL/hop limit, and the TCP header+payload slice. ok is false for anything but plain IPv4/IPv6 TCP (an IPv6
// packet with extension headers before TCP is not understood and is skipped, like a malformed IPv4 one).
func parseIPTCP(ip []byte) (s, d ipAddr, ttl byte, th []byte, ok bool) {
	if len(ip) < 20 {
		return
	}
	switch ip[0] >> 4 {
	case 4:
		if ip[9] != 6 { // TCP only, like the reference tool
			return
		}
		ihl := int(ip[0]&0xf) * 4
		if ihl < 20 || len(ip) < ihl {
			return
		}
		return addr4([4]byte(ip[12:16])), addr4([4]byte(ip[16:20])), ip[8], ip[ihl:], true
	case 6:
		if len(ip) < 40 || ip[6] != 6 { // next header must be TCP directly, no extension headers
			return
		}
		copy(s[:], ip[8:24])
		copy(d[:], ip[24:40])
		return s, d, ip[7], ip[40:], true
	}
	return
}

// handleIP advances the state machine with one raw IPv4 or IPv6 packet (header included, no ethernet header).
func (t *desyncTracker) handleIP(ip []byte) {
	s, d, ttl, th, ok := parseIPTCP(ip)
	if !ok || len(th) < 20 {
		return
	}
	off := int(th[12]>>4) * 4
	if off < 20 || len(th) < off {
		return
	}
	sport, dport := binary.BigEndian.Uint16(th[0:]), binary.BigEndian.Uint16(th[2:])
	out := desyncKey{s, d, sport, dport}
	in := desyncKey{d, s, dport, sport}
	seq, ackv := binary.BigEndian.Uint32(th[4:]), binary.BigEndian.Uint32(th[8:])
	syn, ackf, rst := th[13]&0x02 != 0, th[13]&0x10 != 0, th[13]&0x04 != 0
	payload := len(th) - off

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	now := time.Now()
	// any SYN-ACK from the peer teaches the inbound TTL (ttl auto-calibration), tracked or not
	if syn && ackf && payload == 0 && !rst && t.isPeer(s) && t.peerTTLv == 0 {
		t.peerTTLv = ttl
	}
	if !rst && (t.conns[out] == nil && t.conns[in] == nil) {
		t.noteHandshake(out, in, d, s, th, off, seq, ackv, syn, ackf, payload, now)
	}
	// duplicate ACK check from server in response to our injected fake packet (patterniha synchronization):
	// when an out-of-window fake packet was sent (wrong_seq method), RFC 793/9293 mandates that
	// the server reply with a pure ACK where ack == SND.NXT. Receiving it confirms the fake packet
	// cleared the middlebox DPI and reached the server before real application data is sent.
	if c := t.conns[in]; c != nil && c.fakeSent {
		if !syn && ackf && !rst && payload == 0 && ackv == c.waitAck {
			delete(t.conns, in)
			if ackCh := t.ackWait[in]; ackCh != nil {
				delete(t.ackWait, in)
				close(ackCh)
			}
			return
		}
	}
	// our outgoing SYN on a tracked key: (re)learn the ISN from the wire
	if c := t.conns[out]; c != nil && syn && !ackf && payload == 0 && !rst {
		if !c.isnKnown || seq != c.synSeq {
			c.synSeq, c.isnKnown, c.synAckSeq, c.synAckAck = seq, true, 0, 0
		}
		c.at = now
		return
	}
	// inbound SYN-ACK for a tracked conn: remember its seq/ack, and follow a NAT that rewrote our ISN
	if c := t.conns[in]; c != nil && syn && ackf && payload == 0 && !rst {
		if c.isnKnown && ackv != c.synSeq+1 {
			c.synSeq = ackv - 1 // uniform rewrite: the server's stream starts here now
		}
		c.synAckSeq, c.synAckAck, c.at = seq, ackv, now
		return
	}
	if rst {
		delete(t.recent, out)
		delete(t.recent, in)
		if t.conns[out] != nil {
			t.abandonLocked(out)
		}
		if t.conns[in] != nil {
			t.abandonLocked(in)
		}
		return
	}
	// outbound non-SYN segment on a tracked connection: record kernel options (e.g. TCP timestamps)
	if c := t.conns[out]; c != nil && !syn && off > 20 && len(c.tcpOpts) == 0 {
		c.tcpOpts = append([]byte(nil), th[20:off]...)
	}
	c := t.conns[out]
	if c == nil || c.fakeSent || c.synAckAck == 0 && !c.isnKnown {
		return // nothing to anchor the fake's ack to yet, or fake already fired
	}
	switch {
	case c.isnKnown:
		// early: fire on the handshake's final ACK or the first data flight, whichever comes first.
		// sum/seqsum modes stay for the first DATA segment: their fake is a valid-window duplicate of that
		// segment, so it needs the segment's real seq/ack to be identical to the real flight (bare ACKs have
		// nothing to mirror). The mirror base lives on the connection (2.8.1): it was tracker-global, so two
		// pool connections opening at once cross-set it and the second fire mirrored the wrong segment.
		if !syn && ackf && seq-c.synSeq+1 < 0x80000000 {
			if sumMode := sumMirrorMode(t.cfg.Mode); sumMode {
				c.sumSeq = c.synSeq + 1
			}
			t.fireLocked(out, c, c.synSeq+1, ackv)
		}
	default:
		// late: the first outbound data segment is the anchor (its seq IS the stream start)
		if payload > 0 && ackf && !syn {
			if sumMirrorMode(t.cfg.Mode) {
				c.sumSeq = seq
			}
			t.fireLocked(out, c, seq, ackv)
		}
	}
}

// fireLocked builds and sends the fake for one completed handshake (mu held).
func (t *desyncTracker) fireLocked(k desyncKey, c *desyncConn, base, ack uint32) {
	ttl := 64
	if t.cfg.Mode == "ttl" {
		ttl = t.cfg.TTL
		if ttl <= 0 { // auto: one hop less than the distance the server's packets travel
			if t.peerTTLv > 0 {
				ttl = hopTTL(t.peerTTLv)
			} else {
				t.miss++
				if !t.missNoted {
					t.missNoted = true
					if t.logf != nil {
						t.logf("wat: fake-sni ttl auto: the peer's TTL is not learned yet, handshake left unclassified (calibrates from the first SYN-ACK)")
					}
				}
				return
			}
		}
	}
	// The sum family (sum, seqsum, rst, all) mirrors the triggering data segment: identical seq (so the fake sits
	// in the receiver window where the DPI's reassembler is already collecting), identical ack, but a deliberately
	// damaged TCP checksum — the same fooling as GoodbyeDPI's --wrong-chksum and zapret's badsum. The server's
	// kernel drops it at checksum validation; a DPI that parses before checksumming reads the SNI. NATs that
	// validate checksums (nf_conntrack_checksum=1 + an INVALID-drop FORWARD rule) kill these modes; ISPs usually
	// pass (zapret's documented field observation).
	if sumMirrorMode(t.cfg.Mode) {
		base = c.sumSeq
	}
	// seq = base - len(fake): the fake lands exactly below the stream start. The server holds snd_una at the
	// stream start, so this is an old duplicate; a DPI without window checks reassembles it as the first flight.
	t.firedN++
	if ch := t.wait[k]; ch != nil {
		delete(t.wait, k)
		close(ch)
	}
	if t.needsAck() {
		c.fakeSent = true
		c.waitAck = base
	} else {
		delete(t.conns, k)
		if ackCh := t.ackWait[k]; ackCh != nil {
			delete(t.ackWait, k)
			close(ackCh)
		}
	}
	send := t.send
	if t.needsAck() && send != nil { // keep the markers for the one retransmit Wrap may ask for (3.0.0)
		c.sent = c.sent[:0]
		send = func(p []byte) {
			t.keep(c, p)
			t.send(p)
		}
	}
	if t.send == nil {
		if ackCh := t.ackWait[k]; ackCh != nil {
			delete(t.ackWait, k)
			close(ackCh)
		}
		delete(t.conns, k)
		return
	}
	if t.cfg.Mode == "rst" {
		// rst mode sends an in-window RST|ACK with damaged checksum: middleboxes clear flow state,
		// while the server kernel drops corrupted checksum packets before parsing flags.
		pkt := fakeRSTPacket(k, base, ack, ttl)
		damageChecksum(pkt)
		send(pkt)
		return
	}
	hello := t.pickHello()
	switch t.cfg.Mode {
	case "split":
		// split mode: the same below-window fake ClientHello, but cut across t.cfg.Split TCP segments (default 3:
		// first record byte alone, then a boundary at the SNI extension, then the remainder). The seq numbers
		// concatenate, so the server still discards the whole ghost as old duplicates and a reassembling DPI still
		// reads the allowlisted SNI; a per-packet DPI (the MCI/Irancell TLS parsers that inspect each first payload
		// segment) never gets a parseable record or SNI out of one segment. Targets: stateless SNI filters.
		seq := base - uint32(len(hello))
		off := 0
		for _, seg := range splitHello(hello, t.cfg.Split) {
			send(fakePacketWithOptions(k, seq+uint32(off), ack, ttl, seg, c.tcpOpts))
			off += len(seg)
		}
	case "hlen0":
		// hlen0 mode (F&F tlshello-0-len): a fake ClientHello whose TLS record length field is 0, placed below the
		// stream start like seq mode. A stateful DPI that trusts the length field latches an empty handshake record
		// with no SNI and stops parsing the flow; the bytes after the header still carry the allowlisted SNI for a
		// per-packet sniffer, and the real first flight follows right behind the marker. Targets: the stateful
		// TLS-SNI parsers of the MCI/Irancell filters.
		send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, fakeHelloZeroRecord(hello), c.tcpOpts))
	case "fakeip":
		// fakeip mode: a well-formed SYN and ClientHello for a flow from this same client port to a whitelisted CDN
		// address (cfg.FakeIP, default 104.16.0.1 = a Cloudflare edge), with sequence numbers below the real stream
		// start. The destination differs, so the packets leave toward the CDN (Cloudflare answers, the kernel RSTs
		// it) and the real server never sees them; a DPI that keys its allowlist by destination IP has now recorded
		// this client talking to an allowed CDN. Targets: IP-allowlist classifiers (Irancell's 188.114.98.0/CDN
		// whitelist, MCI's CDN-fronting method).
		fk := k
		fk.dstIP, fk.dstPt = desyncFakeIP(t.cfg, k.dstIP.is4()), 443
		syn := base - uint32(len(hello)) - 1
		send(fakeFlagPacket(fk, syn, 0, ttl, 0x02)) // SYN
		send(fakePacketWithOptions(fk, syn+1, 0, ttl, hello, c.tcpOpts))
	case "synrst":
		// synrst mode: an in-window SYN|RST with a damaged TCP checksum. SYN|RST is not a legal flag combination,
		// so stateful middleboxes that keep a flow table treat it as a teardown-and-reset and purge the entry harder
		// than a plain RST|ACK; the server's kernel drops the packet at checksum validation before reading flags.
		// Targets: stateful flow tables that ignore a single in-window RST (the MCI/Irancell session trackers).
		pkt := fakeFlagPacket(k, base, ack, ttl, 0x06) // SYN|RST
		damageChecksum(pkt)
		send(pkt)
	case "ff":
		// ff mode: the real F&F record + segment plan (docs/SNI-SPOOFING-RESEARCH.md §3.3, the Irancell
		// pattng-tlshello-0-len preset). The fake ClientHello is re-framed into an empty record + a 104-byte
		// record + one 1-byte record per remaining handshake byte, then sent as ≤Split TCP segments (default 11:
		// 114 B carrying the first two records, then nine 1-byte pieces, then the remainder) with contiguous
		// below-window sequence numbers ending exactly at the real stream's ISN+1, so the server drops the whole
		// run as old duplicates while a record/segment-triage DPI (Irancell/MCI) never sees a parseable SNI.
		// Targets: the field recipe's working DPI class (first-record / first-segment triage).
		if !t.fireFFLocked(k, c, base, ack, ttl, hello, 0) {
			// the preset needs H[0:104]: too short (only reachable with a hand-built tracker, FakeClientHello is
			// always longer) -> keep the flow classified with the plain seq marker instead of sending nothing.
			t.miss++
			if !t.missNoted {
				t.missNoted = true
				if t.logf != nil {
					t.logf("wat: fake-sni ff: the fake ClientHello is shorter than the F&F record plan (%d < %d bytes), sending the plain seq marker", len(hello), 5+ffChunk)
				}
			}
			send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts))
		}
	case "all":
		// all mode (kitchen sink): the seq + sum + hlen0 markers ~1 ms apart, then the true F&F record/segment
		// plan from 3 ms, so a filter has to mishandle every signal class (below-window junk, bad checksums,
		// zero-length records, the F&F record/segment shape) to miss the SNI. The time.AfterFunc spacing is
		// seqsum's: the sniffer lock is never held across a sleep (audit 2026-10-21).
		send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts)) // seq: below window, valid checksum
		sumPkt := fakePacketWithOptions(k, base, ack, ttl, hello, c.tcpOpts)
		damageChecksum(sumPkt)
		hlenPkt := fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, fakeHelloZeroRecord(hello), c.tcpOpts)
		t.keep(c, sumPkt)
		t.keep(c, hlenPkt)
		time.AfterFunc(time.Millisecond, func() { t.send(sumPkt) })
		time.AfterFunc(2*time.Millisecond, func() { t.send(hlenPkt) })
		_ = t.fireFFLocked(k, c, base, ack, ttl, hello, 3*time.Millisecond)
	case "seqsum":
		// dual marker (2.8.0): the below-window seq fake first, then the in-window bad-checksum mirror
		// ~1 ms later (GoodbyeDPI sends wrong-seq + wrong-chksum as two fakes per connection). A filter
		// must discard BOTH correctly to miss the SNI: window-junk dropping alone does not stop the sum
		// marker, checksum dropping alone does not stop the seq marker. Both still die before the server.
		send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts))
		pkt := fakePacketWithOptions(k, base, ack, ttl, hello, c.tcpOpts)
		damageChecksum(pkt)
		// the second marker goes out after the 1 ms gap WITHOUT sleeping under t.mu: fireLocked runs
		// inside the sniffer's lock and a sleep here stalls every concurrent fire and Wrap announce
		// (audit 2026-10-21). close() never nils t.send, so a fire racing shutdown is a dropped packet.
		t.keep(c, pkt)
		time.AfterFunc(time.Millisecond, func() { t.send(pkt) })
	case "sum":
		// sum mode mirrors the triggering data segment: in-window seq (base = c.sumSeq), damaged checksum
		pkt := fakePacketWithOptions(k, base, ack, ttl, hello, c.tcpOpts)
		damageChecksum(pkt)
		send(pkt)
	case "paws":
		// paws mode: an in-window fake ClientHello with a VALID TCP checksum and a stale TCP timestamp. The server's
		// Linux kernel drops it via RFC 7323 PAWS (TSval older than TS.recent) and answers with a dup-ACK, while a DPI
		// that checks window and checksum accepts it and classifies the flow. The kernel adds a random per-connection
		// offset to TSval, so a fixed value would be "older" only half the time: the stale value is derived from the
		// real one (3.0.2). Without a timestamp option nothing makes the kernel drop an in-window segment (it would
		// be taken as the real stream), so the plain below-window seq marker goes out instead.
		opts, ok := staleTimestampOpts(c.tcpOpts)
		if !ok {
			send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts))
			break
		}
		send(fakePacketWithOptions(k, base, ack, ttl, hello, opts))
	default:
		send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts))
	}
}

// fireFFLocked builds the F&F record re-frame + segment plan for one fake hello and injects it below the stream
// start (mu held): the first piece goes out now, the rest at the preset's 1 ms "delays" via time.AfterFunc — a
// sleep here would stall every concurrent fire and Wrap announce (audit 2026-10-21). startDelay shifts the whole
// run later so all mode can put it after its single markers. Every sequence number is < the stream start the
// server holds, and the last piece ends exactly at it, so the server drops the run as old duplicates. Returns
// false (sending nothing) when the hello is too short for the 104-byte record.
func (t *desyncTracker) fireFFLocked(k desyncKey, c *desyncConn, base, ack uint32, ttl int, hello []byte, startDelay time.Duration) bool {
	r := recordReframe(hello)
	if len(r) == 0 {
		return false
	}
	seq := base - uint32(len(r)) // the first fragment starts below the stream start
	off := 0
	for i, seg := range ffSegs(r, t.cfg.Split) {
		pkt := fakePacketWithOptions(k, seq+uint32(off), ack, ttl, seg, c.tcpOpts)
		off += len(seg)
		t.keep(c, pkt)
		if d := startDelay + time.Duration(i)*time.Millisecond; d <= 0 {
			t.send(pkt)
		} else {
			time.AfterFunc(d, func() { t.send(pkt) }) // the preset's 1 ms spacing; frames arrive in sequence order
		}
	}
	return true
}

// damageChecksum rewrites a valid TCP checksum into an invalid one, unconditionally: s-1, but when that would
// wrap to 0xffff (a VALID fold: the internet checksum of a correct packet is 0xffff by definition) it goes to
// s-2 instead. The 2.7.1 formula (s^1)-1 was an IDENTITY for every even s — (s+1)-1 = s — so on average every
// second sum-marker shipped with a fully valid checksum and the server would have accepted its payload as real
// stream data. Found by the sum-mode test flaking with ~50 % frequency (the SNI random bytes decide the parity).
func damageChecksum(pkt []byte) {
	at := ipHdrLen(pkt) + 16 // the TCP checksum field, after a 20 B IPv4 or 40 B IPv6 header
	s := binary.BigEndian.Uint16(pkt[at:])
	d := s - 1
	if d == 0xffff {
		d = s - 2
	}
	binary.BigEndian.PutUint16(pkt[at:], d)
}

// staleTimestampOpts returns the observed TCP options with the timestamp (RFC 7323, kind 8) moved 2^30 into the past:
// older than the server's TS.recent, so Linux discards a data segment carrying it (PAWS) and sends a dup-ACK. ok is
// false when the connection has no timestamp option, where no such option can be made up.
func staleTimestampOpts(opts []byte) (out []byte, ok bool) {
	out = append([]byte(nil), opts...)
	for i := 0; i < len(out); {
		switch out[i] {
		case 0: // EOL
			return opts, false
		case 1: // NOP
			i++
			continue
		}
		if i+1 >= len(out) {
			break
		}
		l := int(out[i+1])
		if l < 2 || i+l > len(out) {
			break
		}
		if out[i] == 8 && l == 10 {
			binary.BigEndian.PutUint32(out[i+2:i+6], binary.BigEndian.Uint32(out[i+2:i+6])-1<<30)
			return out, true
		}
		i += l
	}
	return opts, false
}
