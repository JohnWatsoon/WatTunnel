package wat

// F19 phase 1 (3.3.0): wattun-internal raw-tier wire SHAPES. Each one is a raw-IP carrier (Linux + CAP_NET_RAW, like
// icmp/gre/ipip) whose datagram on the wire carries an outer header that a classifier recognises as a known tunnelling
// protocol. Between two wattun 3.3.0 peers they interoperate; with a real implementation of that protocol they do
// NOT, and wattun does not pretend to: the header is a fixed, key-derived shape and the sealed session datagram rides
// after it. Both ends must run 3.3.0 and select the same carrier name (an older peer rejects the name at startup).
//
//	sit          IP protocol 41, inner 40-byte IPv6 header with ULA fc00::/7 addresses (6in4-like)
//	6to4         IP protocol 41, inner IPv6 header with the 2002:V4ADDR::/48 prefix
//	xfrm-ipsec   IP protocol 50 (ESP): 8-byte header (key-derived SPI + sequence counter)
//	etherip      IP protocol 97 (EtherIP): 2-byte EtherIP header + 14-byte Ethernet header
//	l2tpv3       IP protocol 115: 4-byte L2TPv3 session header (key-derived session id)
//
// Direction isolation (H9/M15): every header carries role-specific keyed fields, and the frame is built with the
// sender's role. The client only accepts a frame addressed to it (server → client) and the server only one addressed
// to it, so a host that also receives its own locally looped proto-41/50/97/115 datagram cannot feed the session its
// own frame (a raw socket sees a copy of what it sent over loopback). The Linux constructor additionally installs a
// classic-BPF filter built from those same keyed fields, so foreign packets of the same protocol number are dropped in
// the kernel instead of costing a strip attempt (M15).
//
// The Linux I/O lives in rawshape_linux.go; other platforms refuse these carriers (raw sockets need Linux). The
// header codecs live here so their build/parse tests run on every platform.

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/net/bpf"
)

// rawShapeDomain is the key-derivation domain of the raw-tier shapes. H7: it must contain the module path exactly
// (github.com/JohnWatsoon/WatTunnel); a typo here is a per-PSK wire constant that cannot be fixed after a release
// without breaking every deployed peer.
const rawShapeDomain = "github.com/JohnWatsoon/WatTunnel/rawshape:v1:"

// rawShape identifies one shaped raw-IP carrier.
type rawShape uint8

const (
	rawShapeSIT rawShape = iota
	rawShape6to4
	rawShapeESP
	rawShapeEtherIP
	rawShapeL2TPv3
)

type rawShapeSpec struct {
	proto int // outer IP protocol number
	hdr   int // fixed header bytes this shape puts after the outer IPv4 header
}

var rawShapeSpecs = [5]rawShapeSpec{
	rawShapeSIT:     {proto: 41, hdr: 40},
	rawShape6to4:    {proto: 41, hdr: 40},
	rawShapeESP:     {proto: 50, hdr: 8},
	rawShapeEtherIP: {proto: 97, hdr: 16},
	rawShapeL2TPv3:  {proto: 115, hdr: 4},
}

// rawShapeMTU is the shape's payload ceiling in a 1400-byte wire datagram: 1400 minus the fixed header. The raw
// carriers' Profile and Config.MaxPayload clamp both use it (M1/M15).
func rawShapeMTU(s rawShape) int { return 1400 - rawShapeSpecs[s].hdr }

// rawShapeByName maps a -carrier name to its shape.
func rawShapeByName(name string) (rawShape, bool) {
	switch name {
	case "sit":
		return rawShapeSIT, true
	case "6to4":
		return rawShape6to4, true
	case "xfrm-ipsec":
		return rawShapeESP, true
	case "etherip":
		return rawShapeEtherIP, true
	case "l2tpv3":
		return rawShapeL2TPv3, true
	}
	return 0, false
}

// rawShapeKey is the per-shape header state both ends derive from the PSK; a packet whose keyed fields do not match is
// dropped, so a third party speaking the same protocol number cannot inject into the session. Each field has one value
// per role and the frame is built for the receiver's value, which is what makes the direction check possible.
type rawShapeKey struct {
	spi [2]uint32   // xfrm-ipsec: [0] the client's, [1] the server's
	mac [12]byte    // etherip: [0:6] the client's NIC, [6:12] the server's
	sid [2]uint32   // l2tpv3: [0] the client's session id, [1] the server's
	v6  [2][16]byte // sit/6to4: [0] the client's inner address, [1] the server's
}

// me indexes the role's own values; the peer is 1-me.
func (k rawShapeKey) me(server bool) int {
	if server {
		return 1
	}
	return 0
}

// newRawShapeKey derives the fixed header fields from the PSK (domain-separated from every other wat key use).
func newRawShapeKey(s rawShape, key []byte) rawShapeKey {
	h := sha256.Sum256(append([]byte(rawShapeDomain), key...))
	extra := sha256.Sum256(h[:]) // a second block for the peer role's fields
	var k rawShapeKey
	k.spi[0] = binary.BigEndian.Uint32(h[0:])
	if k.spi[0] == 0 {
		k.spi[0] = 1
	}
	k.spi[1] = binary.BigEndian.Uint32(extra[0:])
	if k.spi[1] == 0 {
		k.spi[1] = 2
	}
	if k.spi[1] == k.spi[0] {
		k.spi[1] ^= 1
	}
	k.sid[0] = binary.BigEndian.Uint32(h[4:])
	if k.sid[0] == 0 {
		k.sid[0] = 0x1000
	}
	k.sid[1] = binary.BigEndian.Uint32(extra[4:])
	if k.sid[1] == 0 {
		k.sid[1] = 0x2000
	}
	if k.sid[1] == k.sid[0] {
		k.sid[1] ^= 1
	}
	copy(k.mac[:6], h[8:14])
	copy(k.mac[6:], h[14:20])
	for i := 0; i < 12; i++ {
		if i%6 == 0 { // locally administered, unicast: looks like an ordinary virtual NIC
			k.mac[i] = (k.mac[i] &^ 0x01) | 0x02
		}
	}
	if s == rawShapeSIT {
		k.v6[0][0], k.v6[1][0] = 0xfd, 0xfd // ULA fc00::/7
		copy(k.v6[0][1:], h[0:15])
		copy(k.v6[1][1:], h[15:30])
	} else if s == rawShape6to4 {
		// 2002:V4ADDR::/48: the prefix carries an IPv4 address
		k.v6[0][0], k.v6[0][1] = 0x20, 0x02
		k.v6[1][0], k.v6[1][1] = 0x20, 0x02
		copy(k.v6[0][2:6], h[20:24])
		copy(k.v6[1][2:6], h[24:28])
	}
	// the two ends must not share an inner address
	if k.v6[0] == k.v6[1] {
		k.v6[1][15] ^= 1
	}
	return k
}

// rawShapeFrame appends this shape's outer header for payload and returns the datagram body (what the kernel wraps in
// the outer IPv4 header). server is the sender's role; seq feeds the ESP sequence counter (the other shapes ignore it).
func rawShapeFrame(s rawShape, k rawShapeKey, server bool, seq uint32, dst, payload []byte) []byte {
	me, peer := k.me(server), 1-k.me(server)
	switch s {
	case rawShapeSIT, rawShape6to4:
		dst = appendIPv6Hdr(dst, k.v6[me], k.v6[peer], len(payload))
	case rawShapeESP:
		dst = binary.BigEndian.AppendUint32(dst, k.spi[peer]) // the receiver's SPI, as ESP puts it
		dst = binary.BigEndian.AppendUint32(dst, seq)
	case rawShapeEtherIP:
		dst = append(dst, 0x30, 0x00) // version 3, reserved
		dst = append(dst, k.mac[6*peer:6*peer+6]...)
		dst = append(dst, k.mac[6*me:6*me+6]...)
		dst = append(dst, 0x08, 0x00) // EtherType: IPv4, what EtherIP usually carries
	case rawShapeL2TPv3:
		dst = binary.BigEndian.AppendUint32(dst, k.sid[peer]) // the receiver's session id, as L2TPv3 puts it
	}
	return append(dst, payload...)
}

// appendIPv6Hdr appends the 40-byte inner IPv6 header of sit/6to4: version 6, the payload length, next header 253
// (experimental, i.e. an opaque tunnel payload) and hop limit 64.
func appendIPv6Hdr(dst []byte, src, dstIP [16]byte, plen int) []byte {
	dst = append(dst, 0x60, 0, 0, 0)
	dst = binary.BigEndian.AppendUint16(dst, uint16(plen))
	dst = append(dst, 253, 64)
	dst = append(dst, src[:]...)
	return append(dst, dstIP[:]...)
}

// rawShapeStrip validates a received datagram body (after the outer IPv4 header) against this shape, key and the
// receiver's role, and returns the sealed session datagram, or nil when it is not this shape/key or it goes the wrong
// way (H9: a client only accepts server → client frames, and vice versa).
func rawShapeStrip(s rawShape, k rawShapeKey, server bool, b []byte) []byte {
	spec := rawShapeSpecs[s]
	if len(b) < spec.hdr {
		return nil
	}
	me, peer := k.me(server), 1-k.me(server)
	switch s {
	case rawShapeSIT, rawShape6to4:
		if b[0]>>4 != 6 || int(binary.BigEndian.Uint16(b[4:6])) != len(b)-40 {
			return nil
		}
		if b[6] != 253 || b[7] != 64 {
			return nil
		}
		var ip [16]byte
		copy(ip[:], b[24:40]) // the destination must be this end
		// sit is ULA, 6to4 carries the 2002::/16 prefix: a sit receiver must not accept a 6to4 frame and vice versa
		if s == rawShapeSIT && ip[0] != 0xfd || s == rawShape6to4 && (ip[0] != 0x20 || ip[1] != 0x02) {
			return nil
		}
		if ip != k.v6[me] {
			return nil
		}
		var src [16]byte
		copy(src[:], b[8:24]) // and the source must be the peer
		if src != k.v6[peer] {
			return nil
		}
	case rawShapeESP:
		if binary.BigEndian.Uint32(b) != k.spi[me] {
			return nil
		}
	case rawShapeEtherIP:
		if b[0]>>4 != 3 || binary.BigEndian.Uint16(b[14:16]) != 0x0800 {
			return nil
		}
		if string(b[2:8]) != string(k.mac[6*me:6*me+6]) || string(b[8:14]) != string(k.mac[6*peer:6*peer+6]) {
			return nil
		}
	case rawShapeL2TPv3:
		if binary.BigEndian.Uint32(b) != k.sid[me] {
			return nil
		}
	}
	return b[spec.hdr:]
}

// rawShapeFilter is the classic-BPF program NewShapedRaw installs on its raw socket (M15): accept only packets of this
// shape's protocol whose keyed field addresses this receiver, so foreign traffic of the same protocol number never
// reaches the Go loop. It mirrors rawIPFilter/icmp_linux.go's filter shape (load the outer IP header length into X,
// then match keyed words in the body). The userspace strip repeats every check, so a filter bug can only cost work,
// never admit a foreign frame.
func rawShapeFilter(s rawShape, k rawShapeKey, server bool) []bpf.Instruction {
	me := k.me(server)
	switch s {
	case rawShapeSIT, rawShape6to4:
		a := k.v6[me]
		return bpfMatchWords([][2]uint32{ // the inner IPv6 destination, 4 words
			{24, binary.BigEndian.Uint32(a[0:4])},
			{28, binary.BigEndian.Uint32(a[4:8])},
			{32, binary.BigEndian.Uint32(a[8:12])},
			{36, binary.BigEndian.Uint32(a[12:16])},
		})
	case rawShapeESP:
		return bpfMatchWords([][2]uint32{{0, k.spi[me]}})
	case rawShapeEtherIP:
		return bpfMatchWords([][2]uint32{{2, binary.BigEndian.Uint32(k.mac[6*me : 6*me+4])}})
	case rawShapeL2TPv3:
		return bpfMatchWords([][2]uint32{{0, k.sid[me]}})
	}
	return nil
}

// bpfMatchWords builds "accept iff, for every (offset, value), the 4-byte word at that body offset equals value"; the
// offsets are relative to the outer IP header's end (X is set by LoadMemShift).
func bpfMatchWords(words [][2]uint32) []bpf.Instruction {
	prog := make([]bpf.Instruction, 0, 1+2*len(words)+2)
	prog = append(prog, bpf.LoadMemShift{Off: 0})
	first := len(prog)
	for _, w := range words {
		prog = append(prog, bpf.LoadIndirect{Off: w[0], Size: 4}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: w[1]})
	}
	n := len(prog)
	for i := first + 1; i < n; i += 2 { // patch every reject jump to land on the final RetConstant{0}
		j := prog[i].(bpf.JumpIf)
		j.SkipFalse = uint8(n - i)
		prog[i] = j
	}
	return append(prog, bpf.RetConstant{Val: 0xffff}, bpf.RetConstant{Val: 0})
}
