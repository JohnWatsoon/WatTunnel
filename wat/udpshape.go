package wat

// F19 phase 2 (3.3.0): wattun-internal UDP wire SHAPES. Same udp carrier (one UDP datagram = one session packet) with
// a fixed, key-derived header in front of every datagram, so a classifier sees the datagram of a protocol it knows.
// Between two wattun 3.3.0 peers they interoperate; they are NOT real VXLAN/Geneve/GUE/FOu/DNSCrypt/NTP/OpenVPN/SRTP
// and do not pretend to be (no inner packets are produced or parsed, and a real peer of that protocol would not talk
// to this). Both ends must run 3.3.0 with the same carrier name and the same key; a datagram whose magic does not
// match is dropped, so foreign traffic only costs a strip attempt.
//
//	name           UDP port  header
//	fou-gre        5555      8 B  GRE header with key + protocol 0x0800
//	gue-ipip       6080      8 B  GUE-like header (v1, proto 0x0800) + 4-byte key
//	vxlan          4789      8 B  VXLAN header with I flag + 24-bit VNI
//	geneve         6081      8 B  Geneve base header (proto 0x6558) + 24-bit VNI
//	dnscrypt-udp   443       11 B key magic + version + length, then zero padding to a multiple of 64 (>= 256 B total)
//	ntp-direct     123       48 B NTPv4 header (mode 3 from the client, 4 from the server) + key reference id
//	openvpn-dco    1194      4 B  OpenVPN P_DATA_V2-like opcode/keyid + 3-byte peer id
//	srtp-direct    5004      12 B RTP header (V2, PT 96, sequence + timestamp, key-derived SSRC)
//
// The wrapper types (ShapedUDPClient/ShapedUDPServer) live in udpshape_carrier.go; this file holds the codecs so their
// build/parse tests run on every platform. The ports are the conventional ones for each protocol and are a default for
// -peer/-listen (an explicit port in the address wins).

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"sync/atomic"
)

const udpShapeMTU = 1400 // the udp carrier's datagram ceiling; each shape's header comes out of it

// udpShapeDomain is the key-derivation domain of the UDP shapes. H7: it must contain the module path exactly
// (github.com/JohnWatsoon/WatTunnel); a typo here is a per-PSK wire constant that cannot be fixed after a release
// without breaking every deployed peer.
const udpShapeDomain = "github.com/JohnWatsoon/WatTunnel/udpshape:v1:"

const dnscryptMin = 256 // DNSCrypt pads every message to a multiple of 64 and the minimum is 256 bytes

type udpShape struct {
	name string
	port int
	hdr  int // fixed header bytes (max, including a short length varint)
	pad  int // extra MTU allowance for padding the header may add after the payload
}

// udpShapeTable is the shipped set; the index is stable within a process only, identity is by name.
var udpShapeTable = []udpShape{
	{name: "fou-gre", port: 5555, hdr: 8},
	{name: "gue-ipip", port: 6080, hdr: 8},
	{name: "vxlan", port: 4789, hdr: 8},
	{name: "geneve", port: 6081, hdr: 8},
	{name: "dnscrypt-udp", port: 443, hdr: 11, pad: 63},
	{name: "ntp-direct", port: 123, hdr: 48},
	{name: "openvpn-dco", port: 1194, hdr: 4},
	{name: "srtp-direct", port: 5004, hdr: 12},
}

func udpShapeByName(name string) (*udpShape, bool) {
	for i := range udpShapeTable {
		if udpShapeTable[i].name == name {
			return &udpShapeTable[i], true
		}
	}
	return nil, false
}

// UDPShapePort returns the conventional UDP port of one phase-2 shaped carrier, or 0 for an unknown name.
func UDPShapePort(name string) int {
	if sh, ok := udpShapeByName(name); ok {
		return sh.port
	}
	return 0
}

// mtu is the largest session datagram this shape can carry inside one 1400 B UDP datagram.
func (sh *udpShape) mtu() int { return udpShapeMTU - sh.hdr - sh.pad }

// udpShaper is one connection's shaping state: the key-derived magic fields and the per-shape sequence counters. It is
// safe for concurrent use (the client's Send and every server session's SendTo may race on one RawIO).
type udpShaper struct {
	shape  *udpShape
	server bool
	magic  [16]byte
	aux    uint32 // VNI / peer-id / SSRC / GRE key, a slice of magic
	seq    atomic.Uint32
}

// newUDPShaper derives this connection's shape state from the PSK.
func newUDPShaper(name string, key []byte, server bool) (*udpShaper, bool) {
	sh, ok := udpShapeByName(name)
	if !ok {
		return nil, false
	}
	h := sha256.Sum256(append(append([]byte(udpShapeDomain), name...), key...))
	s := &udpShaper{shape: sh, server: server}
	copy(s.magic[:], h[:])
	s.aux = binary.BigEndian.Uint32(h[16:])
	if s.aux == 0 {
		s.aux = 0x01020304
	}
	return s, true
}

// frame returns the on-wire datagram for one sealed session packet: the shape header then payload (plus padding where
// the shape calls for it).
func (s *udpShaper) frame(out, payload []byte) []byte {
	switch s.shape.name {
	case "fou-gre":
		// GRE flags: key present (0x2000), protocol 0x0800 (IPv4), then the key.
		out = append(out, 0x20, 0x00, 0x08, 0x00)
		out = binary.BigEndian.AppendUint32(out, s.aux)
		return append(out, payload...)
	case "gue-ipip":
		out = append(out, 0x40, 0x00, 0x08, 0x00) // version 1, no flags, protocol IPv4
		out = binary.BigEndian.AppendUint32(out, s.aux)
		return append(out, payload...)
	case "vxlan":
		out = append(out, 0x08, 0, 0, 0) // I flag, 3 reserved
		out = append(out, byte(s.aux>>16), byte(s.aux>>8), byte(s.aux), 0)
		return append(out, payload...)
	case "geneve":
		out = append(out, 0x00, 0x00, 0x65, 0x58) // version 0, no options, protocol 0x6558 (transparent Ethernet)
		out = append(out, byte(s.aux>>16), byte(s.aux>>8), byte(s.aux), 0)
		return append(out, payload...)
	case "dnscrypt-udp":
		out = append(out, s.magic[:8]...)
		out = append(out, 1) // version
		out = binary.AppendUvarint(out, uint64(len(payload)))
		out = append(out, payload...)
		for len(out)%64 != 0 { // DNSCrypt messages are multiples of 64 bytes
			out = append(out, 0)
		}
		for len(out) < dnscryptMin {
			out = append(out, make([]byte, 64)...)
		}
		return out
	case "ntp-direct":
		mode := byte(0x23) // LI 0, version 4, mode 3 (client)
		if s.server {
			mode = 0x24 // mode 4 (server)
		}
		out = append(out, mode, 0, 6, 0xfa)       // stratum 0, poll 6, precision -6
		out = append(out, 0, 0, 0, 0)             // root delay
		out = append(out, 0, 0, 0, 0)             // root dispersion
		out = append(out, s.magic[8:12]...)       // reference id
		out = append(out, s.magic[12:16]...)      // reference timestamp, upper half
		out = append(out, 0, 0, 0, 0)             // reference timestamp, lower half
		out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // originate timestamp
		out = append(out, 0, 0, 0, 0, 0, 0, 0, 0) // receive timestamp
		// transmit timestamp: the sequence as whole seconds plus a random fraction, so the header changes per packet
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(s.seq.Add(1))<<32|uint64(rand.Uint32()))
		out = append(out, ts[:]...)
		return append(out, payload...)
	case "openvpn-dco":
		out = append(out, 0x48) // OpenVPN P_DATA_V2 opcode, key id 0
		out = append(out, byte(s.aux>>16), byte(s.aux>>8), byte(s.aux))
		return append(out, payload...)
	case "srtp-direct":
		seq := uint16(s.seq.Add(1))
		out = append(out, 0x80, 0x60) // RTP version 2, no extensions, payload type 96
		out = binary.BigEndian.AppendUint16(out, seq)
		out = binary.BigEndian.AppendUint32(out, uint32(seq)*160) // 20 ms at 8 kHz
		out = binary.BigEndian.AppendUint32(out, s.aux)           // SSRC
		return append(out, payload...)
	}
	return out
}

// strip validates one received datagram against this shape and key and returns the sealed session packet, or nil when
// it is not ours (wrong shape, wrong key, truncated, padded wrong).
func (s *udpShaper) strip(b []byte) []byte {
	hdr := s.shape.hdr
	if len(b) < hdr {
		return nil
	}
	switch s.shape.name {
	case "fou-gre":
		if b[0] != 0x20 || b[1] != 0x00 || b[2] != 0x08 || b[3] != 0x00 || binary.BigEndian.Uint32(b[4:8]) != s.aux {
			return nil
		}
	case "gue-ipip":
		if b[0] != 0x40 || b[1] != 0x00 || b[2] != 0x08 || b[3] != 0x00 || binary.BigEndian.Uint32(b[4:8]) != s.aux {
			return nil
		}
	case "vxlan":
		if b[0] != 0x08 || (uint32(b[4])<<16|uint32(b[5])<<8|uint32(b[6])) != s.aux&0xffffff {
			return nil
		}
	case "geneve":
		if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x65 || b[3] != 0x58 ||
			(uint32(b[4])<<16|uint32(b[5])<<8|uint32(b[6])) != s.aux&0xffffff {
			return nil
		}
	case "dnscrypt-udp":
		if string(b[:8]) != string(s.magic[:8]) || b[8] != 1 || len(b)%64 != 0 || len(b) < dnscryptMin {
			return nil
		}
		plen, n := binary.Uvarint(b[9:])
		if n <= 0 || plen > uint64(len(b)-9-n) {
			return nil
		}
		off := 9 + n
		return b[off : off+int(plen)]
	case "ntp-direct":
		mode := b[0] & 0x07
		if b[0]>>3&0x07 != 4 || (mode != 3 && mode != 4) || string(b[12:16]) != string(s.magic[8:12]) {
			return nil
		}
	case "openvpn-dco":
		if b[0] != 0x48 || (uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) != s.aux&0xffffff {
			return nil
		}
	case "srtp-direct":
		if b[0] != 0x80 || b[1] != 0x60 || binary.BigEndian.Uint32(b[8:12]) != s.aux {
			return nil
		}
	}
	return b[hdr:]
}
