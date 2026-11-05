package wat

// F19 phase-1 shaped raw carriers (3.3.0): the header codecs are portable, so their build/parse tests run on every
// platform. They also pin the H9/M15 direction isolation: a client only accepts server -> client frames and the
// server only client -> server ones. The real raw-socket loopback test is rawshape_linux_test.go (CI/root only).

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
)

func TestRawShapeTable(t *testing.T) {
	cases := []struct {
		name  string
		proto int
		hdr   int
		mtu   int
	}{
		{"sit", 41, 40, 1360},
		{"6to4", 41, 40, 1360},
		{"xfrm-ipsec", 50, 8, 1392},
		{"etherip", 97, 16, 1384},
		{"l2tpv3", 115, 4, 1396},
	}
	for _, c := range cases {
		s, ok := rawShapeByName(c.name)
		if !ok {
			t.Fatalf("%s: not a raw shape", c.name)
		}
		if got := rawShapeSpecs[s]; got.proto != c.proto || got.hdr != c.hdr {
			t.Errorf("%s: spec %+v, want proto %d hdr %d", c.name, got, c.proto, c.hdr)
		}
		if got := rawShapeMTU(s); got != c.mtu { // M1/M15: the payload ceiling the session clamp uses
			t.Errorf("%s: rawShapeMTU = %d, want %d", c.name, got, c.mtu)
		}
	}
	if _, ok := rawShapeByName("udp"); ok {
		t.Error("udp must not be a raw shape")
	}
	// cmd/wattun builds its carrier maps from this list, so it must be exactly the table (audit L6/F15).
	if got := RawShapedCarrierNames(); !slices.Equal(got, rawShapeNames[:]) {
		t.Errorf("RawShapedCarrierNames() = %v, want %v", got, rawShapeNames)
	}
}

// TestRawShapeKeyPerShape: audit L14/F27 (2026-11-04). The shape name is part of the derivation, so one PSK yields
// independent header fields per shape. Before the fix xfrm-ipsec, etherip and l2tpv3 derived the exact same struct
// from one hash (and sit/6to4 exposed that hash's bytes in their inner IPv6 header, which a middlebox can read).
func TestRawShapeKeyPerShape(t *testing.T) {
	key := []byte("one-psk")
	seen := map[rawShapeKey]rawShape{}
	for s := range rawShapeNames {
		k := newRawShapeKey(rawShape(s), key)
		if prev, dup := seen[k]; dup {
			t.Fatalf("%s and %s derive identical keyed header fields from one PSK", rawShapeNames[prev], rawShapeNames[s])
		}
		seen[k] = rawShape(s)
	}
}

// TestRawShapeCodec runs frames through build+strip per shape in both roles: the receiver's role accepts the frame it
// is addressed to and rejects the one its own end would send (H9), plus wrong keys, truncation and the sibling shape.
func TestRawShapeCodec(t *testing.T) {
	key := []byte("raw-shape-test-key")
	payload := []byte("sealed session datagram")
	for _, name := range rawShapeNames {
		s, ok := rawShapeByName(name)
		if !ok {
			t.Fatal(name)
		}
		k := newRawShapeKey(s, key)
		for seq := uint32(1); seq <= 2; seq++ {
			// client -> server: built as the client, accepted only by the server role
			up := rawShapeFrame(s, k, false, seq, nil, payload)
			if want := rawShapeSpecs[s].hdr + len(payload); len(up) != want {
				t.Fatalf("%s: frame %d bytes, want %d", name, len(up), want)
			}
			if got := rawShapeStrip(s, k, true, up); !bytes.Equal(got, payload) {
				t.Fatalf("%s seq %d: server strip %q, want %q", name, seq, got, payload)
			}
			if rawShapeStrip(s, k, false, up) != nil {
				t.Fatalf("%s seq %d: the client accepted a client->server frame (its own looped frame, H9)", name, seq)
			}
			// server -> client: only the client role accepts it
			down := rawShapeFrame(s, k, true, seq, nil, payload)
			if got := rawShapeStrip(s, k, false, down); !bytes.Equal(got, payload) {
				t.Fatalf("%s seq %d: client strip %q, want %q", name, seq, got, payload)
			}
			if rawShapeStrip(s, k, true, down) != nil {
				t.Fatalf("%s seq %d: the server accepted a server->client frame", name, seq)
			}
			// a wrong key (another PSK) must not parse
			if other := newRawShapeKey(s, []byte("another-key")); rawShapeStrip(s, other, true, up) != nil {
				t.Fatalf("%s: wrong key accepted", name)
			}
			// truncated below the fixed header must not parse
			if rawShapeStrip(s, k, true, up[:rawShapeSpecs[s].hdr-1]) != nil {
				t.Fatalf("%s: truncated frame accepted", name)
			}
		}
	}
	// sit and 6to4 share IP protocol 41 but must not accept each other's frames
	sit := rawShapeFrame(rawShapeSIT, newRawShapeKey(rawShapeSIT, key), false, 1, nil, payload)
	six := rawShapeFrame(rawShape6to4, newRawShapeKey(rawShape6to4, key), false, 1, nil, payload)
	if rawShapeStrip(rawShapeSIT, newRawShapeKey(rawShapeSIT, key), true, six) != nil {
		t.Error("sit accepted a 6to4 frame")
	}
	if rawShapeStrip(rawShape6to4, newRawShapeKey(rawShape6to4, key), true, sit) != nil {
		t.Error("6to4 accepted a sit frame")
	}
}

// TestRawShapeHeaders pins the fields a classifier looks at and the per-role keyed values: the IPv6 addresses swap with
// the sender, the ESP SPI and L2TPv3 session id name the receiver, and the EtherIP MACs name both NICs.
func TestRawShapeHeaders(t *testing.T) {
	key := []byte("raw-shape-headers")
	payload := []byte("abc")
	up := func(s rawShape, seq uint32) []byte {
		return rawShapeFrame(s, newRawShapeKey(s, key), false, seq, nil, payload)
	}
	sitK := newRawShapeKey(rawShapeSIT, key)
	sit := up(rawShapeSIT, 1)
	if sit[0]>>4 != 6 || sit[0]&0x0f != 0 || binary.BigEndian.Uint16(sit[4:6]) != uint16(len(payload)) {
		t.Fatalf("sit ipv6 header: %x", sit[:8])
	}
	if !bytes.Equal(sit[8:24], sitK.v6[0][:]) || !bytes.Equal(sit[24:40], sitK.v6[1][:]) || sit[24] != 0xfd {
		t.Fatalf("sit client frame must go from the client's ULA to the server's: %x", sit[8:40])
	}
	downSit := rawShapeFrame(rawShapeSIT, sitK, true, 1, nil, payload)
	if !bytes.Equal(downSit[8:24], sitK.v6[1][:]) || !bytes.Equal(downSit[24:40], sitK.v6[0][:]) {
		t.Fatalf("sit server frame direction: %x", downSit[8:40])
	}
	six := up(rawShape6to4, 1)
	if six[24] != 0x20 || six[25] != 0x02 {
		t.Fatalf("6to4 destination %x is not 2002::/16", six[24:40])
	}
	espK := newRawShapeKey(rawShapeESP, key)
	esp := rawShapeFrame(rawShapeESP, espK, false, 7, nil, payload)
	if binary.BigEndian.Uint32(esp) != espK.spi[1] || binary.BigEndian.Uint32(esp[4:8]) != 7 {
		t.Fatalf("esp client header %x, want the server's SPI %#x: wire check", esp[:8], espK.spi[1])
	}
	espDown := rawShapeFrame(rawShapeESP, espK, true, 7, nil, payload)
	if binary.BigEndian.Uint32(espDown) != espK.spi[0] {
		t.Fatalf("esp server header %x, want the client's SPI %#x", espDown[:4], espK.spi[0])
	}
	ethK := newRawShapeKey(rawShapeEtherIP, key)
	eth := up(rawShapeEtherIP, 1)
	if eth[0]>>4 != 3 || binary.BigEndian.Uint16(eth[14:16]) != 0x0800 ||
		!bytes.Equal(eth[2:8], ethK.mac[6:12]) || !bytes.Equal(eth[8:14], ethK.mac[0:6]) {
		t.Fatalf("etherip client header: %x", eth[:16])
	}
	l2K := newRawShapeKey(rawShapeL2TPv3, key)
	l2 := up(rawShapeL2TPv3, 1)
	if binary.BigEndian.Uint32(l2) != l2K.sid[1] {
		t.Fatalf("l2tpv3 client header %x, want the server's session id %#x", l2[:4], l2K.sid[1])
	}
}

// TestRawShapeFilter: each role's filter must carry that role's own keyed value and not the peer's, so a filter
// installed for one end cannot accept frames addressed to the other; and every program must be valid classic-BPF
// (bpf.Assemble works on the kernel's instruction set). Kernel attachment/behaviour: rawshape_linux_test.go (CI/root).
func TestRawShapeFilter(t *testing.T) {
	key := []byte("raw-shape-filter")
	for _, name := range rawShapeNames {
		s, _ := rawShapeByName(name)
		k := newRawShapeKey(s, key)
		clientFilter, serverFilter := rawShapeFilter(s, k, false), rawShapeFilter(s, k, true)
		if _, err := bpf.Assemble(clientFilter); err != nil {
			t.Fatalf("%s: client filter does not assemble: %v", name, err)
		}
		if _, err := bpf.Assemble(serverFilter); err != nil {
			t.Fatalf("%s: server filter does not assemble: %v", name, err)
		}
		clientVals, serverVals := bpfJumpVals(clientFilter), bpfJumpVals(serverFilter)
		own, peer := roleWord(s, k, 0), roleWord(s, k, 1)
		if !slices.Contains(clientVals, own) || slices.Contains(clientVals, peer) {
			t.Fatalf("%s: client filter values %x, want the client's %#x and not the server's %#x", name, clientVals, own, peer)
		}
		if !slices.Contains(serverVals, peer) || slices.Contains(serverVals, own) {
			t.Fatalf("%s: server filter values %x, want the server's %#x and not the client's %#x", name, serverVals, peer, own)
		}
	}
}

// roleWord is the 4-byte keyed value that only role me puts in (or looks for in) a frame of shape s.
func roleWord(s rawShape, k rawShapeKey, me int) uint32 {
	switch s {
	case rawShapeSIT, rawShape6to4:
		return binary.BigEndian.Uint32(k.v6[me][0:4])
	case rawShapeESP:
		return k.spi[me]
	case rawShapeEtherIP:
		return binary.BigEndian.Uint32(k.mac[6*me : 6*me+4])
	default: // rawShapeL2TPv3
		return k.sid[me]
	}
}

// bpfJumpVals returns every constant the program compares against.
func bpfJumpVals(prog []bpf.Instruction) []uint32 {
	var out []uint32
	for _, ins := range prog {
		if j, ok := ins.(bpf.JumpIf); ok {
			out = append(out, j.Val)
		}
	}
	return out
}
