package wat

// F19 phase-2 shaped UDP carriers (3.3.0): header codec build/parse tests. These run on every platform; the loopback
// end-to-end row per shape is udpshape_loopback_test.go.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestUDPShapeTable(t *testing.T) {
	want := map[string]int{
		"fou-gre": 5555, "gue-ipip": 6080, "vxlan": 4789, "geneve": 6081,
		"dnscrypt-udp": 443, "ntp-direct": 123, "openvpn-dco": 1194, "srtp-direct": 5004,
	}
	// M1/M15: the payload ceiling the engine clamps an explicit -mtu to (1400 - header - padding allowance).
	wantMTU := map[string]int{
		"fou-gre": 1392, "gue-ipip": 1392, "vxlan": 1392, "geneve": 1392,
		"dnscrypt-udp": 1326, "ntp-direct": 1352, "openvpn-dco": 1396, "srtp-direct": 1388,
	}
	if len(udpShapeTable) != len(want) {
		t.Fatalf("%d shapes, want %d", len(udpShapeTable), len(want))
	}
	for _, sh := range udpShapeTable {
		if want[sh.name] != sh.port || UDPShapePort(sh.name) != want[sh.name] {
			t.Errorf("%s: port %d/%d, want %d", sh.name, sh.port, UDPShapePort(sh.name), want[sh.name])
		}
		if got, want := sh.mtu(), udpShapeMTU-sh.hdr-sh.pad; got != want {
			t.Errorf("%s: mtu %d, want %d", sh.name, got, want)
		}
		if sh.mtu() != wantMTU[sh.name] {
			t.Errorf("%s: mtu %d, want the ceiling %d", sh.name, sh.mtu(), wantMTU[sh.name])
		}
		if sh.mtu() <= 0 {
			t.Errorf("%s: nonpositive mtu", sh.name)
		}
	}
	if UDPShapePort("udp") != 0 {
		t.Error("udp must not be a shaped carrier")
	}
	// cmd/wattun builds its carrier maps from this list, so it must be exactly the table (audit L6/F15).
	names := UDPShapedCarrierNames()
	if len(names) != len(udpShapeTable) {
		t.Fatalf("%d exported names, want %d", len(names), len(udpShapeTable))
	}
	for i, sh := range udpShapeTable {
		if names[i] != sh.name {
			t.Errorf("UDPShapedCarrierNames()[%d] = %q, want %q", i, names[i], sh.name)
		}
	}
	if _, ok := newUDPShaper("nope", []byte("k"), false); ok {
		t.Error("unknown shape accepted")
	}
}

// TestUDPShapeCodec checks each shape's frame/strip round trip, the MTU bound and the "wrong magic = drop" rule.
func TestUDPShapeCodec(t *testing.T) {
	key := []byte("udp-shape-test-key")
	for _, sh := range udpShapeTable {
		sh := sh
		t.Run(sh.name, func(t *testing.T) {
			client, ok := newUDPShaper(sh.name, key, false)
			if !ok {
				t.Fatal("shaper")
			}
			server, _ := newUDPShaper(sh.name, key, true)
			for _, size := range []int{1, 200, sh.mtu()} {
				payload := bytes.Repeat([]byte{0xA5}, size)
				f := client.frame(nil, payload)
				if len(f) > udpShapeMTU {
					t.Fatalf("%d B payload: frame %d B > %d MTU", size, len(f), udpShapeMTU)
				}
				if got := server.strip(f); !bytes.Equal(got, payload) {
					t.Fatalf("%d B payload: server strip %d B", size, len(got))
				}
				// the other direction (server -> client) must parse too
				g := server.frame(nil, payload)
				if got := client.strip(g); !bytes.Equal(got, payload) {
					t.Fatalf("%d B payload: client strip %d B", size, len(got))
				}
			}
			f := client.frame(nil, []byte("hello"))
			// another PSK must not parse
			if other, _ := newUDPShaper(sh.name, []byte("another-key"), false); other.strip(f) != nil {
				t.Fatal("wrong key accepted")
			}
			// a foreign datagram (zeros of header length) must not parse
			if server.strip(make([]byte, sh.hdr)) != nil {
				t.Fatal("zero header accepted")
			}
			// a truncated datagram must not parse
			if server.strip(f[:sh.hdr-1]) != nil {
				t.Fatal("truncated header accepted")
			}
			// flipping the first byte (the magic/cookie of every shape) must drop it
			bad := append([]byte(nil), f...)
			bad[0] ^= 0xff
			if server.strip(bad) != nil {
				t.Fatal("corrupted magic accepted")
			}
		})
	}
}

// TestUDPShapeFields pins the fields a protocol classifier looks at for each shape.
func TestUDPShapeFields(t *testing.T) {
	key := []byte("udp-shape-fields")
	payload := []byte("payload")
	frame := func(name string, server bool) ([]byte, *udpShaper) {
		sh, ok := newUDPShaper(name, key, server)
		if !ok {
			t.Fatal(name)
		}
		return sh.frame(nil, payload), sh
	}
	if f, sh := frame("fou-gre", false); f[0] != 0x20 || f[1] != 0 || f[2] != 0x08 || f[3] != 0x00 ||
		binary.BigEndian.Uint32(f[4:8]) != sh.aux {
		t.Errorf("fou-gre header %x", f[:8])
	}
	if f, sh := frame("gue-ipip", false); f[0] != 0x40 || f[2] != 0x08 || f[3] != 0x00 ||
		binary.BigEndian.Uint32(f[4:8]) != sh.aux {
		t.Errorf("gue-ipip header %x", f[:8])
	}
	if f, sh := frame("vxlan", false); f[0] != 0x08 || (uint32(f[4])<<16|uint32(f[5])<<8|uint32(f[6])) != sh.aux&0xffffff {
		t.Errorf("vxlan header %x", f[:8])
	}
	if f, sh := frame("geneve", false); f[0] != 0x00 || f[2] != 0x65 || f[3] != 0x58 ||
		(uint32(f[4])<<16|uint32(f[5])<<8|uint32(f[6])) != sh.aux&0xffffff {
		t.Errorf("geneve header %x", f[:8])
	}
	if f, _ := frame("dnscrypt-udp", false); len(f)%64 != 0 || len(f) < dnscryptMin ||
		!bytes.Equal(f[:8], newRawShaperMagic(t, "dnscrypt-udp", key)) {
		t.Errorf("dnscrypt frame: %d bytes %x", len(f), f[:9])
	}
	if f, _ := frame("ntp-direct", false); f[0] != 0x23 {
		t.Errorf("ntp client mode byte %#x", f[0])
	}
	if f, _ := frame("ntp-direct", true); f[0] != 0x24 {
		t.Errorf("ntp server mode byte %#x", f[0])
	}
	if f, sh := frame("openvpn-dco", false); f[0] != 0x48 ||
		(uint32(f[1])<<16|uint32(f[2])<<8|uint32(f[3])) != sh.aux&0xffffff {
		t.Errorf("openvpn header %x", f[:4])
	}
	if f, sh := frame("srtp-direct", false); f[0] != 0x80 || f[1] != 0x60 ||
		binary.BigEndian.Uint32(f[8:12]) != sh.aux {
		t.Errorf("srtp header %x", f[:12])
	}
}

// newRawShaperMagic returns the 8-byte DNSCrypt-style magic a shaper derives from the key.
func newRawShaperMagic(t *testing.T, name string, key []byte) []byte {
	t.Helper()
	sh, ok := newUDPShaper(name, key, false)
	if !ok {
		t.Fatal(name)
	}
	return sh.magic[:8]
}
