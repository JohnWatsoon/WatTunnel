package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCsum(t *testing.T) {
	if got := csum([]byte{0x08, 0x00, 0x00, 0x00}); got != 0xF7FF {
		t.Errorf("csum(echo header, zero rest) = %#04x, want 0xF7FF", got)
	}
}

func TestPktLayout(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	b := pkt(8, 0xC001, 0x1234, body)
	if len(b) != 8+len(body) {
		t.Fatalf("packet length = %d, want %d", len(b), 8+len(body))
	}
	if b[0] != 8 {
		t.Errorf("type = %d, want 8", b[0])
	}
	if got := binary.BigEndian.Uint16(b[4:]); got != 0xC001 {
		t.Errorf("id = %#04x, want 0xC001", got)
	}
	if got := binary.BigEndian.Uint16(b[6:]); got != 0x1234 {
		t.Errorf("seq = %#04x, want 0x1234", got)
	}
	if !bytes.Equal(b[8:], body) {
		t.Errorf("payload = %x, want %x", b[8:], body)
	}
	if got := csum(b); got != 0 {
		t.Errorf("csum(full packet) = %#04x, want 0 for even length", got)
	}
}

func TestPayloadLayout(t *testing.T) {
	const seq = 0xA1B2C3D4
	p := payload(3, 2, 64, seq)
	if len(p) != 64 {
		t.Fatalf("payload length = %d, want 64", len(p))
	}
	if string(p[:4]) != magic {
		t.Errorf("magic = %q, want %q", p[:4], magic)
	}
	if p[4] != 3 || p[5] != 2 {
		t.Errorf("k, variant = %d, %d, want 3, 2", p[4], p[5])
	}
	if got := int(binary.BigEndian.Uint16(p[6:])); got != 64 {
		t.Errorf("size field = %d, want 64", got)
	}
	if got := binary.BigEndian.Uint32(p[8:]); got != seq {
		t.Errorf("seq = %#08x, want %#08x", got, uint32(seq))
	}
	// a size below the header is clamped to it, and the seq still round-trips
	small := payload(0, 1, 1, seq)
	if len(small) != hdrLen {
		t.Fatalf("small payload length = %d, want hdrLen %d", len(small), hdrLen)
	}
	if got := int(binary.BigEndian.Uint16(small[6:])); got != hdrLen {
		t.Errorf("small size field = %d, want %d", got, hdrLen)
	}
	if got := binary.BigEndian.Uint32(small[8:]); got != seq {
		t.Errorf("small seq = %#08x, want %#08x", got, uint32(seq))
	}
}

func TestClampEchoParams(t *testing.T) {
	k, sz := clampEchoParams(0, 600, 608)
	if k != 1 || sz != 600 {
		t.Fatalf("k=0 case = (%d, %d), want (1, 600)", k, sz)
	}
	k, sz = clampEchoParams(255, 65535, 100)
	if k != maxProbeK || sz != 92 {
		t.Fatalf("amplification clamp = (%d, %d), want (%d, 92)", k, sz, maxProbeK)
	}
	k, sz = clampEchoParams(2, 2000, 2048)
	if k != 2 || sz != maxProbeSize {
		t.Fatalf("MTU clamp = (%d, %d), want (2, %d)", k, sz, maxProbeSize)
	}
}

func TestResolveDstAndParseStep(t *testing.T) {
	if _, err := resolveDst(""); err == nil {
		t.Fatal("empty dst must fail")
	}
	if _, err := resolveDst("not a host!!!"); err == nil {
		t.Fatal("garbage dst must fail")
	}
	if a, err := resolveDst("127.0.0.1"); err != nil || a.IP.String() != "127.0.0.1" {
		t.Fatalf("resolveDst(127.0.0.1) = (%v, %v)", a, err)
	}
	r, s, n, k, v, d, err := parseStep("100:600:4:2:1:5")
	if err != nil || r != 100 || s != 600 || n != 4 || k != 2 || v != 1 || d.Seconds() != 5 {
		t.Fatalf("parseStep valid failed: (%d,%d,%d,%d,%d,%v,%v)", r, s, n, k, v, d, err)
	}
	for _, bad := range []string{"", "0:600:1", "10:600:0", "abc:600:1", "10:600:1:1:0:0"} {
		if _, _, _, _, _, _, err := parseStep(bad); err == nil {
			t.Errorf("parseStep(%q) unexpectedly succeeded", bad)
		}
	}
}
