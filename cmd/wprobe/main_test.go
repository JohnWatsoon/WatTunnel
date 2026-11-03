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
