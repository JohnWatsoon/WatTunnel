//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// A segment with its checksum filled in sums to zero over the pseudo-header (v4 and v6, odd length too).
func TestTCPSum(t *testing.T) {
	for _, ips := range [][2]string{{"10.0.0.1", "192.0.2.7"}, {"2001:db8::1", "2001:db8::2"}} {
		src, dst := net.ParseIP(ips[0]), net.ParseIP(ips[1])
		seg := make([]byte, 33)
		binary.BigEndian.PutUint16(seg, 61000)
		seg[12] = 5 << 4
		seg[32] = 0xab
		binary.BigEndian.PutUint16(seg[16:], tcpSum(src, dst, seg))
		if got := tcpSum(src, dst, seg); got != 0 {
			t.Errorf("%v: checksum over a checksummed segment = %#x, want 0", ips, got)
		}
	}
}

func TestPayload(t *testing.T) {
	*size = 64
	h, ok := parse(mk(4, 7, 9, 100, 50))
	if !ok || h != (hdr{4, 7, 9, 100, 50}) {
		t.Fatalf("parse(mk) = %+v %v", h, ok)
	}
	if _, ok := parse([]byte("WFP0xxxxxxxxxxxxxxxxxxxxx")); ok {
		t.Fatal("wrong magic parsed")
	}
}
