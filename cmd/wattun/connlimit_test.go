package main

import (
	"net"
	"testing"
)

func TestConnLimiterPerIP(t *testing.T) {
	l := newConnLimiter(100, 2)
	if !l.acquire("192.0.2.1") || !l.acquire("192.0.2.1") {
		t.Fatal("two connections from one IP should be admitted")
	}
	if l.acquire("192.0.2.1") {
		t.Fatal("a third connection from one IP over the per-IP cap should be refused")
	}
	if !l.acquire("192.0.2.2") {
		t.Fatal("the per-IP cap must not block another source")
	}
}

func TestConnLimiterGlobal(t *testing.T) {
	l := newConnLimiter(2, 100)
	if !l.acquire("192.0.2.1") || !l.acquire("192.0.2.2") {
		t.Fatal("two connections under the global cap should be admitted")
	}
	if l.acquire("192.0.2.3") {
		t.Fatal("a connection over the global cap should be refused")
	}
}

func TestConnLimiterRelease(t *testing.T) {
	l := newConnLimiter(1, 1)
	if !l.acquire("192.0.2.1") {
		t.Fatal("first connection should be admitted")
	}
	if l.acquire("192.0.2.1") {
		t.Fatal("second connection should be refused")
	}
	l.release("192.0.2.1")
	l.mu.Lock()
	total, perIP := l.total, len(l.perIP)
	l.mu.Unlock()
	if total != 0 || perIP != 0 {
		t.Fatalf("after release: total=%d, per-IP entries=%d, want 0 and 0", total, perIP)
	}
	if !l.acquire("192.0.2.1") {
		t.Fatal("a released slot should be reusable")
	}
}

// stringAddr is a net.Addr whose String is exactly what the test supplied.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func TestRemoteIP(t *testing.T) {
	for _, c := range []struct {
		addr net.Addr
		want string
	}{
		{nil, ""},
		{&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}, "127.0.0.1"},
		{stringAddr("192.0.2.7:1234"), "192.0.2.7"},
		{stringAddr("[2001:db8::1]:443"), "2001:db8::1"},
		{stringAddr("not-a-host-port"), "not-a-host-port"},
		{stringAddr(""), ""},
	} {
		if got := remoteIP(c.addr); got != c.want {
			t.Errorf("remoteIP(%v) = %q, want %q", c.addr, got, c.want)
		}
	}
}
