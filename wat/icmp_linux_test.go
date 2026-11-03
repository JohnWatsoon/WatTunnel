//go:build linux

package wat

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// ipIcmp builds an IPv4 header (IHL 5) + ICMP header of the given type and identifier.
func ipIcmp(typ uint8, ident uint16) []byte {
	b := make([]byte, 20+8+4)
	b[0] = 0x45
	b[9] = 1
	b[20] = typ
	b[24], b[25] = byte(ident>>8), byte(ident)
	return b
}

// The kernel filter must hand the process only its own ICMP type with an identifier in the tunnel's range.
func TestICMPFilterPerType(t *testing.T) {
	base := IdentBase([]byte("k"))
	all := []uint8{0, 3, 5, 8, 11, 13, 14, 15, 16, 17, 18}
	for _, kind := range []string{"echo", "timestamp", "info", "mask"} {
		req, rep, ok := ICMPTypes(kind)
		if !ok {
			t.Fatal(kind)
		}
		for _, server := range []bool{false, true} {
			want := rep
			if server {
				want = req
			}
			vm, err := bpf.NewVM(icmpFilter(want, base))
			if err != nil {
				t.Fatal(err)
			}
			for _, typ := range all {
				for _, id := range []uint16{base - 1, base, base + identLanes - 1, base + identLanes} {
					n, err := vm.Run(ipIcmp(typ, id))
					if err != nil {
						t.Fatal(err)
					}
					accept := typ == want && id >= base && id < base+identLanes
					if (n > 0) != accept {
						t.Errorf("%s server=%v type %d ident %d: accepted=%v want %v", kind, server, typ, id, n > 0, accept)
					}
				}
			}
		}
	}
	if _, _, ok := ICMPTypes("bogus"); ok {
		t.Error("bogus icmp type accepted")
	}
	for kind, w := range map[string][2]uint8{"echo": {8, 0}, "timestamp": {13, 14}, "info": {15, 16}, "mask": {17, 18}} {
		if a, b, _ := ICMPTypes(kind); a != w[0] || b != w[1] {
			t.Errorf("%s: %d/%d", kind, a, b)
		}
	}
}

// Real raw sockets on loopback (needs root; skipped otherwise): a client and a server session exchange data over
// each ICMP type pair. The packet types are checked on the sockets themselves.
// Reverse mode (2.0.0) runs the same exchange with the server sending the requests and knocking.
func TestICMPLoopbackPerType(t *testing.T) {
	for _, kind := range []string{"echo", "timestamp", "info", "mask", "reverse-echo", "reverse-timestamp"} {
		t.Run(kind, func(t *testing.T) {
			key := []byte("icmp-type-test-" + kind)
			reverse := strings.HasPrefix(kind, "reverse-")
			kind := strings.TrimPrefix(kind, "reverse-")
			speer := ""
			if reverse {
				speer = "127.0.0.1"
			}
			sio, err := NewICMPIOReverse(true, reverse, speer, key, kind)
			if err != nil {
				if os.Geteuid() != 0 {
					t.Skipf("raw socket (not root): %v", err)
				}
				t.Fatalf("raw socket as root: %v", err)
			}
			cio, err := NewICMPIOReverse(false, reverse, "127.0.0.1", key, kind)
			if err != nil {
				sio.Close()
				if os.Geteuid() != 0 {
					t.Skipf("raw socket (not root): %v", err)
				}
				t.Fatalf("raw socket as root: %v", err)
			}
			req, _, _ := ICMPTypes(kind)
			if cio.sendType() == sio.sendType() || (sio.sendType() == req) != reverse {
				t.Fatalf("reverse=%v: client sends %d, server sends %d", reverse, cio.sendType(), sio.sendType())
			}
			sio.Knock(4, 50*time.Millisecond)
			srv := NewServer(Config{Key: key}, sio)
			t.Cleanup(srv.Close)
			go func() {
				for s := range srv.New {
					go func(s *Session) {
						for {
							st, err := s.Accept()
							if err != nil {
								return
							}
							go func() { io.Copy(st, st); st.CloseWrite() }()
						}
					}(s)
				}
			}()
			cli, err := NewSession(Config{Key: key, Paths: 4, MaxBps: 20e6}, cio)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cli.Close)
			echoOnceKind(t, cli, 300<<10, 5)
		})
	}
}

func echoOnceKind(t *testing.T, cli *Session, n int, seed byte) {
	t.Helper()
	data := pattern(n, seed)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()
	got := make(chan []byte, 1)
	go func() { b, _ := readAll(st); got <- b }()
	select {
	case b := <-got:
		if !bytes.Equal(b, data) {
			t.Fatalf("echo mismatch: got %d want %d", len(b), n)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("echo timeout")
	}
}

func TestBatchDefault(t *testing.T) {
	t.Setenv("WAT_BATCH", "")
	if !batchWanted(&ICMPIO{}) || batchWanted(&UDPClient{}) {
		t.Error("unset: want on for icmp, off for udp")
	}
	if icmpBatchDisabled() {
		t.Error("icmp batching disabled with WAT_BATCH unset")
	}
	t.Setenv("WAT_BATCH", "0")
	if batchWanted(&ICMPIO{}) || !icmpBatchDisabled() {
		t.Error("WAT_BATCH=0 must force it off")
	}
	t.Setenv("WAT_BATCH", "1")
	if !batchWanted(&UDPClient{}) {
		t.Error("WAT_BATCH=1 must turn it on for udp")
	}
}
