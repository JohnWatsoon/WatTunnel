package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// newScepterRig is a paired UDP session pair with a real ScepterState on the server; it returns the client.
func newScepterRig(t *testing.T) *wat.Session {
	t.Helper()
	caps, _ := wat.CapFromName("full") // the cumulative mask a real credential carries
	pair := &wat.PairingConfig{Ver: 1, Caps: caps}
	copy(pair.Key[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(pair.UUID[:], []byte("0123456789abcdef"))
	key := []byte("hub-test-key-hub-test-key-hub-te")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	state, err := wat.NewScepterState(pair, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key, Pairing: pair}, us)
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go func(s *wat.Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					if st.ID() == 0 {
						go wat.ServeScepter(st, state)
					} else {
						st.Reset()
					}
				}
			}(s)
		}
	}()
	uc, err := wat.NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := wat.NewSession(wat.Config{Key: key, Pairing: pair}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	waitFor(t, "session alive", 5*time.Second, cli.Alive)
	return cli
}

// sockDir is a TempDir with its long name: Windows AF_UNIX refuses to connect through an 8.3 short path
// (TEMP often holds one), and Linux paths are unaffected.
func sockDir(t *testing.T) string {
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	d, err := os.MkdirTemp(".", ".socktest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	abs, _ := filepath.Abs(d)
	return abs
}

// The socket answers through the unit's one scepter stream; concurrent callers are serialized, never mixed.
func TestScepterSockRelay(t *testing.T) {
	cli := newScepterRig(t)
	h := &scepterHub{dial: func() (*wat.ScepterClient, error) { return wat.DialScepter(cli) }, logf: t.Logf}
	path := scepterSockPath(filepath.Join(sockDir(t), "ir.yml"))
	l, err := serveScepterSock(path, h)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var b strings.Builder
			if err := scepterCallSock(path, "scepter.ping", nil, "", &b); err != nil {
				t.Errorf("call: %v", err)
				return
			}
			if !strings.Contains(b.String(), `"pong":true`) || strings.Count(b.String(), "\n") != 1 {
				t.Errorf("answer = %q, want one pong line", b.String())
			}
		}()
	}
	wg.Wait()
}

func TestScepterSockErrors(t *testing.T) {
	path := scepterSockPath(filepath.Join(sockDir(t), "x.yml"))
	if err := scepterCallSock(path, "scepter.ping", nil, "", &strings.Builder{}); !errors.Is(err, errNoSock) {
		t.Fatalf("no unit: err = %v, want errNoSock (the one-shot fallback trigger)", err)
	}
	h := &scepterHub{dial: func() (*wat.ScepterClient, error) { return nil, errors.New("tunnel down") }, logf: t.Logf}
	l, err := serveScepterSock(path, h)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer l.Close()
	err = scepterCallSock(path, "scepter.ping", nil, "", &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "tunnel down") {
		t.Fatalf("dead channel: err = %v, want the transport error relayed", err)
	}
	// a garbage request is refused, not executed
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("nope\n"))
	buf := make([]byte, 200)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), "bad request") {
		t.Fatalf("garbage answer = %q", buf[:n])
	}
}
