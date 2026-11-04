//go:build linux

package wat

// CI/root only: raw sockets need CAP_NET_RAW. This test was NOT run on the Windows checkout that wrote the carriers; it
// is the Linux gate that proves each raw-tier shape comes up on loopback, and that the H9/M15 role check + socket
// filter keep the client from consuming its own locally looped frame. It is named to match CI's sudo job
// (TestICMP|TestRawIP), so the existing CI job runs it without a workflow change.

import (
	"os"
	"testing"
	"time"
)

func TestRawIPShapedLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need root")
	}
	key := []byte("raw-shape-loopback")
	for _, name := range rawShapeNames {
		t.Run(name, func(t *testing.T) {
			srv, err := NewShapedRaw(name, true, "", "", key)
			if err != nil {
				t.Fatalf("%s server socket: %v", name, err)
			}
			defer srv.Close()
			cli, err := NewShapedRaw(name, false, "127.0.0.1", "", key)
			if err != nil {
				t.Fatalf("%s client socket: %v", name, err)
			}
			defer cli.Close()
			if err := cli.Send([]byte("ping"), 0); err != nil {
				t.Fatalf("%s send: %v", name, err)
			}
			srv.c.SetReadDeadline(time.Now().Add(2 * time.Second))
			p, _, src, err := srv.Recv()
			if err != nil || string(p) != "ping" {
				t.Fatalf("%s server got %q %v (is the protocol intercepted on this kernel?)", name, p, err)
			}
			if err := srv.SendTo([]byte("pong"), 0, src); err != nil {
				t.Fatalf("%s reply: %v", name, err)
			}
			// H9: the client socket also receives a copy of the frame it just sent; the role check must drop it, so
			// the first delivery the client sees is the server's pong, never its own ping.
			cli.c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if p, _, _, err = cli.Recv(); err != nil || string(p) != "pong" {
				t.Fatalf("%s client got %q %v, want pong (its own ping was not filtered, H9)", name, p, err)
			}
		})
	}
}
