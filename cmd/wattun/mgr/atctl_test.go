package mgr

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type killCount struct{ n atomic.Int32 }

func (k *killCount) Kill() error { k.n.Add(1); return nil }

// The panel's skip/stop buttons append to the control file; a skip counts only for the carrier it names, a stop
// always, and a line is acted on once.
func TestAtCtlSkipStop(t *testing.T) {
	f := filepath.Join(t.TempDir(), "job.ctl")
	oldPath, oldSeen := atCtlPath, atCtlSeen
	t.Cleanup(func() { atCtlPath, atCtlSeen = oldPath, oldSeen; atCtlHit.Store(0) })
	atCtlPath, atCtlSeen = f, 0
	add := func(l string) {
		fh, _ := os.OpenFile(f, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		fh.WriteString(l + "\n")
		fh.Close()
	}
	if h := atCtlPoll("udp"); h != 0 {
		t.Fatalf("no file: %d", h)
	}
	add("skip udp")
	if h := atCtlPoll("tcp"); h != 0 {
		t.Fatalf("a skip for udp hit tcp: %d", h)
	}
	add("skip tcp")
	if h := atCtlPoll("tcp"); h != atCtlSkip {
		t.Fatalf("skip tcp: %d", h)
	}
	if h := atCtlPoll("tcp"); h != 0 {
		t.Fatalf("the same line acted on twice: %d", h)
	}
	// a running probe: the watcher kills its client on stop
	k := &killCount{}
	stop := atWatch("tls", k)
	add("stop")
	deadline := time.Now().Add(3 * time.Second)
	for atCtlHit.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	if atCtlHit.Load() != atCtlStop || k.n.Load() != 1 {
		t.Fatalf("stop: hit=%d kills=%d", atCtlHit.Load(), k.n.Load())
	}
}
