package wat

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRollRotateJitterBounds: the churn budget stays inside the ±40 % time / ±25 % count windows and above
// the floors, so a bad roll can never hot-loop the redialer nor synchronize the pool.
func TestRollRotateJitterBounds(t *testing.T) {
	base := time.Hour
	now := time.Now()
	for i := 0; i < 500; i++ {
		b := rollRotate(base, 4<<20) // 4 MB: above the 1 MB floor, so the jitter window is visible
		d := b.at.Sub(now)
		if d < 30*time.Minute || d > 90*time.Minute {
			t.Fatalf("roll %d: %v outside the 36..84 min jitter window", i, d)
		}
		if b.bytes < 3<<20 || b.bytes > 5<<20 {
			t.Fatalf("roll %d: %d bytes outside the 3..5 MB jitter window", i, b.bytes)
		}
	}
	// floors
	small := rollRotate(time.Second, 1)
	if small.at.Sub(now) < 10*time.Second {
		t.Fatalf("time floor not applied: %v", small.at.Sub(now))
	}
	if small.bytes < 1<<20 {
		t.Fatalf("byte floor not applied: %d", small.bytes)
	}
	// off switches
	off := rollRotate(0, 0)
	if !off.at.IsZero() || off.bytes != 0 {
		t.Fatalf("zero base did not disable the budget: %+v", off)
	}
}

// TestRotateDueSemantics: a connection recycles when EITHER axis of its budget is hit, and not before.
func TestRotateDueSemantics(t *testing.T) {
	pc := newPoolConn(nil)
	defer func() {
		if pc.c != nil {
			pc.c.Close()
		}
	}()
	now := time.Now()
	// no budget: never due
	if pc.rotateDue(now) {
		t.Fatal("no budget: reported due")
	}
	// time axis: past the timestamp => due
	b := rotateBudget{at: now.Add(-time.Second), bytes: 0}
	pc.rot.Store(&b)
	if !pc.rotateDue(now) {
		t.Fatal("past the time budget: not reported due")
	}
	// time axis: still inside => not due
	b.at = now.Add(time.Hour)
	pc.rot.Store(&b)
	if pc.rotateDue(now) {
		t.Fatal("inside the time budget: reported due")
	}
	// byte axis: txSize over the budget => due
	b.at = now.Add(time.Hour)
	b.bytes = 10
	pc.rot.Store(&b)
	pc.txSize.Store(10)
	if !pc.rotateDue(now) {
		t.Fatal("txSize hit the byte budget: not reported due")
	}
	pc.txSize.Store(9)
	if pc.rotateDue(now) {
		t.Fatal("txSize under the byte budget: reported due")
	}
}

// TestWriteLoopCountsBytes: the churn byte axis counts the bytes handed to the socket, framing header included
// (2.8.1: rotateDue compared the byte budget against the datagram count, ~256x off at the default 4096-byte MTU).
func TestWriteLoopCountsBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvC := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			srvC <- c // held (and referenced) so neither GC nor the peer closes it under the writer
		}
	}()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	pc := newPoolConn(cl)
	var wg sync.WaitGroup
	go pc.serve(&wg, func([]byte) bool { return true })
	defer func() { // LIFO: the conns close before the wait
		pc.fail()
		wg.Wait()
		select {
		case c := <-srvC:
			c.Close()
		default:
		}
	}()
	p := make([]byte, 100)
	deadline := time.Now().Add(2 * time.Second)
	for pc.txSize.Load() < uint64(2+len(p)) && time.Now().Before(deadline) {
		if !pc.enqueue(p) {
			t.Fatal("enqueue failed: connection died")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := pc.txSize.Load(); got < uint64(2+len(p)) {
		t.Fatalf("txSize %d after 2 s, want at least %d (2-byte header + payload)", got, 2+len(p))
	}
}

// TestCloneCarriesDialHook: -sessions clones inherit the fake-SNI dial hook (2.8.1: they did not, so every
// session beyond the first dialed bare and -fake-sni fired only on session 1's connections).
func TestCloneCarriesDialHook(t *testing.T) {
	c, err := newSlotPoolClient(func(ctx context.Context, slot int) (net.Conn, error) {
		return nil, errors.New("no dial in this test")
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var called atomic.Bool // two dialers run the hook concurrently (slotLoop + the direct dial below)
	c.SetDialHook(func(ctx context.Context, slot int, inner func(context.Context, int) (net.Conn, error)) (net.Conn, error) {
		called.Store(true)
		return nil, errors.New("hook ran")
	})
	n, err := c.Clone(1)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	_, _ = n.dialer()(t.Context(), 0)
	if !called.Load() {
		t.Fatal("the clone's dialer skipped the dial hook")
	}
}

// TestRotatePickSingleConn: a 1-slot pool never recycles its only connection (audit 2026-10-22):
// every recycle would be a full-pool outage until the redial completes. Two+ slots keep recycling.
func TestRotatePickSingleConn(t *testing.T) {
	c, err := newSlotPoolClient(func(context.Context, int) (net.Conn, error) {
		return nil, errors.New("no dial")
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	pc := newPoolConn(p1)
	c.slots[0].Store(pc)
	now := time.Now()
	if c.rotatePick(now) != nil {
		t.Fatal("rotatePick returned conn before due")
	}
	b := rotateBudget{at: now.Add(-time.Second)}
	pc.rot.Store(&b)
	if got := c.rotatePick(now); got != nil {
		t.Fatalf("rotatePick single conn: got %v, want nil (the last usable conn)", got)
	}
}
