package wat

// W7/F13 (3.3.0) benchmark evidence: the cost of -shape-data on a session. Run with:
//
//	go test -run xxx -bench 'ShapeData' -benchtime 1s ./wat/
//
// The link is the in-process zero-delay memory pair (bench_test.go), i.e. loopback with no network or carrier cost: the
// numbers isolate the session's own CPU (padding, seal, acks), which is the part shape-data changes.
import (
	"fmt"
	"io"
	"testing"
)

// benchEcho measures request/response throughput of 200 B messages, the small-packet pattern shape-data reshapes.
func benchEcho(b *testing.B, mtu int, shape float64) {
	cli, srv := memPair(b, Config{MaxPayload: mtu, ShapeData: shape})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 200)
	buf := make([]byte, len(msg))
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(st, buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(cli.Stats().PadBytes)/float64(b.N), "padB/msg")
}

func BenchmarkShapeDataSmall(b *testing.B) {
	for _, mtu := range []int{640, 1400} {
		for _, c := range []struct {
			name string
			pct  float64
		}{{"off", 0}, {"on10pct", 0.10}, {"on25pct", 0.25}} {
			b.Run(fmt.Sprintf("mtu%d_%s", mtu, c.name), func(b *testing.B) { benchEcho(b, mtu, c.pct) })
		}
	}
}

// benchBulk measures one-way stream throughput; bulk packets are already full, so padding must cost ~nothing.
func benchBulk(b *testing.B, mtu int, shape float64) {
	cli, srv := memPair(b, Config{MaxPayload: mtu, ShapeData: shape})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, st) }()
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	st.CloseWrite()
	for { // wait for the last bytes to be acked before stopping the timer
		cli.mu.Lock()
		done := st.finAcked
		cli.mu.Unlock()
		if done {
			break
		}
		runtimeGosched()
	}
	b.StopTimer()
	b.ReportMetric(float64(cli.Stats().PadBytes), "padB")
}

func BenchmarkShapeDataBulk(b *testing.B) {
	for _, mtu := range []int{640, 1400} {
		for _, c := range []struct {
			name string
			pct  float64
		}{{"off", 0}, {"on10pct", 0.10}, {"on25pct", 0.25}} {
			b.Run(fmt.Sprintf("mtu%d_%s", mtu, c.name), func(b *testing.B) { benchBulk(b, mtu, c.pct) })
		}
	}
}
