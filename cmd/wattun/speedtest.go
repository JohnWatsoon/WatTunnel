package main

// Built-in speed test through the live tunnel.
//
// A stream whose 2-byte target header is 0 (never a real port) goes to the server's speed-test handler instead of a
// local service, so no test service or extra port is needed on either side. After the header the client sends
// one op byte and a big-endian uint64 size:
//
//	'D' (download): the server writes size bytes and closes its side.
//	'U' (upload):   the client writes size bytes and closes its side; the server answers with the uint64 count it read.
//
// The client side is the /speedtest endpoint on the metrics address (127.0.0.1 only):
//
//	curl '127.0.0.1:19700/speedtest?dir=down&mb=10'
//
// With -sessions N (2.3.0) the test runs one stream on every live session at once, each moving its share of the
// size, and reports the total over the wall time ("sessions" says how many took part). The server side is unchanged:
// it only ever sees ordinary speed-test streams.
//
// streams=N (2.4.18, 1-32, default 16 since 3.3.0; was 8) runs N streams on every session, the way real users load a
// tunnel with many connections. On a direct pool each stream rides one TCP connection (stream pinning), so a single
// stream shows what one connection does and N streams what the tunnel does. streams=1 is the pre-2.4.18 single-stream
// test. 16 is the auto-mode/`wattun speedtest` default so the figure reflects multi-connection capacity rather than
// one connection's share.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

const (
	speedTestPort  = 0
	speedTestMaxMB = 256
	speedTestLimit = 3 * time.Minute
	// speedTestStreamsMax is the accepted streams= range (1..32); speedTestStreamsDefault is used when it is absent
	// or out of range (3.3.0: 16, was 8).
	speedTestStreamsMax     = 32
	speedTestStreamsDefault = 16
)

var speedChunk = make([]byte, 32<<10)

// serveSpeedTest runs on the server for a stream whose header asked for target 0.
func serveSpeedTest(st *wat.Stream) {
	var req [9]byte
	if _, err := io.ReadFull(st, req[:]); err != nil {
		st.Reset()
		return
	}
	size := binary.BigEndian.Uint64(req[1:])
	if size > speedTestMaxMB<<20 {
		st.Reset()
		return
	}
	switch req[0] {
	case 'D':
		if err := writeN(st, size); err != nil {
			st.Reset()
			return
		}
		st.CloseWrite()
	case 'U':
		n, err := io.Copy(io.Discard, io.LimitReader(st, int64(size)+1))
		if err != nil {
			st.Reset()
			return
		}
		var ack [8]byte
		binary.BigEndian.PutUint64(ack[:], uint64(n))
		st.Write(ack[:])
		st.CloseWrite()
	default:
		st.Reset()
	}
}

func writeN(w io.Writer, n uint64) error {
	for n > 0 {
		c := speedChunk
		if uint64(len(c)) > n {
			c = c[:n]
		}
		if _, err := w.Write(c); err != nil {
			return err
		}
		n -= uint64(len(c))
	}
	return nil
}

type speedResult struct {
	Dir      string  `json:"dir"`
	Bytes    uint64  `json:"bytes"`
	Seconds  float64 `json:"seconds"`
	MBps     float64 `json:"mb_per_s"`
	Mbit     float64 `json:"mbit_per_s"`
	OK       bool    `json:"ok"`
	Error    string  `json:"error,omitempty"`
	Sessions int     `json:"sessions"` // sessions the test ran on in parallel (2.3.0)
	Streams  int     `json:"streams"`  // streams per session (2.4.18)
}

// runSpeedTest moves size bytes in one direction through every live session of tun at once, streams streams on
// each (size split between them all), and times the whole.
func runSpeedTest(tun *tunnel, dir string, size uint64, streams int, done <-chan struct{}) speedResult {
	list := tun.live()
	streams = max(streams, 1)
	if len(list) == 0 {
		return speedResult{Dir: dir, Bytes: size, Error: "tunnel is not connected", Sessions: len(tun.list), Streams: streams}
	}
	if len(list) == 1 && streams == 1 {
		r := speedOne(list[0], dir, size, done)
		r.Sessions, r.Streams = 1, 1
		return r
	}
	var jobs []*wat.Session
	for _, s := range list {
		for range streams {
			jobs = append(jobs, s)
		}
	}
	part := size / uint64(len(jobs))
	parts := make([]speedResult, len(jobs))
	var wg sync.WaitGroup
	t0 := time.Now()
	for i, s := range jobs {
		n := part
		if i == 0 {
			n += size - part*uint64(len(jobs)) // the remainder
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			parts[i] = speedOne(s, dir, n, done)
		}()
	}
	wg.Wait()
	res := speedResult{Dir: dir, Bytes: size, Sessions: len(list), Streams: streams}
	for i, p := range parts {
		if !p.OK {
			res.Error = fmt.Sprintf("stream %d of %d: %s", i+1, len(jobs), p.Error)
			return res
		}
	}
	res.Seconds = time.Since(t0).Seconds()
	res.MBps = float64(size) / 1e6 / res.Seconds
	res.Mbit = res.MBps * 8
	res.OK = true
	return res
}

// speedOne moves size bytes in one direction through one stream of sess and times it. done (the HTTP
// request's context) aborts the transfer when the caller walks away — without it an abandoned /speedtest
// kept up to sessions×32 streams running until the 3-minute cap (audit 2026-10-21).
func speedOne(sess *wat.Session, dir string, size uint64, done <-chan struct{}) speedResult {
	res := speedResult{Dir: dir, Bytes: size}
	fail := func(err error) speedResult { res.Error = err.Error(); return res }
	if !sess.Alive() {
		return fail(errors.New("tunnel is not connected"))
	}
	st, err := sess.OpenStream()
	if err != nil {
		return fail(err)
	}
	timer := time.AfterFunc(speedTestLimit, st.Reset)
	defer timer.Stop()
	fin := make(chan struct{})
	defer close(fin) // the watcher below must not linger for the full limit after an early return
	if done != nil {
		go func() {
			select {
			case <-done:
				st.Reset()
			case <-fin:
			case <-time.After(speedTestLimit):
			}
		}()
	}
	var hdr [11]byte
	binary.BigEndian.PutUint16(hdr[:2], speedTestPort)
	hdr[2] = 'D'
	if dir == "up" {
		hdr[2] = 'U'
	}
	binary.BigEndian.PutUint64(hdr[3:], size)
	t0 := time.Now()
	if _, err := st.Write(hdr[:]); err != nil {
		return fail(err)
	}
	if dir == "up" {
		if err := writeN(st, size); err != nil {
			return fail(err)
		}
		st.CloseWrite()
		var ack [8]byte
		if _, err := io.ReadFull(st, ack[:]); err != nil {
			return fail(fmt.Errorf("no answer from the server (is it running wattun 1.8.1 or newer?): %w", err))
		}
		if got := binary.BigEndian.Uint64(ack[:]); got != size {
			return fail(fmt.Errorf("server received %d of %d bytes", got, size))
		}
	} else {
		st.CloseWrite()
		n, err := io.Copy(io.Discard, st)
		if err != nil {
			return fail(err)
		}
		if uint64(n) != size {
			return fail(fmt.Errorf("received %d of %d bytes (is the server running wattun 1.8.1 or newer?)", n, size))
		}
	}
	res.Seconds = time.Since(t0).Seconds()
	res.MBps = float64(size) / 1e6 / res.Seconds
	res.Mbit = res.MBps * 8
	res.OK = true
	return res
}

// speedTestStreams parses /speedtest's streams= parameter: 1..speedTestStreamsMax, else the default (3.3.0: 16, so
// auto mode and `wattun speedtest` measure multi-stream capacity; before: 8).
func speedTestStreams(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > speedTestStreamsMax {
		return speedTestStreamsDefault
	}
	return n
}

// speedTestHandler serves /speedtest?dir=down|up&mb=N on the client's metrics address.
func speedTestHandler(tun *tunnel) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		if dir != "up" {
			dir = "down"
		}
		mb, err := strconv.Atoi(r.URL.Query().Get("mb"))
		if err != nil || mb < 1 {
			mb = 10
		}
		streams := speedTestStreams(r.URL.Query().Get("streams"))
		mb = min(mb, speedTestMaxMB*streams) // the server's cap is per stream, and mb is split between the streams
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(runSpeedTest(tun, dir, uint64(mb)<<20, streams, r.Context().Done()))
	}
}
