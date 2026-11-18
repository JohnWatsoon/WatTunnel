package wat

import (
	"net"
	"os"
)

// PacketIO moves already-encrypted datagrams. path selects an ICMP identifier (a striping lane).
type PacketIO interface {
	// Send transmits one datagram on the lane.
	Send(p []byte, path int) error
	// Recv blocks for the next datagram; the slice is only valid until the next call.
	Recv() (p []byte, path int, src net.Addr, err error)
	// SetPeer tells a server which address authenticated traffic came from.
	SetPeer(a net.Addr)
	Close() error
}

// Profile is what a carrier knows about its own transport. A carrier opts in by implementing Profiled; ICMP does
// not, so it always gets the zero Profile, i.e. the original behaviour (the sim tests pin that).
type Profile struct {
	Reliable bool    // delivers every datagram in order per connection (TCP based): no packet-count loss detection, delay judged by its floor
	NoDirect bool    // HTTP/CDN-capable pool (ws/wss/h2/h2c/grpc unless reverse): keep the 4 KB MTU instead of auto-promoting to 16 KB directMTU (3.3.8)
	MTU      int     // default datagram size when Config.MaxPayload == 0 (0 = MaxPayload, the ICMP-safe 640)
	MaxMTU   int     // largest datagram the carrier frames (0 = MaxPayloadHi)
	InitBps  float64 // default starting pace when Config.InitBps == 0 (0 = 1.5 MB/s)
}

// Profiled is the optional interface of PacketIO / RawIO carriers that carry a Profile.
type Profiled interface{ Profile() Profile }

func profileOf(x any) Profile {
	if p, ok := x.(Profiled); ok {
		return p.Profile()
	}
	return Profile{}
}

// BatchSender is the optional interface of a PacketIO that can put several datagrams on the wire in one system
// call (sendmmsg). The session uses it when its pacer releases more than one packet at once; without it every
// datagram goes through Send exactly as before. lanes[i] is the lane of ps[i].
type BatchSender interface {
	SendBatch(ps [][]byte, lanes []int) error
}

// Backlogger is the optional interface of a PacketIO with send queues of its own (the pool carriers, 2.4.18): it
// reports when they are full, so the session holds new data back instead of handing over packets the carrier would
// drop. Without it the session sends exactly as before.
type Backlogger interface{ Backlogged() bool }

// RawBacklogger is the RawIO counterpart, per destination; the server's per-session IO turns it into a Backlogger.
type RawBacklogger interface{ BackloggedTo(dst net.Addr) bool }

// DeathReporter is the optional interface of a PacketIO whose own connections die independently (the pool
// carriers): it counts the deaths of THIS io, so a session repairs only after its own carrier lost a
// connection. The process-global counter it replaces also fired on every other pool's churn (audit 2026-10-22).
type DeathReporter interface{ ConnDeaths() uint64 }

// RawBatchSender is the server-side equivalent: one destination, several datagrams.
type RawBatchSender interface {
	SendBatchTo(ps [][]byte, lanes []int, dst net.Addr) error
}

// batchWanted: WAT_BATCH unset = batching on for the ICMP carrier (v1.8.0), off for the others; "0" = off; any other value = on.
func batchWanted(pio any) bool {
	switch os.Getenv("WAT_BATCH") {
	case "0":
		return false
	case "":
		if s, ok := pio.(*subIO); ok {
			pio = s.srv.raw
		}
		_, icmp := pio.(*ICMPIO)
		return icmp
	}
	return true
}

// ICMPTypes maps -icmp-type to the request and reply ICMP type numbers.
func ICMPTypes(kind string) (req, rep uint8, ok bool) {
	switch kind {
	case "", "echo":
		return 8, 0, true
	case "timestamp":
		return 13, 14, true
	case "info":
		return 15, 16, true
	case "mask":
		return 17, 18, true
	}
	return 0, 0, false
}
