package mgr

import (
	"reflect"
	"testing"
)

// Field report (2026-11-16): the custom join [c] of the auto-test table did nothing on the Go manager — the key had
// no case — and EOF made the choice loop spin forever.
func TestAtChooseCustomJoinAndEOF(t *testing.T) {
	NonInteractive = false
	av = []variant{{Label: "udp", Car: "udp", Kind: "d"}, {Label: "tcp", Car: "tcp", Kind: "d"}, {Label: "ws", Car: "ws", Kind: "d"}}
	ar = []result{{OK: true, Down: 5, Up: 5}, {OK: true, Down: 4, Up: 4}, {OK: true, Down: 3, Up: 3}}
	rank := []int{0, 1, 2}
	defer feed("c1+3\n")()
	sel, err := atChoose(rank, false, "")
	if err != nil || !reflect.DeepEqual(sel, []int{0, 2}) {
		t.Fatalf("custom join 1+3: sel %v err %v", sel, err)
	}
	defer feed("")()
	if _, err := atChoose(rank, false, ""); err == nil {
		t.Fatal("EOF must cancel, not pick")
	}
}

// A reverse probe whose Kharej-picked port is held on this server says so instead of timing out as "no link".
func TestAtProbeReverseBusyPort(t *testing.T) {
	ob, ou := p2PortBusy, p2PortUser
	defer func() { p2PortBusy, p2PortUser = ob, ou }()
	p2PortBusy = func(p int, proto string) bool { return p == 23456 && proto == "tcp" }
	p2PortUser = func(int, string) string { return "x-ui" }
	atStop, atSkip = false, ""
	av = []variant{{Label: "tls reverse", Car: "tls", Kind: "r", Peer: "203.0.113.1", Port: "23456"}}
	ar = make([]result, 1)
	atProbe(0, 1)
	if ar[0].Why != "port 23456 busy here (x-ui)" {
		t.Fatalf("why = %q", ar[0].Why)
	}
}
