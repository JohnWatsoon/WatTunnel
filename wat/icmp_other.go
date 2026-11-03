//go:build !linux

package wat

import (
	"errors"
	"net"
	"time"
)

// ICMPIO exists on Linux only (raw sockets + BPF). This stub lets the rest of the module build and test on a
// developer machine; every constructor fails.
type ICMPIO struct{}

func IdentBase(key []byte) uint16 { return 0 }

func NewICMPIO(server bool, peerIP string, key []byte) (*ICMPIO, error) {
	return nil, errors.New("the icmp carrier needs Linux")
}

func (*ICMPIO) Send([]byte, int) error               { return net.ErrClosed }
func (*ICMPIO) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*ICMPIO) SendTo([]byte, int, net.Addr) error   { return net.ErrClosed }
func (*ICMPIO) SetPeer(net.Addr)                     {}
func (*ICMPIO) Close() error                         { return nil }

func NewICMPIOType(server bool, peerIP string, key []byte, kind string) (*ICMPIO, error) {
	return nil, errors.New("the icmp carrier needs Linux")
}

func NewICMPIOReverse(server, reverse bool, peerIP string, key []byte, kind string) (*ICMPIO, error) {
	return nil, errors.New("the icmp carrier needs Linux")
}

func NewICMPIOSource(server, reverse bool, peerIP, srcIP string, key []byte, kind string) (*ICMPIO, error) {
	return nil, errors.New("the icmp carrier needs Linux")
}

func (*ICMPIO) Knock(int, time.Duration) {}
