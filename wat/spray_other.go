//go:build !linux

package wat

import (
	"errors"
	"net"
)

// SprayClient / SprayServer (spray, 3.4.3) exist on Linux only (raw UDP sockets + CAP_NET_RAW); every
// constructor fails elsewhere, the same way the raw-tier carriers do.
type SprayClient struct{}
type SprayServer struct{}

func NewSprayClient(peer, srcIP string, hop int) (*SprayClient, error) {
	return nil, errors.New("the spray carrier needs Linux + root/CAP_NET_RAW")
}

func NewSprayServer(spec string) (*SprayServer, error) {
	return nil, errors.New("the spray carrier needs Linux + root/CAP_NET_RAW")
}

func (*SprayClient) Send([]byte, int) error               { return net.ErrClosed }
func (*SprayClient) SendBatch([][]byte, []int) error      { return net.ErrClosed }
func (*SprayClient) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*SprayClient) SetPeer(net.Addr)                     {}
func (*SprayClient) Close() error                         { return nil }
func (*SprayClient) Profile() Profile                     { return Profile{MTU: 1372, InitBps: 8e6, Spread: true} }

func (*SprayServer) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*SprayServer) SendTo([]byte, int, net.Addr) error   { return net.ErrClosed }
func (*SprayServer) Close() error                         { return nil }
func (*SprayServer) Profile() Profile                     { return Profile{MTU: 1372, InitBps: 8e6, Spread: true} }
