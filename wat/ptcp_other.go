//go:build !linux

package wat

import (
	"errors"
	"net"
)

// PTCPClient / PTCPServer (ptcp, Phantom, 3.4.3) exist on Linux only (raw TCP sockets + CAP_NET_RAW); every
// constructor fails elsewhere, the same way the raw-tier carriers do.
type PTCPClient struct{}
type PTCPServer struct{}

func NewPTCPClient(peer, srcIP, sni string, hop int) (*PTCPClient, error) {
	return nil, errors.New("the ptcp carrier needs Linux + root/CAP_NET_RAW")
}

func NewPTCPServer(port int) (*PTCPServer, error) {
	return nil, errors.New("the ptcp carrier needs Linux + root/CAP_NET_RAW")
}

func (*PTCPClient) Send([]byte, int) error               { return net.ErrClosed }
func (*PTCPClient) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*PTCPClient) SetPeer(net.Addr)                     {}
func (*PTCPClient) Close() error                         { return nil }
func (*PTCPClient) Profile() Profile                     { return Profile{MTU: 1340, InitBps: 8e6, Spread: true} }

func (*PTCPServer) Recv() ([]byte, int, net.Addr, error) { return nil, 0, nil, net.ErrClosed }
func (*PTCPServer) SendTo([]byte, int, net.Addr) error   { return net.ErrClosed }
func (*PTCPServer) Close() error                         { return nil }
func (*PTCPServer) Profile() Profile                     { return Profile{MTU: 1340, InitBps: 8e6, Spread: true} }
