package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// dnsServfail constructs a minimal RFC 1035 Server Failure (RCODE 2) response for query.
func dnsServfail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81 // QR=1 (response), RD=1 (recursion desired)
	resp[3] = 0x82 // RA=1 (recursion available), RCODE=2 (server failure)
	// Zero out answer, authority, and additional counts; keep question count
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0
	return resp
}

// maxInflightDNS bounds concurrent relayed queries to prevent goroutine storms under flood.
const maxInflightDNS = 128

// startDNSListener starts a local UDP and TCP DNS listener that forwards all queries through the tunnel's
// internal DNS relay (server target port 53). This allows client operating systems and applications
// to resolve external DNS records during severe censorship blackouts when domestic resolvers hijack UDP 53.
func startDNSListener(listenAddr string, getTun func() *tunnel, logf func(string, ...any)) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		if logf != nil {
			logf("dns-listen: tcp listen on %s failed: %v (udp only)", pc.LocalAddr().String(), err)
		}
	}
	if logf != nil {
		if ln != nil {
			logf("dns-listen: listening on %s (udp+tcp, forwarding queries via tunnel DNS relay)", pc.LocalAddr().String())
		} else {
			logf("dns-listen: listening on %s (udp, forwarding queries via tunnel DNS relay)", pc.LocalAddr().String())
		}
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	sem := make(chan struct{}, maxInflightDNS)

	closer := &dnsListenerCloser{
		pc:   pc,
		ln:   ln,
		done: done,
		wg:   &wg,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// one byte over the cap: a datagram larger than 4096 is truncated to exactly 4096 by the kernel,
		// and relaying a cut query corrupts it — the extra byte makes truncation observable (audit 2026-10-21)
		buf := make([]byte, maxDNSMsgLen+1)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					if errors.Is(err, net.ErrClosed) {
						return
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			if n < 12 || n > maxDNSMsgLen {
				continue
			}
			query := make([]byte, n)
			copy(query, buf[:n])

			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func(q []byte, from net.Addr) {
					defer wg.Done()
					defer func() { <-sem }()
					tun := getTun()
					ans, err := dialDNSRelay(tun, q)
					if err != nil || len(ans) < 12 {
						if sf := dnsServfail(q); sf != nil {
							_, _ = pc.WriteTo(sf, from)
						}
						return
					}
					_, _ = pc.WriteTo(ans, from)
				}(query, src)
			default:
				// Congested / throttled: immediately return SERVFAIL so client doesn't stall
				if sf := dnsServfail(query); sf != nil {
					_, _ = pc.WriteTo(sf, src)
				}
			}
		}
	}()

	if ln != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-done:
						return
					default:
						if errors.Is(err, net.ErrClosed) {
							return
						}
						time.Sleep(10 * time.Millisecond)
						continue
					}
				}
				closer.conns.Store(conn, struct{}{})
				wg.Add(1)
				go func(c net.Conn) {
					defer wg.Done()
					defer closer.conns.Delete(c)
					defer c.Close()
					writeResp := func(data []byte) error {
						_ = c.SetWriteDeadline(time.Now().Add(dnsRelayTimeout))
						hdr := [2]byte{byte(len(data) >> 8), byte(len(data))}
						if _, err := c.Write(hdr[:]); err != nil {
							return err
						}
						_, err := c.Write(data)
						return err
					}
					for {
						_ = c.SetDeadline(time.Now().Add(dnsRelayTimeout))
						var qlen [2]byte
						if _, err := io.ReadFull(c, qlen[:]); err != nil {
							return
						}
						n := int(qlen[0])<<8 | int(qlen[1])
						if n < 12 || n > maxDNSMsgLen {
							return
						}
						query := make([]byte, n)
						if _, err := io.ReadFull(c, query); err != nil {
							return
						}
						var werr error
						select {
						case sem <- struct{}{}:
							func() {
								defer func() { <-sem }()
								tun := getTun()
								ans, err := dialDNSRelay(tun, query)
								if err != nil || len(ans) < 12 {
									if sf := dnsServfail(query); sf != nil {
										werr = writeResp(sf)
									}
									return
								}
								werr = writeResp(ans)
							}()
						default:
							if sf := dnsServfail(query); sf != nil {
								werr = writeResp(sf)
							}
						}
						if werr != nil {
							return
						}
					}
				}(conn)
			}
		}()
	}

	return closer, nil
}

type dnsListenerCloser struct {
	pc    net.PacketConn
	ln    net.Listener
	done  chan struct{}
	wg    *sync.WaitGroup
	conns sync.Map
	once  sync.Once
}

func (c *dnsListenerCloser) Close() error {
	c.once.Do(func() {
		close(c.done)
		if c.pc != nil {
			_ = c.pc.Close()
		}
		if c.ln != nil {
			_ = c.ln.Close()
		}
		c.conns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
		c.wg.Wait()
	})
	return nil
}
