package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 10 * time.Second
)

// Server is a VLESS inbound.
type Server struct {
	// Destination address to which packets are proxied.
	Destination string

	// Users is the set of allowed UUIDs. It must not be modified after Serve
	// has been called.
	Users map[[16]byte]struct{}

	// Dialer optionally specifies the dialer to use for outgoing connections.
	// If nil, the net package's standard dialer is used.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := s.Dialer
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return dial(ctx, network, addr)
}

func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		log.Printf("vless: %s: accepted", c.RemoteAddr())
		go s.proxy(c)
	}
}

func (s *Server) proxy(c net.Conn) {
	defer c.Close()

	// On any handshake failure we only close: a prober gets no reply.
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	req, err := readRequest(c)
	if err != nil {
		log.Printf("vless: %s: bad request: %v", c.RemoteAddr(), err)
		return
	}
	if _, ok := s.Users[req.uuid]; !ok {
		log.Printf("vless: %s: unknown user", c.RemoteAddr())
		return
	}
	if len(req.addons) != 0 {
		log.Printf("vless: %s: addons not supported", c.RemoteAddr())
		return
	}
	if req.command != tcp {
		log.Printf("vless: %s: command %d not implemented", c.RemoteAddr(), req.command)
		return
	}
	c.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	srv, err := s.dial(ctx, "tcp", s.Destination)
	if err != nil {
		log.Printf("vless: %s: %v", c.RemoteAddr(), err)
		return
	}
	defer srv.Close()

	// vc adds the VLESS response header to the first write towards the client.
	vc := &serverConn{Conn: c}

	done := make(chan struct{})
	go func() {
		n, err := io.Copy(srv, c)
		if err != nil {
			log.Printf("vless: %s: copy to %s failed after %d bytes: %v",
				c.RemoteAddr(), s.Destination, n, err)
		}
		closeWrite(srv)
		close(done)
	}()

	n, err := io.Copy(vc, srv)
	if err != nil {
		log.Printf("vless: %s: copy from %s failed after %d bytes: %v",
			c.RemoteAddr(), s.Destination, n, err)
	}
	vc.CloseWrite()
	<-done
}

// closeWrite half-closes c, or closes it fully if it cannot half-close.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// serverConn prepends the VLESS response header to the first Write,
// so the header and the first payload leave in one segment.
type serverConn struct {
	net.Conn

	writeMu    sync.Mutex
	headerSent bool
}

func (c *serverConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.headerSent {
		return c.Conn.Write(p)
	}
	c.headerSent = true

	buf := make([]byte, 0, 2+len(p))
	buf = append(buf, version, 0) // version, addons length
	buf = append(buf, p...)

	n, err := c.Conn.Write(buf)
	if n -= 2; n < 0 {
		n = 0
	}
	return n, err
}

// CloseWrite sends the response header if nothing was written yet
// (the client is waiting for it), then half-closes the connection.
func (c *serverConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.headerSent {
		c.headerSent = true
		if _, err := c.Conn.Write([]byte{version, 0}); err != nil {
			return err
		}
	}
	closeWrite(c.Conn)
	return nil
}

func readRequest(r io.Reader) (*request, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, err
	}
	/*
		var h [18]byte // version, uuid, addons length
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
	*/
	if ver[0] != version {
		return nil, fmt.Errorf("vless: unexpected request version %d", ver[0])
	}

	req := new(request)

	if _, err := io.ReadFull(r, req.uuid[:]); err != nil {
		return nil, err
	}

	var addonsLength [1]byte
	if _, err := io.ReadFull(r, addonsLength[:]); err != nil {
		return nil, err
	}

	if n := int(addonsLength[0]); n > 0 {
		req.addons = make([]byte, n)
		if _, err := io.ReadFull(r, req.addons); err != nil {
			return nil, err
		}
	}

	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, err
	}
	req.command = cmd[0]
	if req.command == mux {
		return req, nil
	}

	var port [3]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	req.port = binary.BigEndian.Uint16(port[:2])

	switch t := addrType(port[2]); t {
	case ipv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return nil, err
		}
		req.addr = addr{typ: ipv4, ip: netip.AddrFrom4(a)}
	case ipv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return nil, err
		}
		req.addr = addr{typ: ipv6, ip: netip.AddrFrom16(a)}
	case domainName:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		if l[0] == 0 {
			return nil, errors.New("vless: empty domain")
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(r, d); err != nil {
			return nil, err
		}
		req.addr = addr{typ: domainName, domain: string(d)}
	default:
		return nil, fmt.Errorf("vless: unsupported address type %d", t)
	}
	return req, nil
}
