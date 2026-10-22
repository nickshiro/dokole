package tcp

import (
	"context"
	"io"
	"log"
	"net"
)

// Server is a TCP proxy server.
type Server struct {
	// Destination address to which packets are proxied.
	Destination string

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
		log.Printf("tcp: %s: accepted", c.RemoteAddr())
		go s.proxy(c)
	}
}

func (s *Server) proxy(c net.Conn) {
	defer c.Close()

	// TODO(arkriny): use timeout.
	ctx := context.Background()
	srv, err := s.dial(ctx, "tcp", s.Destination)
	if err != nil {
		log.Printf("tcp: %s: %v", c.RemoteAddr(), err)
		return
	}
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		n, err := io.Copy(srv, c)
		if err != nil {
			log.Printf("tcp: %s: copy to %s failed after %d bytes: %v",
				c.RemoteAddr(), s.Destination, n, err)
		}
		srv.(*net.TCPConn).CloseWrite()
		close(done)
	}()

	n, err := io.Copy(c, srv)
	if err != nil {
		log.Printf("tcp: %s: copy from %s failed after %d bytes: %v",
			c.RemoteAddr(), s.Destination, n, err)
	}
	c.(*net.TCPConn).CloseWrite()
	<-done
}
