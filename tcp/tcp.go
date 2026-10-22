package tcp

import (
	"context"
	"io"
	"net"
)

// Server is a TCP proxy server.
type Server struct {
	// Destination address to which packets are proxied to.
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
		go s.proxy(c)
	}
}

func (s *Server) proxy(c net.Conn) {
	defer c.Close()

	ctx := context.Background()
	srv, err := s.dial(ctx, "tcp", s.Destination)
	if err != nil {
		return
	}
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(srv, c)
		srv.(*net.TCPConn).CloseWrite()
		close(done)
	}()

	io.Copy(c, srv)
	c.(*net.TCPConn).CloseWrite()
	<-done
}
