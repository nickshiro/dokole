package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

type TCPProxy struct {
	Destination string
}

func (s *TCPProxy) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *TCPProxy) handle(c net.Conn) {
	defer c.Close()

	srv, err := routeAndDial("tcp", s.Destination)
	if err != nil {
		return
	}
	defer srv.Close()

	errc := make(chan error, 2)
	go func() { errc <- pump(srv, c) }()
	go func() { errc <- pump(c, srv) }()

	for range cap(errc) {
		if err := <-errc; err != nil {
			log.Print(err)
			return
		}
	}
}

func pump(dst, src net.Conn) error {
	_, copyErr := io.Copy(dst, src)

	var closeErr error
	if conn, ok := dst.(interface{ CloseWrite() error }); ok {
		closeErr = conn.CloseWrite()
	}

	err := copyErr
	if err == nil {
		err = closeErr
	}
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("%s -> %s: %w", src.RemoteAddr(), dst.RemoteAddr(), err)
}
