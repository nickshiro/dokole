package tcp

import (
	"errors"
	"fmt"
	"io"
	"net"
)

func Proxy(dest, src string) error {
	ln, err := net.Listen("tcp", src)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handle(c, dest)
	}
}

func handle(c net.Conn, dest string) {
	defer c.Close()

	srv, err := net.Dial("tcp", dest)
	if err != nil {
		return
	}
	defer srv.Close()

	errc := make(chan error, 2)
	go func() { errc <- pump(srv, c) }()
	go func() { errc <- pump(c, srv) }()

	if err := <-errc; err != nil {
		return
	}
	<-errc
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
