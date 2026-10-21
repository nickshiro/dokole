package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	listenAddr = "127.0.0.1:1080"
	target     = "google.com:80"
)

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", listenAddr, err)
	}
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go forward(c, target)
	}
}

func forward(c net.Conn, target string) {
	defer c.Close()

	srv, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("connect to %s for %s: %v", target, c.RemoteAddr(), err)
		return
	}
	defer srv.Close()

	errc := make(chan error, 2)
	go func() { errc <- pump(srv, c) }()
	go func() { errc <- pump(c, srv) }()

	if err := <-errc; err != nil {
		log.Printf("relay %s: %v", c.RemoteAddr(), err)
		return
	}
	if err := <-errc; err != nil {
		log.Printf("relay %s: %v", c.RemoteAddr(), err)
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
