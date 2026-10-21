package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

type Config struct {
	Inbounds []InboundConfig `json:"inbounds"`
}

type InboundConfig struct {
	Protocol string          `json:"protocol"`
	Port     int             `json:"port"`
	Settings json.RawMessage `json:"settings"`
}

type TCPSettings struct {
	Target string `json:"target"`
}

var cfg Config

const (
	listenHost = "127.0.0.1"
)

func main() {
	log.SetPrefix(os.Args[0] + ": ")
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatalf("no config provided")
	}

	if err := loadConfig(os.Args[1]); err != nil {
		log.Fatal(err)
	}

	for _, in := range cfg.Inbounds {
		switch in.Protocol {
		case "tcp":
			var settings TCPSettings
			if err := json.Unmarshal(in.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			addr := net.JoinHostPort(listenHost, strconv.Itoa(in.Port))
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatal(err)
			}
			go serve(ln, settings.Target)

		default:
			log.Fatalf("unsupported protocol %q", in.Protocol)
		}
	}
	for {
	} // main loop
}

func loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if len(cfg.Inbounds) == 0 {
		return fmt.Errorf("at least one inbound is required")
	}
	return nil
}

func serve(ln net.Listener, target string) {
	defer ln.Close()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept on %s: %v", ln.Addr(), err)
			return
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
