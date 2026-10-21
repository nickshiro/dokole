package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strconv"

	"kalinka/tcp"
)

type Config struct {
	Inbounds []InboundConfig `json:"inbounds"`
}

type InboundProtocol string

const (
	TCP InboundProtocol = "tcp"
)

type InboundConfig struct {
	Protocol InboundProtocol `json:"protocol"`
	Port     int             `json:"port"`
	Settings json.RawMessage `json:"settings"`
}

type TCPSettings struct {
	Target string `json:"target"`
}

var cfg Config

const (
	host = "127.0.0.1"
)

func main() {
	log.SetPrefix(os.Args[0] + ": ")
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatalf("no config provided")
	}
	if err := readConfig(os.Args[1]); err != nil {
		log.Fatal(err)
	}

	if len(cfg.Inbounds) == 0 {
		log.Fatal("at least one inbound is required")
	}
	for _, in := range cfg.Inbounds {
		addr := net.JoinHostPort(host, strconv.Itoa(in.Port))
		switch in.Protocol {
		case TCP:
			var settings TCPSettings
			if err := json.Unmarshal(in.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			go tcp.Proxy(settings.Target, addr)

		default:
			log.Fatalf("unsupported protocol %q", in.Protocol)
		}
	}
	select {} // main loop
}

func readConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	return nil
}
