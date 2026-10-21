package main

import (
	"context"
	"encoding/json"
	"kalinka/socks5"
	"log"
	"net"
	"net/netip"
	"os"
)

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type InboundProtocol string

const (
	TCP    InboundProtocol = "tcp"
	SOCKS5 InboundProtocol = "socks5"
)

type Inbound struct {
	Protocol InboundProtocol `json:"protocol"`
	Address  string          `json:"address"`
	Settings json.RawMessage `json:"settings"`
}

type TCPSettings struct {
	Destination string `json:"destination"`
}

type OutboundProtocol string

const (
	Direct OutboundProtocol = "direct"
	Block  OutboundProtocol = "block"
)

type Outbound struct {
	Protocol OutboundProtocol `json:"protocol"`
	IP       []netip.Prefix   `json:"ip"`
}

var config Config

func routeAndDial(network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var outbound Outbound
outer:
	for i := 0; i < len(config.Outbounds); i++ {
		outbound = config.Outbounds[i]
		if len(outbound.IP) == 0 {
			break
		}
		for _, ip := range ips {
			aip, ok := netip.AddrFromSlice(ip)
			if !ok {
				panic("netip.AddrFromSlice(ip)")
			}
			aip = aip.Unmap()
			for _, prefix := range outbound.IP {
				if prefix.Contains(aip) {
					address = net.JoinHostPort(ip.String(), port)
					break outer
				}
			}
		}
	}
	dial, ok := outboundDial[outbound.Protocol]
	if !ok {
		panic(outbound.Protocol)
	}
	return dial(network, address)
}

func main() {
	log.SetPrefix(os.Args[0] + ": ")
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatalf("no config provided")
	}
	contents, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(contents, &config); err != nil {
		log.Fatal(err)
	}

	// TODO(arkriny): maybe there should be some defaults so empty config works
	if len(config.Inbounds) == 0 {
		log.Fatal("no inbound specified")
	}
	if len(config.Outbounds) == 0 {
		log.Fatal("no outbound specified")
	}

	for _, in := range config.Inbounds {
		ln, err := net.Listen("tcp", in.Address)
		if err != nil {
			log.Fatal(err)
		}
		switch in.Protocol {
		case TCP:
			var settings TCPSettings
			if err := json.Unmarshal(in.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			p := TCPProxy{
				Destination: settings.Destination,
			}
			go p.Serve(ln)

		case SOCKS5:
			s := socks5.Server{
				Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
					return routeAndDial(network, address)
				},
			}
			go s.Serve(ln)

		default:
			log.Fatalf("unknown protocol %s", in.Protocol)
		}
	}
	select {} // main loop
}
