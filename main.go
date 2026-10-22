package main

import (
	"context"
	"encoding/json"
	"errors"
	"kalinka/socks5"
	"log"
	"net"
	"net/netip"
	"os"

	"golang.org/x/net/proxy"
)

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}

type InboundProtocol string

const (
	InboundTCP    InboundProtocol = "tcp"
	InboundSOCKS5 InboundProtocol = "socks5"
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
	OutboundDirect OutboundProtocol = "direct"
	OutboundBlock  OutboundProtocol = "block"
	OutboundSOCKS5 OutboundProtocol = "socks5"
)

type Outbound struct {
	Protocol OutboundProtocol `json:"protocol"`
	IP       []netip.Prefix   `json:"ip"`
	Settings json.RawMessage  `json:"settings"`

	dialer func(network, address string) (net.Conn, error)
}

type SOCKS5Settings struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var config Config

func dialBlock(network, address string) (net.Conn, error) {
	return nil, errors.New("blocked")
}

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
	return outbound.dialer(network, address)
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

	// Resolve outbound dialers
	for i := range config.Outbounds {
		outbound := &config.Outbounds[i]
		switch outbound.Protocol {
		case OutboundDirect:
			outbound.dialer = net.Dial
		case OutboundBlock:
			outbound.dialer = dialBlock
		case OutboundSOCKS5:
			var settings SOCKS5Settings
			if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			auth := &proxy.Auth{
				User:     settings.Username,
				Password: settings.Password,
			}
			d, err := proxy.SOCKS5("tcp", settings.Address, auth, nil)
			if err != nil {
				log.Fatal(err)
			}
			outbound.dialer = d.Dial
		default:
			log.Fatalf("unknown outbound %s", outbound.Protocol)
		}
	}

	for _, in := range config.Inbounds {
		ln, err := net.Listen("tcp", in.Address)
		if err != nil {
			log.Fatal(err)
		}
		switch in.Protocol {
		case InboundTCP:
			var settings TCPSettings
			if err := json.Unmarshal(in.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			p := TCPProxy{
				Destination: settings.Destination,
			}
			go p.Serve(ln)

		case InboundSOCKS5:
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
