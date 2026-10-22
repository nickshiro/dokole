package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"uuid"

	"kalinka/socks5"
	"kalinka/tcp"
	"kalinka/vless"

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
	OutboundVLESS  OutboundProtocol = "vless"
)

type Outbound struct {
	Protocol OutboundProtocol `json:"protocol"`
	IP       []netip.Prefix   `json:"ip"`
	Settings json.RawMessage  `json:"settings"`

	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (o *Outbound) ResolveDialer() error {
	switch o.Protocol {
	case OutboundDirect:
		var d net.Dialer
		o.dialer = d.DialContext

	case OutboundBlock:
		o.dialer = dialBlock

	case OutboundSOCKS5:
		var settings SOCKS5Settings
		if err := json.Unmarshal(o.Settings, &settings); err != nil {
			log.Printf("failed to parse socks5 outbound settings: %v", err)
			return err
		}
		auth := &proxy.Auth{
			User:     settings.Username,
			Password: settings.Password,
		}
		d, err := proxy.SOCKS5("tcp", settings.Address, auth, nil)
		if err != nil {
			log.Printf("failed to create socks5 dialer for %s: %v", settings.Address, err)
			return err
		}
		o.dialer = d.(proxy.ContextDialer).DialContext

	case OutboundVLESS:
		var settings VLESSSettings
		if err := json.Unmarshal(o.Settings, &settings); err != nil {
			log.Printf("failed to parse vless outbound settings: %v", err)
			return err
		}
		id, err := uuid.Parse(settings.ID)
		if err != nil {
			log.Printf("failed to parse vless outbound id: %v", err)
			return err
		}
		d := vless.Dialer{
			ID:      id,
			Address: settings.Address,
		}
		o.dialer = d.Dial

	default:
		return fmt.Errorf("unknown outbound %s", o.Protocol)
	}
	return nil
}

func dialBlock(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("blocked connection to %s %s", network, addr)
	return nil, errors.New("blocked")
}

type SOCKS5Settings struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type VLESSSettings struct {
	Address string `json:"address"`
	ID      string `json:"id"`
}

var config Config

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("no config provided")
	}
	configPath := os.Args[1]
	configContents, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}
	if err := json.Unmarshal(configContents, &config); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	// TODO(arkriny): maybe there should be some defaults so empty config works
	if len(config.Inbounds) == 0 {
		log.Fatalf("no inbound specified")
	}
	if len(config.Outbounds) == 0 {
		log.Fatalf("no outbound specified")
	}

	for i := range config.Outbounds {
		ob := &config.Outbounds[i]
		if err := ob.ResolveDialer(); err != nil {
			log.Fatalf("outbound %d (%s): %v", i, ob.Protocol, err)
		}
	}

	for _, ib := range config.Inbounds {
		ln, err := net.Listen("tcp", ib.Address)
		if err != nil {
			log.Fatalf("failed to listen on %s for inbound %s: %v", ib.Address, ib.Protocol, err)
		}
		switch ib.Protocol {
		case InboundTCP:
			var settings TCPSettings
			if err := json.Unmarshal(ib.Settings, &settings); err != nil {
				log.Fatalf("failed to parse tcp inbound settings: %v", err)
			}
			s := tcp.Server{
				Destination: settings.Destination,
				Dialer:      route,
			}
			go func() {
				if err := s.Serve(ln); err != nil {
					log.Printf("inbound %s on %s closed: %v", ib.Protocol, ib.Address, err)
				}
			}()

		case InboundSOCKS5:
			s := socks5.Server{
				Dialer: route,
			}
			go func() {
				if err := s.Serve(ln); err != nil {
					log.Printf("inbound %s on %s closed: %v", ib.Protocol, ib.Address, err)
				}
			}()

		default:
			log.Fatalf("unknown protocol %s", ib.Protocol)
		}
		log.Printf("started inbound %s on address %s", ib.Protocol, ib.Address)
	}
	select {}
}

func route(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("routing %s %s", network, addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("failed to split host and port in %q: %v", addr, err)
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	var ob Outbound
outer:
	for i := range config.Outbounds {
		ob = config.Outbounds[i]
		if len(ob.IP) == 0 {
			break
		}
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				log.Panicf("resolver returned invalid IP address %v", ip)
			}
			a = a.Unmap()
			for _, prefix := range ob.IP {
				if prefix.Contains(a) {
					addr = net.JoinHostPort(ip.String(), port)
					break outer
				}
			}
		}
	}
	log.Printf("dialing %s %s via outbound %s", network, addr, ob.Protocol)
	c, err := ob.dialer(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("outbound %s: %w", ob.Protocol, err)
	}
	return c, nil
}
