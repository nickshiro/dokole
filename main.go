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

	dialer func(ctx context.Context, network, address string) (net.Conn, error)
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
			return err
		}
		auth := &proxy.Auth{
			User:     settings.Username,
			Password: settings.Password,
		}
		d, err := proxy.SOCKS5("tcp", settings.Address, auth, nil)
		if err != nil {
			return err
		}
		o.dialer = d.(proxy.ContextDialer).DialContext

	case OutboundVLESS:
		var settings VLESSSettings
		if err := json.Unmarshal(o.Settings, &settings); err != nil {
			log.Fatal(err)
		}
		id, err := uuid.Parse(settings.ID)
		if err != nil {
			log.Fatal(err)
		}

		d := vless.Dialer{
			ID:      id,
			Address: settings.Address,
		}
		o.dialer = d.DialContext

	default:
		return fmt.Errorf("unknown outbound %s", o.Protocol)
	}
	return nil
}

func dialBlock(ctx context.Context, network, address string) (net.Conn, error) {
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
	configContents, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(configContents, &config); err != nil {
		log.Fatal(err)
	}

	// TODO(arkriny): maybe there should be some defaults so empty config works
	if len(config.Inbounds) == 0 {
		log.Fatal("no inbound specified")
	}
	if len(config.Outbounds) == 0 {
		log.Fatal("no outbound specified")
	}

	for i := range config.Outbounds {
		if err := config.Outbounds[i].ResolveDialer(); err != nil {
			log.Fatal(err)
		}
	}

	for _, ib := range config.Inbounds {
		ln, err := net.Listen("tcp", ib.Address)
		if err != nil {
			log.Fatal(err)
		}
		switch ib.Protocol {
		case InboundTCP:
			var settings TCPSettings
			if err := json.Unmarshal(ib.Settings, &settings); err != nil {
				log.Fatal(err)
			}
			s := tcp.Server{
				Destination: settings.Destination,
				Dialer:      routeAndDial,
			}
			go s.Serve(ln)

		case InboundSOCKS5:
			s := socks5.Server{
				Dialer: routeAndDial,
			}
			go s.Serve(ln)

		default:
			log.Fatalf("unknown protocol %s", ib.Protocol)
		}
	}
	select {}
}

func routeAndDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
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
				panic("netip.AddrFromSlice(ip)")
			}
			a = a.Unmap()
			for _, prefix := range ob.IP {
				if prefix.Contains(a) {
					address = net.JoinHostPort(ip.String(), port)
					break outer
				}
			}
		}
	}
	return ob.dialer(ctx, network, address)
}
