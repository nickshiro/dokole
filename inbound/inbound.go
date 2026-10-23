package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"uuid"

	"kalinka/socks5"
	"kalinka/tcp"
	"kalinka/vless"
)

type InboundProtocol string

const (
	TCP    InboundProtocol = "tcp"
	SOCKS5 InboundProtocol = "socks5"
	VLESS  InboundProtocol = "vless"
)

type Inbound struct {
	Protocol InboundProtocol `json:"protocol"`
	Address  string          `json:"address"`
	Settings json.RawMessage `json:"settings"`
}

type TCPSettings struct {
	Destination string `json:"destination"`
}

type VLESSSettings struct {
	Users []uuid.UUID `json:"users"`
}

type Dialer func(ctx context.Context, network string, addr string) (net.Conn, error)

func (ib *Inbound) Run(dialer Dialer) error {
	if ib.Address == "" {
		return errors.New("no address specified")
	}
	switch ib.Protocol {
	case TCP:
		ln, err := net.Listen("tcp", ib.Address)
		if err != nil {
			return err
		}

		var settings TCPSettings
		if err := json.Unmarshal(ib.Settings, &settings); err != nil {
			return fmt.Errorf("failed to parse tcp settings: %v", err)
		}
		s := tcp.Server{
			Destination: settings.Destination,
			Dialer:      dialer,
		}
		go func() {
			if err := s.Serve(ln); err != nil {
				log.Printf("inbound %s on %s closed: %v", ib.Protocol, ib.Address, err)
			}
		}()

	case SOCKS5:
		ln, err := net.Listen("tcp", ib.Address)
		if err != nil {
			return err
		}
		s := socks5.Server{
			Dialer: dialer,
		}
		go func() {
			if err := s.Serve(ln); err != nil {
				log.Printf("inbound %s on %s closed: %v", ib.Protocol, ib.Address, err)
			}
		}()

	case VLESS:
		ln, err := net.Listen("tcp", ib.Address)
		if err != nil {
			return err
		}
		var settings VLESSSettings
		if err := json.Unmarshal(ib.Settings, &settings); err != nil {
			return fmt.Errorf("failed to parse vless settings: %v", err)
		}
		s := vless.Server{
			Users:  settings.Users,
			Dialer: dialer,
		}
		go func() {
			if err := s.Serve(ln); err != nil {
				log.Printf("inbound %s on %s closed: %v", ib.Protocol, ib.Address, err)
			}
		}()

	default:
		return fmt.Errorf("unknown protocol %s", ib.Protocol)
	}
	return nil
}
