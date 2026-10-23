package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"uuid"

	"kalinka/vless"

	"golang.org/x/net/proxy"
)

type Protocol string

const (
	Direct Protocol = "direct"
	Block  Protocol = "block"
	SOCKS5 Protocol = "socks5"
	VLESS  Protocol = "vless"
)

type SOCKS5Settings struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type VLESSSettings struct {
	Address string `json:"address"`
	ID      string `json:"id"`
}

type Outbound struct {
	Protocol Protocol        `json:"protocol"`
	IP       []netip.Prefix  `json:"ip"`
	Settings json.RawMessage `json:"settings"`

	Dialer Dialer `json:"-"`
}

type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

func (o *Outbound) ResolveDialer() error {
	switch o.Protocol {
	case Direct:
		var d net.Dialer
		o.Dialer = d.DialContext

	case Block:
		o.Dialer = dialBlock

	case SOCKS5:
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
		o.Dialer = d.(proxy.ContextDialer).DialContext

	case VLESS:
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
		o.Dialer = d.Dial

	default:
		return fmt.Errorf("unknown outbound %s", o.Protocol)
	}
	return nil
}

func dialBlock(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("blocked connection to %s %s", network, addr)
	return nil, errors.New("blocked")
}
