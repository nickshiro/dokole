package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const version byte = 0

const (
	tcp byte = 0x01
	udp byte = 0x02
	mux byte = 0x03
)

type addrType byte

const (
	ipv4       addrType = 0x01
	domainName addrType = 0x02
	ipv6       addrType = 0x03
)

type addr struct {
	typ    addrType
	ip     netip.Addr
	domain string
}

type request struct {
	uuid    [16]byte
	addons  []byte
	command byte
	port    uint16
	addr    addr
}

func (req *request) marshal() ([]byte, error) {
	if len(req.addons) > 255 {
		return nil, errors.New("vless: addons too long")
	}

	b := make([]byte, 0, 24+len(req.addons)+len(req.addr.domain))
	b = append(b, version)
	b = append(b, req.uuid[:]...)
	b = append(b, byte(len(req.addons)))
	b = append(b, req.addons...)
	b = append(b, byte(req.command))

	if req.command == mux {
		return b, nil
	}

	b = binary.BigEndian.AppendUint16(b, req.port)
	switch req.addr.typ {
	case ipv4:
		if !req.addr.ip.Is4() {
			return nil, errors.New("vless: invalid IPv4 address")
		}
		ip := req.addr.ip.As4()
		b = append(b, byte(ipv4))
		b = append(b, ip[:]...)

	case ipv6:
		if !req.addr.ip.Is6() || req.addr.ip.Is4In6() {
			return nil, errors.New("vless: invalid IPv6 address")
		}
		ip := req.addr.ip.As16()
		b = append(b, byte(ipv6))
		b = append(b, ip[:]...)

	case domainName:
		if n := len(req.addr.domain); n == 0 || n > 255 {
			return nil, errors.New("vless: domain length must be 1..255")
		}
		b = append(b, byte(domainName), byte(len(req.addr.domain)))
		b = append(b, req.addr.domain...)

	default:
		return nil, fmt.Errorf("vless: unsupported address type %d", req.addr.typ)
	}
	return b, nil
}
