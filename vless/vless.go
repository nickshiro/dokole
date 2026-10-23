package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const version byte = 0

type command byte

const (
	tcp command = 0x01
	udp command = 0x02
	mux command = 0x03
)

type addressType byte

const (
	ipv4       addressType = 0x01
	domainName addressType = 0x02
	ipv6       addressType = 0x03
)

type address struct {
	addrType addressType
	addr     string
	port     uint16
}

func (a address) hostPort() string {
	return net.JoinHostPort(a.addr, strconv.Itoa(int(a.port)))
}

type request struct {
	uuid   [16]byte
	addons []byte
	cmd    command
	addr   address
}

func (req *request) marshal() ([]byte, error) {
	b := make([]byte, 0, 24+len(req.addons)+len(req.addr.addr))
	b = append(b, version)
	b = append(b, req.uuid[:]...)
	b = append(b, byte(len(req.addons)))
	b = append(b, req.addons...)
	b = append(b, byte(req.cmd))

	if req.cmd == mux {
		return b, nil
	}

	b = binary.BigEndian.AppendUint16(b, req.addr.port)
	switch req.addr.addrType {
	case ipv4:
		ip := net.ParseIP(req.addr.addr).To4()
		if ip == nil {
			return nil, errors.New("vless: invalid IPv4 address")
		}
		b = append(b, byte(ipv4))
		b = append(b, ip[:]...)

	case ipv6:
		ip := net.ParseIP(req.addr.addr).To16()
		if ip == nil {
			return nil, errors.New("vless: invalid IPv6 address")
		}
		b = append(b, byte(ipv6))
		b = append(b, ip[:]...)

	case domainName:
		if n := len(req.addr.addr); n == 0 || n > 255 {
			return nil, errors.New("vless: domain length must be 1..255")
		}
		b = append(b, byte(domainName), byte(len(req.addr.addr)))
		b = append(b, req.addr.addr...)

	default:
		return nil, fmt.Errorf("vless: unsupported address type %d", req.addr.addrType)
	}
	return b, nil
}

func getAddressType(addr string) addressType {
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			return ipv4
		}
		return ipv6
	}
	return domainName
}
