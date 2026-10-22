package vless

import (
	"fmt"
	"net/netip"
	"strings"
)

type Command byte

const (
	CmdTCP Command = 0x01
	CmdUDP Command = 0x02
	CmdMux Command = 0x03
)

type AddressType byte

const (
	AddressIPv4   AddressType = 0x01
	AddressDomain AddressType = 0x02
	AddressIPv6   AddressType = 0x03
)

type Address struct {
	Type   AddressType
	IP     netip.Addr
	Domain string
}

type RequestHeader struct {
	Version byte
	UUID    [16]byte
	Addons  []byte
	Command Command
	Port    uint16
	Address Address
}

func AddressFromIP(ip netip.Addr) Address {
	if ip.Is4() || ip.Is4In6() {
		return Address{Type: AddressIPv4, IP: ip.Unmap()}
	}

	return Address{Type: AddressIPv6, IP: ip}
}

func ParseAddress(address string) (Address, error) {
	if ip, err := netip.ParseAddr(address); err == nil {
		if ip.Zone() != "" {
			return Address{}, fmt.Errorf("vless: IPv6 zones are not supported")
		}
		return AddressFromIP(ip), nil
	}
	if len(address) == 0 || len(address) > 255 {
		return Address{}, fmt.Errorf("vless: domain length must be 1..255")
	}
	if strings.ContainsAny(address, ":/[] \t\r\n") {
		return Address{}, fmt.Errorf("vless: invalid address %q", address)
	}
	return Address{Type: AddressDomain, Domain: address}, nil
}
