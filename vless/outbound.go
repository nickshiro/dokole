package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const Version byte = 0

func WriteRequest(writer io.Writer, header RequestHeader) error {
	if header.Version != Version {
		return fmt.Errorf("VLESS: unsupported version %d", header.Version)
	}
	if len(header.Addons) > 255 {
		return fmt.Errorf("VLESS: addons exceed 255 bytes")
	}
	if header.Command != CmdTCP && header.Command != CmdUDP && header.Command != CmdMux {
		return fmt.Errorf("VLESS: unsupported command %d", header.Command)
	}

	b := make([]byte, 0, 280)
	b = append(b, header.Version)
	b = append(b, header.UUID[:]...)
	b = append(b, byte(len(header.Addons)))
	b = append(b, header.Addons...)
	b = append(b, byte(header.Command))

	if header.Command != CmdMux {
		b = binary.BigEndian.AppendUint16(b, header.Port)
		switch header.Address.Type {
		case AddressIPv4:
			if !header.Address.IP.Is4() {
				return fmt.Errorf("vless: invalid IPv4 address")
			}
			ip := header.Address.IP.As4()
			b = append(b, byte(AddressIPv4))
			b = append(b, ip[:]...)
		case AddressIPv6:
			if !header.Address.IP.Is6() || header.Address.IP.Is4In6() {
				return fmt.Errorf("vless: invalid IPv6 address")
			}
			ip := header.Address.IP.As16()
			b = append(b, byte(AddressIPv6))
			b = append(b, ip[:]...)
		case AddressDomain:
			if len(header.Address.Domain) == 0 || len(header.Address.Domain) > 255 {
				return fmt.Errorf("vless: domain length must be 1..255")
			}
			b = append(b, byte(AddressDomain), byte(len(header.Address.Domain)))
			b = append(b, header.Address.Domain...)
		default:
			return fmt.Errorf("vless: unsupported address type %d", header.Address.Type)
		}
	}

	n, err := writer.Write(b)
	if err != nil {
		return err
	}

	if n != len(b) {
		return io.ErrShortWrite
	}

	return nil
}

func ReadResponse(reader io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err

	}

	if header[0] != Version {
		return fmt.Errorf("VLESS: unexpected response version %d", header[0])
	}

	_, err := io.CopyN(io.Discard, reader, int64(header[1]))
	return err
}

type Dialer struct {
	UUID    [16]byte
	Port    uint16
	Address string
}

func (d *Dialer) Dial(network string, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		target, err := ParseAddress(address)
		if err != nil {
			return nil, err
		}
		connection, err := net.Dial("tcp", d.Address)
		if err != nil {
			return nil, err
		}

		header := RequestHeader{Version: Version, UUID: d.UUID, Command: CmdTCP, Address: target, Port: d.Port}
		if err := WriteRequest(connection, header); err != nil {
			connection.Close()
			return nil, err
		}
		if err := ReadResponse(connection); err != nil {
			connection.Close()
			return nil, err
		}

		return connection, nil

	default:
		return nil, errors.New("network not implemented")
	}
}
