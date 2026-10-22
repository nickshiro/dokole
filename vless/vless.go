package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type Dialer struct {
	ID      [16]byte
	Address string
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, port, err := splitHostPort(address)
		if err != nil {
			return nil, err
		}
		target, err := parseAddress(host)
		if err != nil {
			return nil, err
		}
		req, err := encodeRequest(&request{
			version: version,
			uuid:    d.ID,
			command: tcp,
			addr:    target,
			port:    port,
		})
		if err != nil {
			return nil, err
		}

		var nd net.Dialer
		c, err := nd.DialContext(ctx, "tcp", d.Address)
		if err != nil {
			return nil, err
		}

		if dl, ok := ctx.Deadline(); ok {
			c.SetDeadline(dl)
		}
		if _, err := c.Write(req); err != nil {
			c.Close()
			return nil, err
		}
		// Do not wait for the response header here. Xray keeps that header
		// buffered until the destination sends data, so waiting for it would
		// deadlock protocols in which the client sends the first bytes.
		c.SetDeadline(time.Time{})

		return &Conn{Conn: c}, nil

	default:
		return nil, errors.New("vless: network not implemented: " + network)
	}
}

// Conn is a proxied VLESS connection. The VLESS response header is read by the
// first call to Read, because the server may not send it until the destination
// has data to return.
type Conn struct {
	net.Conn

	readMu       sync.Mutex
	responseRead bool
	responseErr  error
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if !c.responseRead {
		c.responseRead = true
		c.responseErr = readResponse(c.Conn)
		if c.responseErr != nil {
			c.Conn.Close()
		}
	}
	if c.responseErr != nil {
		return 0, c.responseErr
	}
	return c.Conn.Read(p)
}

const version byte = 0

type command byte

const (
	tcp command = 0x01
	udp command = 0x02
	mux command = 0x03
)

type addrType byte

const (
	ipv4       addrType = 0x01
	domainName addrType = 0x02
	ipv6       addrType = 0x03
)

type addr struct {
	Type   addrType
	IP     netip.Addr
	Domain string
}

type request struct {
	version byte
	uuid    [16]byte
	addons  []byte
	command command
	port    uint16
	addr    addr
}

func encodeRequest(req *request) ([]byte, error) {
	if len(req.addons) > 255 {
		return nil, errors.New("vless: addons too long")
	}

	b := make([]byte, 0, 24+len(req.addons)+len(req.addr.Domain))
	b = append(b, req.version)
	b = append(b, req.uuid[:]...)
	b = append(b, byte(len(req.addons)))
	b = append(b, req.addons...)
	b = append(b, byte(req.command))

	if req.command == mux {
		return b, nil
	}

	b = binary.BigEndian.AppendUint16(b, req.port)
	switch req.addr.Type {
	case ipv4:
		if !req.addr.IP.Is4() {
			return nil, errors.New("vless: invalid IPv4 address")
		}
		ip := req.addr.IP.As4()
		b = append(b, byte(ipv4))
		b = append(b, ip[:]...)
	case ipv6:
		if !req.addr.IP.Is6() || req.addr.IP.Is4In6() {
			return nil, errors.New("vless: invalid IPv6 address")
		}
		ip := req.addr.IP.As16()
		b = append(b, byte(ipv6))
		b = append(b, ip[:]...)
	case domainName:
		if n := len(req.addr.Domain); n == 0 || n > 255 {
			return nil, errors.New("vless: domain length must be 1..255")
		}
		b = append(b, byte(domainName), byte(len(req.addr.Domain)))
		b = append(b, req.addr.Domain...)
	default:
		return nil, fmt.Errorf("vless: unsupported address type %d", req.addr.Type)
	}
	return b, nil
}

func readResponse(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}

	if header[0] != version {
		return fmt.Errorf("vless: unexpected response version %d", header[0])
	}

	_, err := io.CopyN(io.Discard, r, int64(header[1]))
	return err
}

func splitHostPort(hostport string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("vless: invalid port %q", portStr)
	}
	return host, uint16(port), nil
}

func parseAddress(address string) (addr, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return addr{Type: domainName, Domain: address}, nil
	}
	if ip.Is4() || ip.Is4In6() {
		return addr{Type: ipv4, IP: ip.Unmap()}, nil
	}
	return addr{Type: ipv6, IP: ip}, nil
}
