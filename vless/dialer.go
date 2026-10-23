package vless

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Dialer struct {
	ID      [16]byte
	Address string

	// Dialer optionally specifies the dialer to use for outgoing connections.
	// If nil, the net package's standard dialer is used.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *Dialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := d.Dialer
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	return dial(ctx, network, addr)
}

func (d *Dialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, err
		}
		a := address{
			addrType: getAddressType(addr),
			addr:     host,
			port:     port,
		}
		req := request{
			uuid: d.ID,
			cmd:  tcp,
			addr: a,
		}
		reqb, err := req.marshal()
		if err != nil {
			return nil, err
		}

		c, err := d.dial(ctx, "tcp", d.Address)
		if err != nil {
			return nil, err
		}

		if dl, ok := ctx.Deadline(); ok {
			c.SetDeadline(dl)
		}
		if _, err := c.Write(reqb); err != nil {
			c.Close()
			return nil, err
		}
		// Do not wait for the response header here. Server may keep that header
		// buffered until the destination sends data, so waiting for it would
		// deadlock protocols in which the client sends the first bytes.
		c.SetDeadline(time.Time{})

		return &Conn{Conn: c}, nil

	default:
		return nil, errors.New("vless: network not implemented: " + network)
	}
}

// Conn is a proxied VLESS connection.
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

func getAddressType(addr string) addressType {
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			return ipv4
		}
		return ipv6
	}
	return domainName
}

/*
func parseAddress(address string) (addr, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return addr{
			typ:    domainName,
			host: address,
			port:   port,
		}, nil
	}
	if ip.Is4() || ip.Is4In6() {
		return addr{
			typ:  ipv4,
			host:   ip.Unmap(),
			port: port,
		}, nil
	}
	return addr{
		typ:  ipv6,
		ip:   ip,
		port: port,
	}, nil
}
*/
