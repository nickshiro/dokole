package vless

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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
	var cmd command

	switch network {
	case "tcp", "tcp4", "tcp6":
		cmd = tcp
	case "udp", "udp4", "udp6":
		cmd = udp
	default:
		return nil, errors.New("vless: network not implemented: " + network)
	}

	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	req := request{
		uuid: d.ID,
		cmd:  cmd,
		addr: address{addrType: getAddressType(host), addr: host, port: port},
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
	c.SetDeadline(time.Time{})

	conn := &Conn{Conn: c}
	if cmd == udp {
		return &UdpConn{Conn: conn}, nil
	}
	return conn, nil
}

// Conn is a proxied VLESS connection.
type Conn struct {
	net.Conn

	readMu       sync.Mutex
	responseRead bool
	responseErr  error
}

type UdpConn struct {
	*Conn
	writeMu sync.Mutex
}

func (c *Conn) ensureResponse() error {
	if !c.responseRead {
		c.responseRead = true
		c.responseErr = readResponse(c.Conn)
		if c.responseErr != nil {
			c.Conn.Close()
		}
	}
	return c.responseErr
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.ensureResponse(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *UdpConn) Write(p []byte) (int, error) {
	if len(p) > math.MaxUint16 {
		return 0, errors.New("vless: datagram too large")
	}

	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.Conn.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UdpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.ensureResponse(); err != nil {
		return 0, err
	}

	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn.Conn, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))

	if n <= len(p) {
		if _, err := io.ReadFull(c.Conn.Conn, p[:n]); err != nil {
			return 0, err
		}
		return n, nil
	}

	if _, err := io.ReadFull(c.Conn.Conn, p); err != nil {
		return 0, err
	}
	if _, err := io.CopyN(io.Discard, c.Conn.Conn, int64(n-len(p))); err != nil {
		return 0, err
	}
	return len(p), nil
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
