package vless

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testID = [16]byte{0: 0xAA, 1: 0xBB, 15: 0xFF}

type testServer struct {
	addr     string
	accepted atomic.Int32
}

// newServer sets up a TCP server; the handler is called for each connection.
func newServer(t *testing.T, handler func(net.Conn)) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &testServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func() {
				defer c.Close()
				handler(c)
			}()
		}
	}()
	return s
}

func wantRequest(port uint16, atyp byte, addr []byte) []byte {
	b := []byte{0}
	b = append(b, testID[:]...)
	b = append(b, 0, 0x01)
	b = binary.BigEndian.AppendUint16(b, port)
	b = append(b, atyp)
	return append(b, addr...)
}

func TestDial_WireFormat(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    []byte
	}{
		{"domain", "example.com:443", wantRequest(443, 0x02, append([]byte{11}, "example.com"...))},
		{"ipv4", "1.2.3.4:80", wantRequest(80, 0x01, []byte{1, 2, 3, 4})},
		{"ipv4-mapped", "[::ffff:1.2.3.4]:80", wantRequest(80, 0x01, []byte{1, 2, 3, 4})},
		{"ipv6", "[2001:db8::1]:8443", wantRequest(8443, 0x03,
			[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan []byte, 1)
			srv := newServer(t, func(c net.Conn) {
				buf := make([]byte, len(tt.want))
				if _, err := io.ReadFull(c, buf); err != nil {
					got <- nil
					return
				}
				got <- buf
				c.Write([]byte{0, 0}) // answer without addons
				io.Copy(c, c)         // echo
			})

			d := &Dialer{ID: testID, Address: srv.addr}
			c, err := d.Dial("tcp", tt.address)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			select {
			case b := <-got:
				if !bytes.Equal(b, tt.want) {
					t.Fatalf("request mismatch\n got: %x\nwant: %x", b, tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("server did not receive request")
			}

			// after handshake connection stay derfault strem
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != "ping" {
				t.Fatalf("echo = %q", buf)
			}
		})
	}
}

// Response header with addons and data in one package: readResponse shouldn’t consume extra
func TestDial_ResponseWithAddonsAndData(t *testing.T) {
	srv := newServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, len(wantRequest(80, 0x01, make([]byte, 4)))))
		c.Write(append([]byte{0, 3, 'x', 'y', 'z'}, "data"...))
		io.Copy(io.Discard, c)
	})

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.Dial("tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "data" {
		t.Fatalf("got %q, want %q", buf, "data")
	}
}

// In case of an invalid input, the connection to the server should not be established.
func TestDial_InvalidInput_NoConnection(t *testing.T) {
	srv := newServer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	d := &Dialer{ID: testID, Address: srv.addr}

	tests := []struct{ name, network, address string }{
		{"udp", "udp", "1.2.3.4:80"},
		{"no port", "tcp", "example.com"},
		{"port too big", "tcp", "example.com:99999"},
		{"port not number", "tcp", "example.com:abc"},
		{"negative port", "tcp", "example.com:-1"},
		{"plus port", "tcp", "example.com:+80"},
		{"empty host", "tcp", ":80"},
		{"domain too long", "tcp", strings.Repeat("a", 256) + ":80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := d.Dial(tt.network, tt.address)
			if err == nil {
				c.Close()
				t.Fatal("expected error")
			}
		})
	}

	time.Sleep(100 * time.Millisecond) // give Accept a chance to work if the connection was still established
	if n := srv.accepted.Load(); n != 0 {
		t.Fatalf("server accepted %d connections, want 0", n)
	}
}

func TestDial_ServerUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // The port is free, the connection will be rejected.

	d := &Dialer{ID: testID, Address: addr}
	// the main thing is an error, not a panic on a nil connection
	if c, err := d.Dial("tcp", "example.com:80"); err == nil {
		c.Close()
		t.Fatal("expected error")
	}
}

func TestDial_BadResponseVersion_ClosesConn(t *testing.T) {
	closed := make(chan struct{})
	srv := newServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, len(wantRequest(80, 0x01, make([]byte, 4)))))
		c.Write([]byte{1, 0}) // incorrect version
		// the client must close the connection: Read will return an error
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == io.EOF {
			close(closed)
		}
	})

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.Dial("tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// The response header is read lazily, so the bad version is reported by
	// the first Read rather than by Dial.
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected read error")
	}

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not close the connection after bad response")
	}
}

func TestDial_ServerClosesBeforeResponse(t *testing.T) {
	srv := newServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, len(wantRequest(80, 0x01, make([]byte, 4)))))
		// leaving without a response
	})

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.Dial("tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// The server closed before sending the response header; the error appears
	// on the first Read.
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected read error")
	}
}

func TestDialContext_DoesNotWaitForResponse(t *testing.T) {
	srv := newServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }) // reads but doesn’t respond

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	d := &Dialer{ID: testID, Address: srv.addr}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("DialContext took %v, it waited for the response header", el)
	}
}

// The deadline for the handshake should not be left on the completed connection.
func TestDialContext_DeadlineClearedAfterHandshake(t *testing.T) {
	srv := newServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, len(wantRequest(80, 0x01, make([]byte, 4)))))
		c.Write([]byte{0, 0})
		io.Copy(c, c)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.DialContext(ctx, "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	time.Sleep(400 * time.Millisecond) // The context deadline has already passed.

	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatalf("write after handshake deadline: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after handshake deadline: %v", err)
	}
}

func TestEncodeRequest_Errors(t *testing.T) {
	ok := addr{Type: domainName, Domain: "a.b"}
	tests := []struct {
		name string
		req  request
	}{
		{"addons too long", request{command: tcp, addr: ok, addons: make([]byte, 256)}},
		{"empty domain", request{command: tcp, addr: addr{Type: domainName}}},
		{"unknown addr type", request{command: tcp, addr: addr{Type: 0x09}}},
		{"ipv4 type with ipv6 ip", request{command: tcp, addr: addr{Type: ipv4, IP: mustAddr(t, "2001:db8::1")}}},
		{"ipv6 type with ipv4 ip", request{command: tcp, addr: addr{Type: ipv6, IP: mustAddr(t, "1.2.3.4")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := encodeRequest(&tt.req); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEncodeRequest_MuxHasNoAddress(t *testing.T) {
	b, err := encodeRequest(&request{version: version, uuid: testID, command: mux})
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + 16 + 1 + 1; len(b) != want {
		t.Fatalf("len = %d, want %d", len(b), want)
	}
	if b[len(b)-1] != byte(mux) {
		t.Fatalf("last byte = %#x, want mux", b[len(b)-1])
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in      string
		wantTyp addrType
		wantIP  string
	}{
		{"example.com", domainName, ""},
		{"1.2.3.4", ipv4, "1.2.3.4"},
		{"::ffff:1.2.3.4", ipv4, "1.2.3.4"},
		{"2001:db8::1", ipv6, "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			a, err := parseAddress(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if a.Type != tt.wantTyp {
				t.Fatalf("type = %d, want %d", a.Type, tt.wantTyp)
			}
			if tt.wantIP != "" && a.IP.String() != tt.wantIP {
				t.Fatalf("ip = %s, want %s", a.IP, tt.wantIP)
			}
		})
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
