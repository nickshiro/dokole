package vless

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
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

// startInbound runs srv on a loopback listener and returns its address.
func startInbound(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		srv.Serve(ln)
	}()
	t.Cleanup(func() {
		ln.Close()
		<-stopped
	})
	return ln.Addr().String()
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
			c, err := d.Dial(t.Context(), "tcp", tt.address)
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

			// After the handshake the connection carries a plain byte stream.
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

func TestDial_InboundBidirectional(t *testing.T) {
	for _, serverFirst := range []bool{false, true} {
		name := "client-first"
		if serverFirst {
			name = "server-first"
		}
		t.Run(name, func(t *testing.T) {
			accepted := make(chan net.Conn, 1)
			release := make(chan struct{})
			defer close(release)
			destination := newServer(t, func(c net.Conn) {
				accepted <- c
				<-release
			})

			address := startInbound(t, &Server{
				Destination: destination.addr,
				Users:       map[[16]byte]struct{}{testID: {}},
			})

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			outbound := &Dialer{ID: testID, Address: address}
			// The address in the request must be ignored: the real
			// destination can only come from Server.Destination.
			client, err := outbound.Dial(ctx, "tcp", "ignored.invalid:1")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			var server net.Conn
			select {
			case server = <-accepted:
			case <-ctx.Done():
				t.Fatal("inbound did not connect to the destination:", ctx.Err())
			}
			defer server.Close()
			for _, c := range []net.Conn{client, server} {
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}

			transfer := func(from, to net.Conn, payload string) {
				t.Helper()
				written := make(chan error, 1)
				go func() {
					_, err := io.Copy(from, strings.NewReader(payload))
					written <- err
				}()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(to, got); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if string(got) != payload {
					t.Fatal("forwarded payload mismatch")
				}
			}

			if serverFirst {
				transfer(server, client, "server greeting")
			}
			transfer(client, server, "client request")
			transfer(server, client, "server response")
			// Repeated writes must not insert another VLESS header.
			transfer(client, server, strings.Repeat("upload\x00", 16*1024))
			transfer(server, client, strings.Repeat("download\xff", 16*1024))
		})
	}
}

// The client half-closes its write side; the destination sees EOF and can
// still answer. This goes through both CloseWrite implementations.
func TestDial_HalfClose(t *testing.T) {
	tests := []struct {
		name  string
		reply string // what the destination sends back after EOF
	}{
		{"destination replies", "got:hello"},
		// The destination closes without sending anything: the inbound must
		// still deliver the response header, otherwise the client would fail
		// inside the header read instead of seeing a clean EOF.
		{"destination silent", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destination := newServer(t, func(c net.Conn) {
				b, _ := io.ReadAll(c) // returns once the client closes its write side
				if tt.reply != "" {
					c.Write([]byte("got:" + string(b)))
				}
			})
			address := startInbound(t, &Server{
				Destination: destination.addr,
				Users:       map[[16]byte]struct{}{testID: {}},
			})

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, err := (&Dialer{ID: testID, Address: address}).Dial(ctx, "tcp", "ignored.invalid:1")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if err := client.(*Conn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.reply {
				t.Fatalf("got %q, want %q", got, tt.reply)
			}
		})
	}
}

// The inbound must close without replying and without dialing upstream.
func TestServer_RejectsSilently(t *testing.T) {
	good := request{
		uuid:    testID,
		command: tcp,
		addr:    addr{typ: domainName, domain: "x.test"},
		port:    80,
	}
	tests := []struct {
		name   string
		mutate func(*request)
	}{
		{"unknown user", func(r *request) { r.uuid[0] ^= 0xFF }},
		{"udp", func(r *request) { r.command = udp }},
		{"mux", func(r *request) { r.command = mux }},
		{"addons", func(r *request) { r.addons = []byte{0x0a, 0x00} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dials atomic.Int32
			address := startInbound(t, &Server{
				Destination: "unused:1",
				Users:       map[[16]byte]struct{}{testID: {}},
				Dialer: func(ctx context.Context, network, a string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("unexpected dial")
				},
			})

			req := good
			tt.mutate(&req)
			b, err := req.marshal()
			if err != nil {
				t.Fatal(err)
			}
			c, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write(b)

			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := c.Read(make([]byte, 16))
			// The server must close without sending a byte. EOF and reset are
			// both fine (unread request bytes make the kernel send RST), but
			// neither data nor a timeout is.
			if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read = %d, %v; want 0 bytes and a close", n, err)
			}
			if d := dials.Load(); d != 0 {
				t.Fatalf("server dialed upstream %d times, want 0", d)
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
	c, err := d.Dial(t.Context(), "tcp", "1.2.3.4:80")
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
			c, err := d.Dial(t.Context(), tt.network, tt.address)
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
	if c, err := d.Dial(t.Context(), "tcp", "example.com:80"); err == nil {
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
	c, err := d.Dial(t.Context(), "tcp", "1.2.3.4:80")
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
	c, err := d.Dial(t.Context(), "tcp", "1.2.3.4:80")
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

// Dial must return without waiting for the response header: if it did, it
// would fail on the context deadline since this server never responds.
func TestDial_DoesNotWaitForResponse(t *testing.T) {
	srv := newServer(t, func(c net.Conn) { io.Copy(io.Discard, c) }) // reads but doesn’t respond

	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.Dial(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// The deadline for the handshake should not be left on the completed connection.
func TestDial_DeadlineClearedAfterHandshake(t *testing.T) {
	srv := newServer(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, len(wantRequest(80, 0x01, make([]byte, 4)))))
		c.Write([]byte{0, 0})
		io.Copy(c, c)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	d := &Dialer{ID: testID, Address: srv.addr}
	c, err := d.Dial(ctx, "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	time.Sleep(150 * time.Millisecond) // The context deadline has already passed.

	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatalf("write after handshake deadline: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after handshake deadline: %v", err)
	}
}

func TestEncodeRequest_MuxHasNoAddress(t *testing.T) {
	req := request{
		uuid:    testID,
		command: mux,
	}
	b, err := req.marshal()
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
			if a.typ != tt.wantTyp {
				t.Fatalf("type = %d, want %d", a.typ, tt.wantTyp)
			}
			if tt.wantIP != "" && a.ip.String() != tt.wantIP {
				t.Fatalf("ip = %s, want %s", a.ip, tt.wantIP)
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

// CloseWrite half-closes the write side if the underlying connection supports
// it, so the peer sees EOF while the response can still be read.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}
