package vless

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPRequestWireFormat(t *testing.T) {
	var id [16]byte
	for i := range id {
		id[i] = byte(i)
	}
	var got bytes.Buffer
	h := RequestHeader{Version: 0, UUID: id, Command: CmdTCP, Port: 443, Address: Address{Type: AddressDomain, Domain: "example.org"}}
	if err := WriteRequest(&got, h); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0}, id[:]...)
	want = append(want, 0, 1, 1, 187, 2, 11)
	want = append(want, []byte("example.org")...)
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("request = %x, want %x", got.Bytes(), want)
	}
}

func TestReadResponsePreservesPayload(t *testing.T) {
	r := bytes.NewReader([]byte{0, 2, 0xaa, 0xbb, 'o', 'k'})
	if err := ReadResponse(r); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "ok" {
		t.Fatalf("payload = %q", b)
	}
}

func TestDialTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		server, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer server.Close()
		if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		b := make([]byte, 30)
		if _, err := io.ReadFull(server, b); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(b[18:], []byte{1, 0, 80, 2, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}) {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = server.Write([]byte{0, 0, 'h', 'i'})
		done <- err
	}()
	dialer := Dialer{Address: listener.Addr().String(), Port: 80}
	conn, err := dialer.Dial("tcp", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "hi" {
		t.Fatalf("payload = %q", b)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
