package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"
)

const maxClientHelloLn = 1 << 14

type Server struct {
	// Address to which authenticated traffic is proxied.
	Destination string

	// Real site full address.
	// Receives all connections that fail authentication, including the bytes already read.
	Target string

	// Server's long-term X25519 key
	PrivateKey *ecdh.PrivateKey

	// Allowed short ids. At least one is required
	ShortIDs [][8]byte

	// Allowed SNI values. Empty means any
	// In Xray-core named (serverNames)
	SNIs []string

	// N.B. Don't include this in the user configuration
	// Exact transport version the server accepts.
	// Look at Dialer.Version and read
	Version [3]byte

	// Maximum clock difference between client and server. Zero disables the check.
	MaxTimeDiff time.Duration

	// Dialer optionally specifies the dialer to use for outgoing connections.
	// If nil, the net package's standard dialer is used.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := s.Dialer
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return dial(ctx, network, addr)
}

func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		log.Printf("reality: %s: accepted", c.RemoteAddr())
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()

	// TODO: add timeouts (in Xray-core ClientHello read, TLS handshake)
	buf, ch := readClientHello(c)

	var authKey []byte
	var err error
	if ch == nil {
		err = errors.New("reality: not a TLS ClientHello")
	} else {
		authKey, err = s.authenticate(ch)
	}
	if err != nil {
		log.Printf("reality: %s: auth rejected (%v), falling back to %s", c.RemoteAddr(), err, s.Target)
		s.fallback(c, buf)
		return
	}

	cert, err := newAuthCert(authKey, ch.serverName)
	if err != nil {
		log.Printf("reality: %s: %v", c.RemoteAddr(), err)
		return
	}
	tc := tls.Server(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(buf), c)}, &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		SessionTicketsDisabled: true,
	})
	if err := tc.Handshake(); err != nil {
		log.Printf("reality: %s: handshake failed: %v", c.RemoteAddr(), err)
		return
	}

	s.proxy(tc, s.Destination)
}

// It returns every byte read (so they can be replayed)
// and the parsed hello, or nil if the data is not a well-formed ClientHello
func readClientHello(c net.Conn) ([]byte, *clientHello) {
	hdr := make([]byte, 5)
	n, err := io.ReadFull(c, hdr)
	buf := hdr[:n]
	if err != nil || hdr[0] != 0x16 || hdr[1] != 3 {
		return buf, nil
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length < 4+2+32+1+sessionIDLen || length > maxClientHelloLn {
		return buf, nil
	}
	body := make([]byte, length)
	n, err = io.ReadFull(c, body)
	buf = append(buf, body[:n]...)
	if err != nil {
		return buf, nil
	}
	ch, err := parseClientHello(body)
	if err != nil {
		return buf, nil
	}
	return buf, ch
}

// Returns the auth key if the ClientHello carries a valid
// REALITY session id that passes all server policies
func (s *Server) authenticate(ch *clientHello) ([]byte, error) {
	if ch.x25519 == nil {
		return nil, errors.New("no x25519 key share")
	}
	if len(s.SNIs) > 0 && !slices.ContainsFunc(s.SNIs, func(n string) bool {
		return strings.EqualFold(n, ch.serverName)
	}) {
		return nil, fmt.Errorf("SNI %q not allowed", ch.serverName)
	}

	pub, err := ecdh.X25519().NewPublicKey(ch.x25519)
	if err != nil {
		return nil, err
	}
	secret, err := s.PrivateKey.ECDH(pub)
	if err != nil {
		return nil, err
	}
	authKey, err := hkdf.Key(sha256.New, secret, ch.random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// The client used the hello with a zeroed session id as associated data
	aad := bytes.Clone(ch.raw)
	clear(aad[sessionIDOffset : sessionIDOffset+sessionIDLen])
	plain, err := aead.Open(nil, ch.random[20:], ch.sessionID, aad)
	if err != nil {
		return nil, errors.New("session id decryption failed")
	}

	version := [3]byte(plain[:3])
	ts := time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)
	shortID := [8]byte(plain[8:16])

	if version != s.Version {
		return nil, fmt.Errorf("reality: client version %v, want %v", version, s.Version)
	}

	if s.MaxTimeDiff > 0 {
		d := time.Since(ts)
		if d < 0 {
			d = -d
		}
		if d > s.MaxTimeDiff {
			return nil, fmt.Errorf("reality: clock difference %v exceeds %v", d, s.MaxTimeDiff)
		}
	}
	if !slices.Contains(s.ShortIDs, shortID) {
		return nil, errors.New("unknown short id")
	}
	return authKey, nil
}

func verNum(v [3]byte) int { return int(v[0])<<16 | int(v[1])<<8 | int(v[2]) }

// Makes a self-signed ed25519 certificate whose signature is replaced with HMAC-SHA512(authKey, public key).
// The TLS CertificateVerify is still signed with the real private key, so the handshake is valid
func newAuthCert(authKey []byte, serverName string) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if serverName != "" {
		tmpl.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	// For ed25519 the signature is the last 64 bytes of the DER certificate
	copy(der[len(der)-sha512.Size:], h.Sum(nil))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func (s *Server) fallback(c net.Conn, prefix []byte) {
	// TODO: add timeout
	ctx := context.Background()
	t, err := s.dial(ctx, "tcp", s.Target)
	if err != nil {
		log.Printf("reality: %s: %v", c.RemoteAddr(), err)
		return
	}
	defer t.Close()
	if _, err := t.Write(prefix); err != nil {
		return
	}
	pipe(c, t, s.Target)
}

func (s *Server) proxy(c net.Conn, dest string) {
	// TODO: add timeout.
	ctx := context.Background()
	srv, err := s.dial(ctx, "tcp", dest)
	if err != nil {
		log.Printf("reality: %s: %v", c.RemoteAddr(), err)
		return
	}
	defer srv.Close()
	pipe(c, srv, dest)
}

func pipe(client, server net.Conn, name string) {
	done := make(chan struct{})
	go func() {
		n, err := io.Copy(server, client)
		if err != nil {
			log.Printf("reality: %s: copy to %s failed after %d bytes: %v",
				client.RemoteAddr(), name, n, err)
		}
		closeWrite(server)
		close(done)
	}()

	n, err := io.Copy(client, server)
	if err != nil {
		log.Printf("reality: %s: copy from %s failed after %d bytes: %v",
			client.RemoteAddr(), name, n, err)
	}
	closeWrite(client)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// replays already-read bytes before reading from the connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

type clientHello struct {
	raw        []byte // handshake message (without the record header)
	random     []byte // 32 bytes
	sessionID  []byte // 32 bytes
	serverName string
	x25519     []byte // client's x25519 public key, 32 bytes
}

var errBadHello = errors.New("reality: malformed ClientHello")

func prefixed8(b []byte) (body, rest []byte, ok bool) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, nil, false
	}
	n := int(b[0])
	return b[1 : 1+n], b[1+n:], true
}

func prefixed16(b []byte) (body, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(b[0])<<8 | int(b[1])
	if len(b) < 2+n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

func parseClientHello(msg []byte) (*clientHello, error) {
	// type(1), length(3), version(2), random(32), session id length(1), session id(32)
	if len(msg) < sessionIDOffset+sessionIDLen || msg[0] != 1 {
		return nil, errBadHello
	}
	if int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(msg)-4 {
		return nil, errBadHello
	}
	if msg[sessionIDLenOffset] != sessionIDLen {
		return nil, errBadHello
	}
	ch := &clientHello{
		raw:       msg,
		random:    msg[6:38],
		sessionID: msg[sessionIDOffset : sessionIDOffset+sessionIDLen],
	}

	p := msg[sessionIDOffset+sessionIDLen:]
	var ok bool
	if _, p, ok = prefixed16(p); !ok { // cipher suites
		return nil, errBadHello
	}
	if _, p, ok = prefixed8(p); !ok { // compression methods
		return nil, errBadHello
	}
	var exts []byte
	if exts, _, ok = prefixed16(p); !ok {
		return nil, errBadHello
	}

	var hybrid []byte
	for len(exts) > 0 {
		if len(exts) < 4 {
			return nil, errBadHello
		}
		typ := int(exts[0])<<8 | int(exts[1])
		var body []byte
		if body, exts, ok = prefixed16(exts[2:]); !ok {
			return nil, errBadHello
		}
		switch typ {
		case 0: // server_name
			list, _, ok := prefixed16(body)
			for ok && len(list) >= 3 {
				var name []byte
				if name, _, ok = prefixed16(list[1:]); !ok {
					break
				}
				if list[0] == 0 {
					ch.serverName = string(name)
					break
				}
				list = list[3+len(name):]
			}
		case 51: // key_share
			shares, _, ok := prefixed16(body)
			for ok && len(shares) >= 4 {
				group := int(shares[0])<<8 | int(shares[1])
				var data []byte
				if data, shares, ok = prefixed16(shares[2:]); !ok {
					break
				}
				switch {
				case group == 0x001d && len(data) == 32:
					ch.x25519 = data
				case group == 0x11ec && len(data) == 1184+32:
					// X25519MLKEM768: ML-KEM-768 key (1184 bytes) followed by x25519.
					hybrid = data[1184:]
				}
			}
		}
	}
	if ch.x25519 == nil {
		ch.x25519 = hybrid
	}
	return ch, nil
}
