package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/refraction-networking/utls"
)

var (
	ErrNotAuthentic = errors.New("reality: server authentication failed")
	ErrFallback     = errors.New("reality: server fell back to target (auth rejected: check public key, shortID, version, clock; or not a REALITY server)")
)

type Dialer struct {
	// In Xray-core named (serverName)
	SNI         string
	Fingerprint tls.ClientHelloID
	ShortID     [8]byte

	// In Xray-core named (password)
	// must be X25519 curve only, validate this
	PublicKey *ecdh.PublicKey

	// N.B. Don't include this in the user configuration
	// In xray-core this field is called clientVersion and is used to filter out
	// older clients if minClientVer/maxClientVer are set on the server.
	// Here it is the (transport version) or (version).
	// We left it in for compatibility and in case there's a glitch in reality.
	// If the version doesn't match, the server will return the certificate for the actual site.
	Version [3]byte // now use [3]byte{0, 0, 1}
}

func (d *Dialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn, err := d.handshake(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) handshake(ctx context.Context, raw net.Conn) (net.Conn, error) {
	var authKey []byte // set before the handshake starts, read in the callback

	conn := tls.UClient(raw, &tls.Config{
		ServerName:             d.SNI,
		InsecureSkipVerify:     true, // the certificate is checked by verifyCert instead
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyCert(authKey, rawCerts)
		},
	}, d.Fingerprint)

	if err := conn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := conn.HandshakeState.Hello

	// The fingerprint must already carry a 32-byte session id, otherwise
	// writing at offset 39 would corrupt the following fields.
	if len(hello.Raw) < sessionIDOffset+sessionIDLen || hello.Raw[sessionIDLenOffset] != sessionIDLen {
		return nil, errors.New("reality: fingerprint hello has no 32-byte session id")
	}

	st := conn.HandshakeState.State13
	if st.KeyShareKeys == nil {
		return nil, errors.New("reality: fingerprint has no TLS 1.3 key share")
	}
	ecdhe := st.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = st.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("reality: fingerprint has no x25519 key share")
	}

	// Zero the session id inside the raw hello first: the raw hello is the
	// AEAD's associated data and the server sees it zeroed too.
	hello.SessionId = make([]byte, sessionIDLen)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)

	copy(hello.SessionId[:3], d.Version[:])
	// hello.SessionId[3] is reserved and stays 0.
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:16], d.ShortID[:])

	secret, err := ecdhe.ECDH(d.PublicKey)
	if err != nil {
		return nil, err
	}
	authKey, err = hkdf.Key(sha256.New, secret, hello.Random[:20], "REALITY", 32)
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
	// 16 bytes of plaintext + 16 of tag fill the 32-byte session id exactly.
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)

	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		return nil, ErrNotAuthentic
	}
	return conn, nil
}

// Checks that the server's ephemeral ed25519 certificate carries
// HMAC-SHA512(authKey, public key) in place of the signature.
func verifyCert(authKey []byte, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return ErrNotAuthentic
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return ErrNotAuthentic
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ErrFallback
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		return ErrNotAuthentic
	}
	return nil
}
