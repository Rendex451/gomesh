package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the size of an X25519 key in bytes.
const KeySize = 32

// ErrInvalidKey is returned when parsing a malformed key.
var ErrInvalidKey = errors.New("invalid key")

// PrivateKey is an X25519 private key.
type PrivateKey [KeySize]byte

// PublicKey is an X25519 public key.
type PublicKey [KeySize]byte

// GeneratePrivateKey creates a new random private key.
func GeneratePrivateKey() (PrivateKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("generate key: %w", err)
	}

	var pk PrivateKey
	copy(pk[:], k.Bytes())
	return pk, nil
}

// ParsePrivateKey parses a base64 key (WireGuard format, 44 chars).
func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// ParsePublicKey parses a base64 key (WireGuard format, 44 chars).
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// ECDH returns the key in a form usable by crypto/ecdh.
func (k PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(k[:])
}

// PublicKey computes the public key for the private key.
func (k PrivateKey) PublicKey() (PublicKey, error) {
	priv, err := k.ECDH()
	if err != nil {
		return PublicKey{}, err
	}

	var pub PublicKey
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

// IsZero reports whether the key is unset. Constant-time comparison,
// so response timing reveals nothing about the secret.
func (k PrivateKey) IsZero() bool {
	var zero PrivateKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Base64 returns the key in WireGuard format. Call it only where
// the key really must be shown (gomesh genkey).
func (k PrivateKey) Base64() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// String hides the key when printed via fmt and slog (%v, %s, %+v, %x).
func (k PrivateKey) String() string { return "PrivateKey(hidden)" }

// GoString hides the key when printed via %#v.
func (k PrivateKey) GoString() string { return k.String() }

// UnmarshalText lets TOML and JSON decoders fill the key from a string.
func (k *PrivateKey) UnmarshalText(text []byte) error {
	return decodeKey((*[KeySize]byte)(k), text)
}

// IsZero reports whether the key is unset.
func (k PublicKey) IsZero() bool { return k == PublicKey{} }

// String returns the key in base64: a public key needn't be hidden.
func (k PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// MarshalText encodes the key in base64.
func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText lets TOML and JSON decoders fill the key from a string.
func (k *PublicKey) UnmarshalText(text []byte) error {
	return decodeKey((*[KeySize]byte)(k), text)
}

// decodeKey decodes base64 without allocations: the length is known in advance.
func decodeKey(dst *[KeySize]byte, text []byte) error {
	want := base64.StdEncoding.EncodedLen(KeySize) // 44
	if len(text) != want {
		return fmt.Errorf("%w: want %d base64 characters, got %d", ErrInvalidKey, want, len(text))
	}
	var buf [KeySize + 1]byte // DecodedLen(44) == 33
	n, err := base64.StdEncoding.Decode(buf[:], text)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if n != KeySize {
		return fmt.Errorf("%w: decoded to %d bytes, want %d", ErrInvalidKey, n, KeySize)
	}
	copy(dst[:], buf[:n])
	return nil
}
