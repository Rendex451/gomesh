// Package crypto содержит ключи и криптографические сессии gomesh.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize — размер ключа X25519 в байтах.
const KeySize = 32

// ErrInvalidKey возвращается при разборе некорректного ключа.
var ErrInvalidKey = errors.New("invalid key")

// PrivateKey — приватный ключ X25519.
type PrivateKey [KeySize]byte

// PublicKey — публичный ключ X25519.
type PublicKey [KeySize]byte

// GeneratePrivateKey создаёт новый случайный приватный ключ.
func GeneratePrivateKey() (PrivateKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("generate key: %w", err)
	}

	var pk PrivateKey
	copy(pk[:], k.Bytes())
	return pk, nil
}

// ParsePrivateKey разбирает ключ в base64 (формат WireGuard, 44 символа).
func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// ParsePublicKey разбирает ключ в base64 (формат WireGuard, 44 символа).
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	err := k.UnmarshalText([]byte(s))
	return k, err
}

// ECDH возвращает ключ в виде, пригодном для crypto/ecdh.
func (k PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(k[:])
}

// PublicKey вычисляет публичный ключ, соответствующий приватному.
func (k PrivateKey) PublicKey() (PublicKey, error) {
	priv, err := k.ECDH()
	if err != nil {
		return PublicKey{}, err
	}

	var pub PublicKey
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

// IsZero сообщает, что ключ не задан. Сравнение за постоянное время,
// чтобы по времени ответа нельзя было ничего узнать о секрете.
func (k PrivateKey) IsZero() bool {
	var zero PrivateKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Base64 возвращает ключ в формате WireGuard. Вызывать только там,
// где ключ действительно нужно показать (gomesh genkey).
func (k PrivateKey) Base64() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// String скрывает ключ при выводе через fmt и slog (%v, %s, %+v, %x).
func (k PrivateKey) String() string { return "PrivateKey(hidden)" }

// GoString скрывает ключ при выводе через %#v.
func (k PrivateKey) GoString() string { return k.String() }

// UnmarshalText позволяет декодерам TOML и JSON заполнять ключ из строки.
func (k *PrivateKey) UnmarshalText(text []byte) error {
	return decodeKey((*[KeySize]byte)(k), text)
}

// IsZero сообщает, что ключ не задан.
func (k PublicKey) IsZero() bool { return k == PublicKey{} }

// String возвращает ключ в base64: публичный ключ скрывать не нужно.
func (k PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// MarshalText кодирует ключ в base64.
func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText позволяет декодерам TOML и JSON заполнять ключ из строки.
func (k *PublicKey) UnmarshalText(text []byte) error {
	return decodeKey((*[KeySize]byte)(k), text)
}

// decodeKey декодирует base64 без аллокаций: длина известна заранее.
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
