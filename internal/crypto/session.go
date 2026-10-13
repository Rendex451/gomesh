package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const kdfInfo = "gomesh v1 session"

// rejectAfter caps the send counter well before it wraps around.
const rejectAfter = math.MaxUint64 - 1<<16

var (
	ErrShortMessage = errors.New("message too short")
	ErrAuth         = errors.New("authentication failed")
	ErrReplay       = errors.New("replayed message")
	ErrExhausted    = errors.New("send counter exhausted")
)

// Session encrypts traffic between two nodes with static keys.
// Safe for concurrent use.
type Session struct {
	send, recv cipher.AEAD
	counter    atomic.Uint64
	replay     ReplayWindow
	index      uint32 // ours, goes into outgoing headers
	peerIndex  uint32 // the peer's, expected in incoming headers
}

// NewSession derives both directions' keys and indices from the static
// ECDH secret. Both sides compute the same values: they are ordered by
// public key, so the lower key's send key is the higher key's recv key.
func NewSession(priv PrivateKey, peer PublicKey) (*Session, error) {
	ours, err := priv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	if ours == peer {
		return nil, errors.New("session: peer key equals own key")
	}

	privECDH, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	peerECDH, err := privECDH.Curve().NewPublicKey(peer[:])
	if err != nil {
		return nil, fmt.Errorf("session: peer key: %w", err)
	}
	// Fails on low-order points, which give an all-zero secret.
	shared, err := privECDH.ECDH(peerECDH)
	if err != nil {
		return nil, fmt.Errorf("session: ecdh: %w", err)
	}

	lo, hi := ours, peer
	weAreLo := bytes.Compare(ours[:], peer[:]) < 0
	if !weAreLo {
		lo, hi = hi, lo
	}
	salt := append(lo[:], hi[:]...)
	okm, err := hkdf.Key(sha256.New, shared, salt, kdfInfo, 2*chacha20poly1305.KeySize+2*4)
	if err != nil {
		return nil, fmt.Errorf("session: kdf: %w", err)
	}

	loKey, hiKey := okm[:32], okm[32:64]
	loIndex, hiIndex := binary.LittleEndian.Uint32(okm[64:68]), binary.LittleEndian.Uint32(okm[68:72])
	sendKey, recvKey := loKey, hiKey
	index, peerIndex := loIndex, hiIndex
	if !weAreLo {
		sendKey, recvKey = hiKey, loKey
		index, peerIndex = hiIndex, loIndex
	}

	s := &Session{index: index, peerIndex: peerIndex}
	if s.send, err = chacha20poly1305.New(sendKey); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	if s.recv, err = chacha20poly1305.New(recvKey); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	// Keys are static, so a counter starting at zero would reuse nonces
	// after a restart. Starting from wall-clock nanoseconds keeps it
	// increasing across restarts, unless the clock goes backwards.
	s.counter.Store(uint64(time.Now().UnixNano()))
	return s, nil
}

// PeerIndex returns the index the peer puts in its headers:
// the key to look this session up by on receive.
func (s *Session) PeerIndex() uint32 { return s.peerIndex }

// Seal appends header and encrypted payload to dst.
func (s *Session) Seal(dst []byte, typ byte, payload []byte) ([]byte, error) {
	c := s.counter.Add(1)
	if c >= rejectAfter {
		return dst, ErrExhausted
	}

	n := len(dst)
	dst = slices.Grow(dst, HeaderLen+len(payload)+TagLen)[:n+HeaderLen]
	hdr := dst[n:]
	Header{Type: typ, Index: s.index, Counter: c}.Encode(hdr)
	return s.send.Seal(dst, nonce(c), payload, hdr), nil
}

// Open verifies msg (header included) and appends the payload to dst.
func (s *Session) Open(dst, msg []byte) ([]byte, error) {
	if len(msg) < HeaderLen+TagLen {
		return dst, ErrShortMessage
	}
	h, _ := DecodeHeader(msg)
	if h.Index != s.peerIndex {
		return dst, ErrAuth
	}
	out, err := s.recv.Open(dst, nonce(h.Counter), msg[HeaderLen:], msg[:HeaderLen])
	if err != nil {
		return dst, ErrAuth
	}
	// Only after authentication: forged counters must not move the window.
	if !s.replay.Accept(h.Counter) {
		return dst, ErrReplay
	}
	return out, nil
}

// nonce builds a ChaCha20-Poly1305 nonce as in WireGuard:
// 4 zero bytes, then the counter in little-endian.
func nonce(counter uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n[:]
}
