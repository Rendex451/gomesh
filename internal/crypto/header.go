package crypto

import "encoding/binary"

const (
	HeaderLen = 13
	TagLen    = 16 // Poly1305

	TypeData      byte = 1
	TypeKeepalive byte = 2
	TypeGossip    byte = 3
)

// Header is the cleartext prefix of every message. It is authenticated
// as AEAD additional data. Integers are little-endian, as in WireGuard.
type Header struct {
	Type    byte
	Index   uint32 // sender's index: the receiver uses it to find the session
	Counter uint64 // nonce, strictly increasing
}

// Encode writes the header to b; b must be at least HeaderLen long.
func (h Header) Encode(b []byte) {
	_ = b[HeaderLen-1]
	b[0] = h.Type
	binary.LittleEndian.PutUint32(b[1:5], h.Index)
	binary.LittleEndian.PutUint64(b[5:13], h.Counter)
}

// DecodeHeader reads a header from b; false if b is shorter than HeaderLen.
func DecodeHeader(b []byte) (Header, bool) {
	if len(b) < HeaderLen {
		return Header{}, false
	}
	return Header{
		Type:    b[0],
		Index:   binary.LittleEndian.Uint32(b[1:5]),
		Counter: binary.LittleEndian.Uint64(b[5:13]),
	}, true
}
