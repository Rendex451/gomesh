package crypto

import "testing"

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{Type: TypeGossip, Index: 0xdeadbeef, Counter: 1<<63 + 42}
	var b [HeaderLen]byte
	h.Encode(b[:])

	got, ok := DecodeHeader(b[:])
	if !ok || got != h {
		t.Fatalf("DecodeHeader = %+v, %v; want %+v, true", got, ok, h)
	}
	if _, ok := DecodeHeader(b[:HeaderLen-1]); ok {
		t.Fatal("DecodeHeader accepted a short buffer")
	}
}
