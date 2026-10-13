package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func newPair(t *testing.T) (a, b *Session) {
	t.Helper()
	ka, kb := mustGenerate(t), mustGenerate(t)
	pa, err := ka.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pb, err := kb.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if a, err = NewSession(ka, pb); err != nil {
		t.Fatal(err)
	}
	if b, err = NewSession(kb, pa); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func mustGenerate(t *testing.T) PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSessionRoundTrip(t *testing.T) {
	a, b := newPair(t)
	if a.index != b.peerIndex || b.index != a.peerIndex {
		t.Fatal("sides disagree on indices")
	}

	for _, tt := range []struct{ from, to *Session }{{a, b}, {b, a}} {
		payload := []byte("hello mesh")
		msg, err := tt.from.Seal(nil, TypeData, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(msg) != HeaderLen+len(payload)+TagLen {
			t.Fatalf("len(msg) = %d", len(msg))
		}
		h, _ := DecodeHeader(msg)
		if h.Type != TypeData || h.Index != tt.from.index {
			t.Fatalf("header = %+v", h)
		}

		got, err := tt.to.Open(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload = %q", got)
		}
		if _, err := tt.to.Open(nil, msg); !errors.Is(err, ErrReplay) {
			t.Fatalf("second Open: err = %v, want ErrReplay", err)
		}
	}
}

func TestSessionAppendsToDst(t *testing.T) {
	a, b := newPair(t)
	msg, err := a.Seal([]byte("prefix"), TypeKeepalive, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open([]byte("out:"), msg[len("prefix"):])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "out:" {
		t.Fatalf("Open = %q", got)
	}
}

func TestSessionRejects(t *testing.T) {
	a, b := newPair(t)
	_, c := newPair(t)
	msg, err := a.Seal(nil, TypeData, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	flip := func(i int) []byte {
		m := bytes.Clone(msg)
		m[i] ^= 1
		return m
	}
	tests := []struct {
		name string
		to   *Session
		msg  []byte
		want error
	}{
		{"short", b, msg[:HeaderLen+TagLen-1], ErrShortMessage},
		{"tampered type", b, flip(0), ErrAuth},
		{"tampered index", b, flip(1), ErrAuth},
		{"tampered counter", b, flip(5), ErrAuth},
		{"tampered body", b, flip(HeaderLen), ErrAuth},
		{"tampered tag", b, flip(len(msg) - 1), ErrAuth},
		{"wrong session", c, msg, ErrAuth},
		{"own message", a, msg, ErrAuth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.to.Open(nil, tt.msg); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	// Rejected forgeries must not burn the real counter.
	if _, err := b.Open(nil, msg); err != nil {
		t.Fatalf("genuine message after forgeries: %v", err)
	}
}

func TestNewSessionRejectsOwnKey(t *testing.T) {
	k := mustGenerate(t)
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(k, pub); err == nil {
		t.Fatal("NewSession accepted own public key")
	}
	if _, err := NewSession(k, PublicKey{}); err == nil {
		t.Fatal("NewSession accepted a zero (low-order) peer key")
	}
}
