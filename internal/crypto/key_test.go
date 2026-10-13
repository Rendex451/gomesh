package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Test vectors from RFC 7748, section 6.1.
func TestPublicKeyRFC7748(t *testing.T) {
	tests := []struct {
		name, priv, pub string
	}{
		{
			name: "alice",
			priv: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			pub:  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		},
		{
			name: "bob",
			priv: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			pub:  "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var priv PrivateKey
			mustHex(t, priv[:], tt.priv)

			pub, err := priv.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(pub[:]); got != tt.pub {
				t.Fatalf("public key = %s, want %s", got, tt.pub)
			}
		})
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k.IsZero() {
		t.Fatal("generated key is zero")
	}
	got, err := ParsePrivateKey(k.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatal("round trip changed the key")
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name, in string
	}{
		{"empty", ""},
		{"too short", strings.Repeat("A", 43)},
		{"too long", strings.Repeat("A", 45)},
		{"not base64", strings.Repeat("!", 44)},
		{"33 bytes without padding", strings.Repeat("A", 44)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.in)
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("err = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestPrivateKeyIsNotPrinted(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := k.Base64()
	wrapped := struct{ Key PrivateKey }{k}

	for _, verb := range []string{"%v", "%s", "%+v", "%#v", "%x"} {
		for _, val := range []any{k, wrapped} {
			out := fmt.Sprintf(verb, val)
			if strings.Contains(out, secret) || strings.Contains(out, hex.EncodeToString(k[:])) {
				t.Errorf("fmt.Sprintf(%q, %T) leaks the key: %s", verb, val, out)
			}
		}
	}
}

func mustHex(t *testing.T, dst []byte, s string) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	copy(dst, b)
}
