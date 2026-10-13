package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rendex451/gomesh/internal/crypto"
)

func newKey(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// validConfig builds a fresh config each time: mutations in one
// test case must not leak into another via shared slices.
func validConfig(t *testing.T) Config {
	t.Helper()
	priv, _ := newKey(t)
	_, peerPub := newKey(t)
	return Config{
		PrivateKey: priv,
		ListenPort: 51900,
		TunName:    "gomesh0",
		TunAddress: netip.MustParsePrefix("10.99.1.1/16"),
		Subnet:     netip.MustParsePrefix("10.99.1.0/24"),
		Seeds:      []netip.AddrPort{netip.MustParseAddrPort("192.168.77.1:51900")},
		Peers: []Peer{{
			PublicKey: peerPub,
			Endpoint:  netip.MustParseAddrPort("192.168.77.2:51900"),
			Subnets:   []netip.Prefix{netip.MustParsePrefix("10.99.2.0/24")},
		}},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
		want   string // error substring; empty means no error expected
	}{
		{"valid", func(*Config) {}, ""},
		{"no seeds is fine", func(c *Config) { c.Seeds = nil }, ""},
		{"missing private key", func(c *Config) { c.PrivateKey = crypto.PrivateKey{} }, "private_key: is required"},
		{"zero port", func(c *Config) { c.ListenPort = 0 }, "listen_port"},
		{"long tun name", func(c *Config) { c.TunName = strings.Repeat("x", 16) }, "longer than 15"},
		{"tun mask same as subnet", func(c *Config) {
			c.TunAddress = netip.MustParsePrefix("10.99.1.1/24")
		}, "must be shorter"},
		{"tun address outside subnet", func(c *Config) {
			c.TunAddress = netip.MustParsePrefix("10.99.2.1/16")
		}, "outside own subnet"},
		{"subnet with host bits", func(c *Config) {
			c.Subnet = netip.MustParsePrefix("10.99.1.5/24")
		}, "host bits"},
		{"seed without port", func(c *Config) {
			c.Seeds = []netip.AddrPort{netip.MustParseAddrPort("192.168.77.1:0")}
		}, "seeds[0]"},
		{"peer is ourselves", func(c *Config) {
			own, _ := c.PrivateKey.PublicKey()
			c.Peers[0].PublicKey = own
		}, "own public key"},
		{"duplicate peer", func(c *Config) {
			dup := c.Peers[0]
			dup.Subnets = []netip.Prefix{netip.MustParsePrefix("10.99.3.0/24")}
			c.Peers = append(c.Peers, dup)
		}, "duplicates peers[0]"},
		{"peer without subnets", func(c *Config) { c.Peers[0].Subnets = nil }, "at least one subnet"},
		{"peer subnet outside overlay", func(c *Config) {
			c.Peers[0].Subnets = []netip.Prefix{netip.MustParsePrefix("10.100.0.0/24")}
		}, "outside overlay"},
		{"peer subnet overlaps own", func(c *Config) {
			c.Peers[0].Subnets = []netip.Prefix{netip.MustParsePrefix("10.99.1.128/25")}
		}, "overlaps subnet"},
		{"tun address is network address", func(c *Config) {
			c.TunAddress = netip.MustParsePrefix("10.99.1.0/16")
		}, "network address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig(t)
			tt.mutate(&c)
			err := c.Validate()

			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	c := validConfig(t)
	c.ListenPort = 0
	c.TunName = ""
	err := c.Validate()
	for _, want := range []string{"listen_port", "tun_name"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %s", err, want)
		}
	}
}

const tomlTemplate = `
private_key = %q
listen_port = 51900
tun_name    = "gomesh0"
tun_address = "10.99.1.1/16"
subnet      = "10.99.1.0/24"
seeds       = ["192.168.77.1:51900"]

[[peers]]
public_key = %q
endpoint   = "192.168.77.2:51900"
subnets    = ["10.99.2.0/24"]
`

func TestParse(t *testing.T) {
	priv, _ := newKey(t)
	_, peerPub := newKey(t)
	valid := fmt.Sprintf(tomlTemplate, priv.Base64(), peerPub.String())

	t.Run("valid", func(t *testing.T) {
		cfg, err := Parse(valid)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PrivateKey != priv {
			t.Error("private key mismatch")
		}
		if cfg.TunAddress != netip.MustParsePrefix("10.99.1.1/16") {
			t.Errorf("tun_address = %s", cfg.TunAddress)
		}
		if len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey != peerPub {
			t.Errorf("peers = %+v", cfg.Peers)
		}
	})

	tests := []struct {
		name, data, want string
	}{
		{"unknown key", valid + "\nmtu = 1420\n", "unknown keys"},
		{"bad prefix", strings.Replace(valid, "10.99.1.0/24", "10.99.1.0/33", 1), "parse"},
		{"bad key", strings.Replace(valid, priv.Base64(), "short", 1), "invalid key"},
		{"invalid values", strings.Replace(valid, "listen_port = 51900", "listen_port = 0", 1), "invalid config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestCheckPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(path); err != nil {
		t.Fatalf("0600: unexpected error: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckPermissions(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("0644: err = %v, want ErrInsecurePermissions", err)
	}
}
