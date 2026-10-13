package packet

import (
	"net/netip"
	"testing"
)

var (
	src4 = netip.MustParseAddr("10.99.1.1")
	dst4 = netip.MustParseAddr("10.99.2.1")
	src6 = netip.MustParseAddr("fd00::1")
	dst6 = netip.MustParseAddr("fd00::2")
)

// ipv4 builds a minimal 20-byte IPv4 header; other fields stay zero.
func ipv4(src, dst netip.Addr) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	return b
}

// ipv6 builds a minimal 40-byte IPv6 header; other fields stay zero.
func ipv6(src, dst netip.Addr) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	return b
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"ipv4", ipv4(src4, dst4), 4},
		{"ipv6", ipv6(src6, dst6), 6},
		{"other", []byte{0x50}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Version(tt.in); got != tt.want {
				t.Fatalf("Version = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSrcDst(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		src, dst netip.Addr // zero values mean "want false"
	}{
		{"ipv4", ipv4(src4, dst4), src4, dst4},
		{"ipv4 with payload", append(ipv4(src4, dst4), 1, 2, 3), src4, dst4},
		{"ipv6", ipv6(src6, dst6), src6, dst6},
		{"empty", nil, netip.Addr{}, netip.Addr{}},
		{"short ipv4", ipv4(src4, dst4)[:19], netip.Addr{}, netip.Addr{}},
		{"short ipv6", ipv6(src6, dst6)[:39], netip.Addr{}, netip.Addr{}},
		{"version 0", make([]byte, 40), netip.Addr{}, netip.Addr{}},
		{"version 5", append([]byte{0x50}, make([]byte, 39)...), netip.Addr{}, netip.Addr{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := func(fn string, got netip.Addr, ok bool, want netip.Addr) {
				t.Helper()
				if wantOK := want.IsValid(); ok != wantOK || got != want {
					t.Errorf("%s = %v, %v; want %v, %v", fn, got, ok, want, wantOK)
				}
			}
			got, ok := Src(tt.in)
			check("Src", got, ok, tt.src)
			got, ok = Dst(tt.in)
			check("Dst", got, ok, tt.dst)
		})
	}
}

// Any input must not panic, and a successful result must match the version.
func FuzzAddr(f *testing.F) {
	f.Add(ipv4(src4, dst4))
	f.Add(ipv6(src6, dst6))
	f.Add([]byte{})
	f.Add([]byte{0x45, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		for _, fn := range []func([]byte) (netip.Addr, bool){Src, Dst} {
			a, ok := fn(b)
			if !ok {
				if a.IsValid() {
					t.Fatalf("ok = false but address %v is valid", a)
				}
				continue
			}
			switch v := Version(b); {
			case v == 4 && (!a.Is4() || len(b) < 20):
				t.Fatalf("version 4: got %v from %d bytes", a, len(b))
			case v == 6 && (!a.Is6() || len(b) < 40):
				t.Fatalf("version 6: got %v from %d bytes", a, len(b))
			case v != 4 && v != 6:
				t.Fatalf("ok = true for version %d", v)
			}
		}
	})
}

func BenchmarkDst(b *testing.B) {
	pkts := map[string][]byte{
		"ipv4": ipv4(src4, dst4),
		"ipv6": ipv6(src6, dst6),
	}
	for name, p := range pkts {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Dst(p)
			}
		})
	}
}
