package packet

import "net/netip"

// Version returns the version field of an IP header, or 0 if b is empty.
func Version(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return int(b[0] >> 4)
}

// Src returns the source address, or false if b is not a complete IP header.
func Src(b []byte) (netip.Addr, bool) {
	return addr(b, 12, 8)
}

// Dst returns the destination address, or false if b is not a complete IP header.
func Dst(b []byte) (netip.Addr, bool) {
	return addr(b, 16, 24)
}

// addr reads an address at off4 in an IPv4 header or off6 in an IPv6 header.
func addr(b []byte, off4, off6 int) (netip.Addr, bool) {
	switch Version(b) {
	case 4:
		if len(b) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(b[off4 : off4+4])), true
	case 6:
		if len(b) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(b[off6 : off6+16])), true
	default:
		return netip.Addr{}, false
	}
}
