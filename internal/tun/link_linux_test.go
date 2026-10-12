package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var testPrefix = netip.MustParsePrefix("10.250.0.1/24")

// openConfigured opens a device with MTU 1420 and testPrefix, and brings it up.
func openConfigured(t *testing.T) *Device {
	t.Helper()
	d := openTest(t, "gomeshtest0")
	if err := d.SetMTU(1420); err != nil {
		t.Fatal(err)
	}
	if err := d.AddAddress(testPrefix); err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestConfigure(t *testing.T) {
	d := openConfigured(t)

	iface, err := net.InterfaceByName(d.Name())
	if err != nil {
		t.Fatal(err)
	}
	if iface.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", iface.MTU)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Error("interface is not up")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range addrs {
		if a.String() == testPrefix.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("addresses = %v, want %s", addrs, testPrefix)
	}
}

func TestAddAddressInvalid(t *testing.T) {
	d := openTest(t, "gomeshtest0")
	if err := d.AddAddress(netip.Prefix{}); err == nil {
		t.Fatal("AddAddress accepted a zero prefix")
	}
}

func TestSetMTUInvalid(t *testing.T) {
	d := openTest(t, "gomeshtest0")

	err := d.SetMTU(0)
	if err == nil {
		t.Fatal("SetMTU(0) succeeded")
	}
	if !strings.Contains(err.Error(), "ip link set") {
		t.Fatalf("error does not include the command: %v", err)
	}
}

// sendUDP sends each payload as a separate datagram to addr.
func sendUDP(t *testing.T, addr string, payloads ...[]byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, p := range payloads {
		if _, err := conn.Write(p); err != nil {
			t.Fatal(err)
		}
	}
}

// nextUDP4 reads into buf until it gets an IPv4/UDP packet to dst,
// skipping anything else. It returns the packet length or a read error.
func nextUDP4(d *Device, buf []byte, dst netip.Addr) (int, error) {
	want := dst.As4()
	for {
		n, err := d.Read(buf)
		if err != nil {
			return n, err
		}
		p := buf[:n]
		if n >= 20 && p[0]>>4 == 4 && p[9] == 17 && bytes.Equal(p[16:20], want[:]) {
			return n, nil
		}
	}
}

// udp4Payload returns the UDP payload of an IPv4 packet.
func udp4Payload(p []byte) []byte {
	ihl := int(p[0]&0x0f) * 4
	return p[ihl+8:]
}

// A datagram to a non-existent host in testPrefix must come out of Read.
func TestReadPacket(t *testing.T) {
	d := openConfigured(t)
	if err := d.file.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello gomesh")
	sendUDP(t, "10.250.0.2:9", payload)

	buf := make([]byte, 1500)
	n, err := nextUDP4(d, buf, netip.MustParseAddr("10.250.0.2"))
	if err != nil {
		t.Fatalf("no matching packet: %v", err)
	}
	if got := udp4Payload(buf[:n]); !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

// Documents what the kernel does when the buffer is smaller than the packet,
// and checks that packet boundaries survive: no tail in the next Read.
func TestReadSmallBuffer(t *testing.T) {
	d := openConfigured(t)
	if err := d.file.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	marker := []byte("marker")
	sendUDP(t, "10.250.0.2:9", bytes.Repeat([]byte{'x'}, 200), marker)
	dst := netip.MustParseAddr("10.250.0.2")

	small := make([]byte, 64)
	n, err := nextUDP4(d, small, dst)
	t.Logf("small buffer: n = %d, err = %v", n, err) // replace with assertions once you know the behavior
	if err == nil && n > len(small) {
		t.Fatalf("n = %d exceeds buffer size %d", n, len(small))
	}

	buf := make([]byte, 1500)
	n, err = nextUDP4(d, buf, dst)
	if err != nil {
		t.Fatalf("marker packet: %v", err)
	}
	if got := udp4Payload(buf[:n]); !bytes.Equal(got, marker) {
		t.Fatalf("next packet payload = %q, want %q (tail of the big packet?)", got, marker)
	}
}

func TestReadPacketIPv6(t *testing.T) {
	d := openTest(t, "gomeshtest0")
	if err := d.SetMTU(1420); err != nil {
		t.Fatal(err)
	}
	// nodad: skip duplicate address detection, otherwise the address is unusable for a few seconds.
	if err := ip("addr", "add", "fd00:250::1/64", "dev", d.Name(), "nodad"); err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	if err := d.file.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello ipv6")
	sendUDP(t, "[fd00:250::2]:9", payload)

	dst := netip.MustParseAddr("fd00:250::2").As16()
	buf := make([]byte, 1500)
	for {
		n, err := d.Read(buf)
		if err != nil {
			t.Fatalf("no matching packet: %v", err)
		}
		p := buf[:n]
		// Fixed 40-byte header, next header at byte 6, destination at 24..40.
		if n < 48 || p[0]>>4 != 6 || p[6] != 17 || !bytes.Equal(p[24:40], dst[:]) {
			continue
		}
		if got := p[48:]; !bytes.Equal(got, payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
		return
	}
}

// A packet written to the device must reach a local UDP socket.
func TestWritePacket(t *testing.T) {
	d := openConfigured(t)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 250, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	payload := []byte("hello from tun")
	src := netip.MustParseAddr("10.250.0.2")
	pkt := buildUDP4(src, testPrefix.Addr(), 5000, port, payload)

	if _, err := d.Write(pkt); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("datagram not delivered (check the checksum and rp_filter): %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}
	if from.AddrPort() != netip.AddrPortFrom(src, 5000) {
		t.Errorf("from = %s, want %s:5000", from, src)
	}
}

// The kernel must reject a packet that is neither IPv4 nor IPv6.
func TestWriteInvalidPacket(t *testing.T) {
	d := openConfigured(t)

	if _, err := d.Write(make([]byte, 20)); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
}

// Example header from RFC 1071 explanations (Wikipedia "IPv4 header checksum").
func TestChecksum(t *testing.T) {
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := checksum(hdr); got != 0xb861 {
		t.Fatalf("checksum = %#04x, want 0xb861", got)
	}
}

// buildUDP4 builds an IPv4/UDP packet. The UDP checksum is left zero,
// which IPv4 allows and means "not computed".
func buildUDP4(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	const ipLen, udpLen = 20, 8
	p := make([]byte, ipLen+udpLen+len(payload))

	p[0] = 0x45                                        // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p))) // total length
	p[8] = 64                                          // TTL
	p[9] = 17                                          // UDP
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:ipLen]))

	u := p[ipLen:]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen+len(payload)))
	copy(u[udpLen:], payload)
	return p
}

// checksum computes the Internet checksum (RFC 1071).
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
