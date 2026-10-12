package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// SetMTU sets the interface MTU(Maximum Transmission Unit).
func (d *Device) SetMTU(mtu int) error {
	return ip("link", "set", "dev", d.name, "mtu", strconv.Itoa(mtu))
}

// AddAddress assigns an address. Its prefix becomes a route via the interface.
func (d *Device) AddAddress(p netip.Prefix) error {
	if !p.IsValid() {
		return errors.New("tun: invalid address prefix")
	}
	return ip("addr", "add", p.String(), "dev", d.name)
}

// Up brings the interface up.
func (d *Device) Up() error {
	return ip("link", "set", "dev", d.name, "up")
}

// ip runs ip(8) and includes its output in the error.
func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: ip %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
