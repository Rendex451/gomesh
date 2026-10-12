package tun

import (
	"io"
	"os"
)

// Device is an open TUN interface. The interface exists as long as the Device
// is open: Close (or process exit) removes it together with its routes.
type Device struct {
	file *os.File
	name string
}

// Compile-time check that Device implements io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*Device)(nil)

// Name returns the interface name.
func (d *Device) Name() string {
	return d.name
}

// Read reads one IP packet into p and returns its length.
// A packet larger than p is silently truncated.
// After Close it returns an error wrapping os.ErrClosed.
func (d *Device) Read(p []byte) (int, error) {
	return d.file.Read(p)
}

// Write writes one IP packet and returns len(p) on success.
// After Close it returns an error wrapping os.ErrClosed.
func (d *Device) Write(p []byte) (int, error) {
	return d.file.Write(p)
}

// Close removes the interface and unblocks Read.
func (d *Device) Close() error {
	return d.file.Close()
}
