package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const devicePath = "/dev/net/tun"

// Open creates a TUN interface.
func Open(name string) (*Device, error) {
	fd, err := unix.Open(devicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	// mode: O_RDWR - open on read & write, O_CLOEXEC - close fd on exec
	if err != nil {
		return nil, fmt.Errorf("tun open %s: %w", devicePath, err)
	}

	actual, err := createInterface(fd, name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Must happen before os.NewFile, otherwise the file is not netpoller-backed.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: set nonblock: %w", err)
	}

	return &Device{
		file: os.NewFile(uintptr(fd), "tun:"+actual),
		name: actual,
	}, nil
}

// createInterface binds fd to a new TUN interface and returns its actual name.
func createInterface(fd int, name string) (string, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return "", fmt.Errorf("tun: interface name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return "", fmt.Errorf("tun: create %q: %w", name, err)
	}
	return ifr.Name(), nil
}
