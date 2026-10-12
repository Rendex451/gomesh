package tun

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root or CAP_NET_ADMIN")
	}
}

// openTest opens a device and closes it when the test ends.
func openTest(t *testing.T, name string) *Device {
	t.Helper()
	requireRoot(t)
	d, err := Open(name)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenName(t *testing.T) {
	const name = "gomeshtest0"
	d := openTest(t, name)

	if d.Name() != name {
		t.Fatalf("Name() = %q, want %q", d.Name(), name)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("interface not visible to the kernel: %v", err)
	}
}

func TestOpenTemplate(t *testing.T) {
	d := openTest(t, "gomeshtest%d")

	if strings.Contains(d.Name(), "%") || !strings.HasPrefix(d.Name(), "gomeshtest") {
		t.Fatalf("Name() = %q, want template expanded by the kernel", d.Name())
	}
}

// Name validation happens before the ioctl, so root is not needed.
func TestOpenNameTooLong(t *testing.T) {
	d, err := Open(strings.Repeat("x", 16))
	if err == nil {
		_ = d.Close()
		t.Fatal("Open succeeded with a 16-byte name")
	}
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
}

func TestOpenBusy(t *testing.T) {
	const name = "gomeshtest0"
	openTest(t, name)

	d2, err := Open(name)
	if err == nil {
		_ = d2.Close()
		t.Fatal("second Open of the same name succeeded")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("err = %v, want EBUSY", err)
	}
}

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// Failed Opens must close the fd they opened. Root is not needed.
func TestOpenErrorDoesNotLeakFD(t *testing.T) {
	before := countFDs(t)
	for range 100 {
		if d, err := Open(strings.Repeat("x", 16)); err == nil {
			_ = d.Close()
			t.Fatal("Open succeeded with a 16-byte name")
		}
	}
	if after := countFDs(t); after != before {
		t.Fatalf("open fds: %d before, %d after", before, after)
	}
}

func TestCloseRemovesInterface(t *testing.T) {
	const name = "gomeshtest0"
	d := openTest(t, name)

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("interface still exists after Close")
	}
}

func TestCloseTwice(t *testing.T) {
	d := openTest(t, "gomeshtest0")

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("second Close: err = %v, want os.ErrClosed", err)
	}
}

func TestWriteAfterClose(t *testing.T) {
	const name = "gomeshtest0"
	d := openTest(t, name)

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Write([]byte{0x45}); err == nil {
		t.Fatal("valid write after close")
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	d := openTest(t, "gomeshtest0")

	done := make(chan error, 1) // buffered: the goroutine must not leak on timeout
	go func() {
		buf := make([]byte, 1500)
		_, err := d.Read(buf)
		done <- err
	}()

	time.Sleep(100 * time.Millisecond) // let Read block
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read error = %v, want os.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}
