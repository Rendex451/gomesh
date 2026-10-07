package main

import (
	"bytes"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func runCmd(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, strings.NewReader(stdin), &out, io.Discard); err != nil {
		t.Fatalf("gomesh %v: %v", args, err)
	}
	return strings.TrimSpace(out.String())
}

func wgCmd(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("wg", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wg %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// Совместимость с WireGuard в обе стороны: ключи одного формата
// и одна и та же кривая, значит, публичные ключи обязаны совпасть.
func TestKeysCompatibleWithWireGuard(t *testing.T) {
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg is not installed")
	}

	t.Run("gomesh genkey", func(t *testing.T) {
		priv := runCmd(t, "", "genkey")
		if ours, theirs := runCmd(t, priv, "pubkey"), wgCmd(t, priv, "pubkey"); ours != theirs {
			t.Fatalf("gomesh pubkey = %s, wg pubkey = %s", ours, theirs)
		}
	})

	t.Run("wg genkey", func(t *testing.T) {
		priv := wgCmd(t, "", "genkey")
		if ours, theirs := runCmd(t, priv, "pubkey"), wgCmd(t, priv, "pubkey"); ours != theirs {
			t.Fatalf("gomesh pubkey = %s, wg pubkey = %s", ours, theirs)
		}
	})
}

func TestUnknownCommand(t *testing.T) {
	err := run([]string{"frobnicate"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("err = %v", err)
	}
}
