package crypto

import "testing"

func TestReplayWindow(t *testing.T) {
	steps := []struct {
		counter uint64
		want    bool
	}{
		{0, true},
		{0, false},
		{5, true},
		{3, true},
		{3, false},
		{5, false},
		{windowSize + 10, true},
		{9, false}, // fell out of the window
		{10, true}, // exactly at the edge
		{windowSize + 9, true},
		{1 << 40, true}, // jump far ahead clears the ring
		{windowSize + 11, false},
		{1<<40 - 1, true},
		{1 << 40, false},
	}
	var w ReplayWindow
	for i, s := range steps {
		if got := w.Accept(s.counter); got != s.want {
			t.Fatalf("step %d: Accept(%d) = %v, want %v", i, s.counter, got, s.want)
		}
	}
}

// Every counter in a sliding range is accepted exactly once,
// even when they arrive out of order.
func TestReplayWindowReordered(t *testing.T) {
	var w ReplayWindow
	for base := uint64(0); base < 10*windowSize; base += 100 {
		for i := uint64(100); i > 0; i-- {
			if !w.Accept(base + i - 1) {
				t.Fatalf("Accept(%d) = false on first sight", base+i-1)
			}
		}
		for i := range uint64(100) {
			if w.Accept(base + i) {
				t.Fatalf("Accept(%d) = true on second sight", base+i)
			}
		}
	}
}
