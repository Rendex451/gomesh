package crypto

import "sync"

// Sliding window from RFC 6479: a ring of bitmap blocks. One block is
// kept spare so the window can slide by whole blocks.
const (
	blockBits  = 64
	ringBlocks = 32
	windowSize = (ringBlocks - 1) * blockBits
)

// ReplayWindow rejects repeated counters and counters older than
// windowSize behind the largest one seen. The zero value is ready to use.
type ReplayWindow struct {
	mu   sync.Mutex
	max  uint64
	ring [ringBlocks]uint64
}

// Accept reports whether counter is new, and marks it as seen.
func (w *ReplayWindow) Accept(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	block := counter / blockBits
	if counter > w.max {
		// Clear the blocks the window slides over.
		cur := w.max / blockBits
		diff := min(block-cur, ringBlocks)
		for i := cur + 1; i <= cur+diff; i++ {
			w.ring[i%ringBlocks] = 0
		}
		w.max = counter
	} else if w.max-counter > windowSize {
		return false
	}

	bit := uint64(1) << (counter % blockBits)
	old := w.ring[block%ringBlocks]
	w.ring[block%ringBlocks] = old | bit
	return old&bit == 0
}
