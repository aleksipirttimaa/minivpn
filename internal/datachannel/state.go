package datachannel

import (
	"hash"
	"sync"
)

// replayWindowSize is the number of packet IDs the sliding window tracks.
// Matches OpenVPN's DEFAULT_SEQ_BACKTRACK (packet_id.h).
const replayWindowSize = 64

// replayWindow is a sliding-window duplicate / replay filter for the
// non-AEAD data channel. It accepts a packet ID if it is either ahead of
// the highest ID seen so far, or within replayWindowSize positions behind
// and not already received.
type replayWindow struct {
	maxID  uint32
	seen   [replayWindowSize]bool
	ready  bool
}

// checkAndRecord returns true and records the ID if the packet should be
// accepted, or false if it is a replay or outside the window.
func (w *replayWindow) checkAndRecord(id uint32) bool {
	if id == 0 {
		return false // OpenVPN rejects packet ID zero
	}
	if !w.ready {
		w.maxID = id
		w.seen[id%replayWindowSize] = true
		w.ready = true
		return true
	}
	if id > w.maxID {
		// Advance the window, clearing any slots that fall into the new range.
		advance := id - w.maxID
		if advance >= replayWindowSize {
			w.seen = [replayWindowSize]bool{}
		} else {
			for i := uint32(1); i <= advance; i++ {
				w.seen[(w.maxID+i)%replayWindowSize] = false
			}
		}
		w.maxID = id
		w.seen[id%replayWindowSize] = true
		return true
	}
	diff := w.maxID - id
	if diff >= replayWindowSize {
		return false // too far behind the window
	}
	slot := id % replayWindowSize
	if w.seen[slot] {
		return false // already received
	}
	w.seen[slot] = true
	return true
}

// keySlot holds the different local and remote keys.
type keySlot [64]byte

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	dataCipher dataCipher

	// outgoing and incoming nomenclature is probably more adequate here.
	hmacLocal       hash.Hash
	hmacRemote      hash.Hash
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	replay replayWindow

	hash func() hash.Hash
	mu   sync.Mutex

	// not used at the moment, paving the way for key rotation.
	// keyID           int
}

// CheckAndRecord accepts or rejects an incoming packet ID using the sliding
// replay window. It is safe for concurrent use.
func (dcs *dataChannelState) CheckAndRecord(id uint32) bool {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	return dcs.replay.checkAndRecord(id)
}
