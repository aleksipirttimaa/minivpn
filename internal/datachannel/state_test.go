package datachannel

import "testing"

func Test_replayWindow_checkAndRecord(t *testing.T) {
	tests := []struct {
		name string
		ids  []uint32
		want []bool
	}{
		{
			name: "in-order accepted",
			ids:  []uint32{1, 2, 3, 4},
			want: []bool{true, true, true, true},
		},
		{
			name: "duplicate rejected",
			ids:  []uint32{1, 1},
			want: []bool{true, false},
		},
		{
			name: "zero always rejected",
			ids:  []uint32{0},
			want: []bool{false},
		},
		{
			name: "out-of-order within window accepted",
			ids:  []uint32{1, 3, 2},
			want: []bool{true, true, true},
		},
		{
			name: "out-of-order duplicate rejected",
			ids:  []uint32{1, 3, 1},
			want: []bool{true, true, false},
		},
		{
			name: "just inside window accepted",
			// maxID will be replayWindowSize; id=1 is replayWindowSize-1 steps behind.
			ids: func() []uint32 {
				ids := make([]uint32, replayWindowSize+1)
				for i := range ids {
					ids[i] = uint32(i + 1)
				}
				// replace last: id=1 is replayWindowSize-1 behind maxID, inside window
				// but already seen — replace with an unseen id that is inside the window.
				// Use id=replayWindowSize (second to last), which was already sent,
				// so instead probe with a gap: send 1..replayWindowSize-1, then skip
				// replayWindowSize, jump to replayWindowSize+1, then re-send the skipped one.
				return nil // handled by separate test case below
			}(),
			want: nil,
		},
		{
			name: "skipped ID within window accepted after advance",
			// Send 1, 3 (skip 2), advance to 4, then send 2 (3 behind, in window).
			ids:  []uint32{1, 3, 4, 2},
			want: []bool{true, true, true, true},
		},
		{
			name: "outside window rejected",
			// Send 1, then jump to replayWindowSize+2. id=1 is now replayWindowSize+1 behind.
			ids:  []uint32{1, replayWindowSize + 2, 1},
			want: []bool{true, true, false},
		},
		{
			name: "large jump clears window, unseen nearby ID accepted",
			// id=137 is 63 positions behind 200 (just inside a 64-slot window).
			ids:  []uint32{1, 200, 137},
			want: []bool{true, true, true},
		},
		{
			name: "large jump clears window, old ID rejected",
			ids:  []uint32{1, 200, 1},
			want: []bool{true, true, false},
		},
	}

	for _, tt := range tests {
		if tt.ids == nil {
			continue // skip placeholder cases
		}
		t.Run(tt.name, func(t *testing.T) {
			var w replayWindow
			for i, id := range tt.ids {
				got := w.checkAndRecord(id)
				if got != tt.want[i] {
					t.Errorf("step %d id=%d: got %v, want %v", i, id, got, tt.want[i])
				}
			}
		})
	}
}
