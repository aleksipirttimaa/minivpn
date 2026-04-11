package datachannel

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

// makeNonAEADBuffer builds a minimal non-AEAD plaintext buffer where the
// first four bytes encode id and the rest are payload.
func makeNonAEADBuffer(id uint32, payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, id)
	copy(buf[4:], payload)
	return buf
}

func Test_decodeEncryptedPayloadAEAD(t *testing.T) {
	state := makeTestingStateAEAD()
	goodEncryptedPayload, _ := hex.DecodeString("00000000b3653a842f2b8a148de26375218fb01d31278ff328ff2fc65c4dbf9eb8e67766")
	goodDecodeIV, _ := hex.DecodeString("000000006868686868686868")
	goodDecodeCipherText, _ := hex.DecodeString("31278ff328ff2fc65c4dbf9eb8e67766b3653a842f2b8a148de26375218fb01d")
	goodDecodeAEAD, _ := hex.DecodeString("4800000000000000")

	type args struct {
		buf     []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr error
	}{
		{
			"empty buffer should fail",
			args{
				[]byte{},
				makeTestingSession(),
				state,
			},
			&encryptedData{},
			ErrTooShort,
		},
		{
			"too short should fail",
			args{
				bytes.Repeat([]byte{0xff}, 19),
				makeTestingSession(),
				state,
			},
			&encryptedData{},
			ErrTooShort,
		},
		{
			"good decode should not fail",
			args{
				goodEncryptedPayload,
				makeTestingSession(),
				state,
			},
			&encryptedData{
				iv:         goodDecodeIV,
				ciphertext: goodDecodeCipherText,
				aead:       goodDecodeAEAD,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadAEAD(log.Log, tt.args.buf, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("decodeEncryptedPayloadAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeEncryptedPayloadAEAD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeEncryptedPayloadNonAEAD(t *testing.T) {

	goodInput, _ := hex.DecodeString("fdf9b069b2e5a637fa7b5c9231166ea96307e4123031323334353637383930313233343581e4878c5eec602c2d2f5a95139c84af")
	iv, _ := hex.DecodeString("30313233343536373839303132333435")
	ciphertext, _ := hex.DecodeString("81e4878c5eec602c2d2f5a95139c84af")

	type args struct {
		buf     []byte
		session *session.Manager
		state   *dataChannelState
	}
	tests := []struct {
		name    string
		args    args
		want    *encryptedData
		wantErr error
	}{
		{
			name: "empty buffer should fail",
			args: args{
				[]byte{},
				makeTestingSession(),
				makeTestingStateNonAEAD(),
			},
			want:    &encryptedData{},
			wantErr: ErrCannotDecode,
		},
		{
			name: "too short buffer should fail",
			args: args{
				bytes.Repeat([]byte{0xff}, 27),
				makeTestingSession(),
				makeTestingStateNonAEAD(),
			},
			want:    &encryptedData{},
			wantErr: ErrCannotDecode,
		},
		{
			name: "good decode",
			args: args{
				goodInput,
				makeTestingSession(),
				makeTestingStateNonAEADReversed(),
			},
			want: &encryptedData{
				iv:         iv,
				ciphertext: ciphertext,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEncryptedPayloadNonAEAD(log.Log, tt.args.buf, tt.args.session, tt.args.state)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("decodeEncryptedPayloadNonAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got.iv, tt.want.iv) {
				t.Errorf("decodeEncryptedPayloadNonAEAD().iv = %v, want %v", got.iv, tt.want.iv)
			}
			if !bytes.Equal(got.ciphertext, tt.want.ciphertext) {
				t.Errorf("decodeEncryptedPayloadNonAEAD().iv = %v, want %v", got.iv, tt.want.iv)
			}
		})
	}
}

// Test_maybeDecompress_replayWindow exercises the sliding-window replay filter
// inside maybeDecompress for non-AEAD ciphers. Each step shares the same
// dataChannelState to simulate sequential packet reception.
func Test_maybeDecompress_replayWindow(t *testing.T) {
	payload := []byte("data")
	opts := &config.OpenVPNOptions{} // no compression

	type step struct {
		name    string
		id      uint32
		wantErr error
	}

	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "in-order packets are all accepted",
			steps: []step{
				{"id=1", 1, nil},
				{"id=2", 2, nil},
				{"id=3", 3, nil},
			},
		},
		{
			name: "out-of-order within window is accepted",
			steps: []step{
				{"id=1", 1, nil},
				{"id=3", 3, nil},
				{"id=2 arrives late but within window", 2, nil},
			},
		},
		{
			name: "duplicate packet is rejected",
			steps: []step{
				{"id=1 first", 1, nil},
				{"id=1 duplicate", 1, ErrReplayAttack},
			},
		},
		{
			name: "zero packet ID is always rejected",
			steps: []step{
				{"id=0", 0, ErrReplayAttack},
			},
		},
		{
			name: "packet outside the window is rejected",
			// Advance maxID to replayWindowSize+1 then send id=1 which
			// is replayWindowSize positions behind and thus out of window.
			steps: func() []step {
				ss := make([]step, 0, replayWindowSize+2)
				for i := uint32(1); i <= replayWindowSize+1; i++ {
					ss = append(ss, step{name: "advance", id: i, wantErr: nil})
				}
				ss = append(ss, step{"id=1 now outside window", 1, ErrReplayAttack})
				return ss
			}(),
		},
		{
			name: "last slot inside window is accepted",
			// maxID advances to replayWindowSize, then id=1 is exactly
			// replayWindowSize-1 positions behind (inside the window).
			steps: func() []step {
				ss := make([]step, 0, replayWindowSize+1)
				for i := uint32(1); i <= replayWindowSize; i++ {
					ss = append(ss, step{name: "advance", id: i, wantErr: nil})
				}
				// id=1 is replayWindowSize-1 steps behind maxID=replayWindowSize: still inside.
				ss = append(ss, step{"id=1 just inside window", 1, ErrReplayAttack}) // already seen during advance
				return ss
			}(),
		},
		{
			name: "large jump clears window, old IDs rejected",
			steps: []step{
				{"id=1", 1, nil},
				{"id=200 clears window", 200, nil},
				{"id=1 now outside window", 1, ErrReplayAttack},
			},
		},
		{
			name: "large jump clears window, recent unseen ID accepted",
			steps: []step{
				{"id=1", 1, nil},
				{"id=200 clears window", 200, nil},
				// id=137 is 63 positions behind 200: within window, unseen.
				{"id=137 within window unseen", 137, nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := makeTestingStateNonAEAD()
			for _, s := range tt.steps {
				buf := makeNonAEADBuffer(s.id, payload)
				_, err := maybeDecompress(buf, st, opts)
				if !errors.Is(err, s.wantErr) {
					t.Errorf("step %q (id=%d): got err %v, want %v", s.name, s.id, err, s.wantErr)
				}
			}
		})
	}
}
