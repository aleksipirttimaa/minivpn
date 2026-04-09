package wire

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

// keyDataWithComments is the same key prefixed with the comment block that
// openvpn-keygen emits by default, to guard against regressions in comment stripping.
const keyDataWithComments = `#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
f5f052e38b86c44a7f190157e59e94fa
dd67c1974759d1521c2601c96a2baccc
162d549ac46d5fa7fdc45550c77d6952
04b99e30a15b7481541a9f18d9e010c5
a614a468e67a9997835bfc0644f295b9
a413f0cc6ef2e7ac3901b42ba039a9a4
51e02593b8aa059c748ac87dade38eae
bf6fa8a43caa2623225611020128917b
cf60d356a7eeb48d91b230251039a3ff
465815ec7d34d4d132446adacb75dd8c
2eb99ddae3dc5deadfe88d78ec4a52fa
df2f0706a2be4814589dcb5d3b276bf3
3654df5a7241d003f4729fece1c02793
811c4d10e06d969f9798ced2a24c2f76
c040024d19256531a37502ad3487ca8f
34335f34d61fb3be37946fa0c9ae1898
-----END OpenVPN Static key V1-----`

const keyData = `-----BEGIN OpenVPN Static key V1-----
f5f052e38b86c44a7f190157e59e94fa
dd67c1974759d1521c2601c96a2baccc
162d549ac46d5fa7fdc45550c77d6952
04b99e30a15b7481541a9f18d9e010c5
a614a468e67a9997835bfc0644f295b9
a413f0cc6ef2e7ac3901b42ba039a9a4
51e02593b8aa059c748ac87dade38eae
bf6fa8a43caa2623225611020128917b
cf60d356a7eeb48d91b230251039a3ff
465815ec7d34d4d132446adacb75dd8c
2eb99ddae3dc5deadfe88d78ec4a52fa
df2f0706a2be4814589dcb5d3b276bf3
3654df5a7241d003f4729fece1c02793
811c4d10e06d969f9798ced2a24c2f76
c040024d19256531a37502ad3487ca8f
34335f34d61fb3be37946fa0c9ae1898
-----END OpenVPN Static key V1-----`

const (
	key0 = "a614a468e67a9997835bfc0644f295b9a413f0cc6ef2e7ac3901b42ba039a9a451e02593b8aa059c748ac87dade38eaebf6fa8a43caa2623225611020128917b"
	key1 = "3654df5a7241d003f4729fece1c02793811c4d10e06d969f9798ced2a24c2f76c040024d19256531a37502ad3487ca8f34335f34d61fb3be37946fa0c9ae1898"
)

func TestNewControlChannelSecurityTLSAuth(t *testing.T) {
	k0, _ := hex.DecodeString(key0)
	k1, _ := hex.DecodeString(key1)

	t.Run("direction=1: local=key1, remote=key0", func(t *testing.T) {
		ccs, err := NewControlChannelSecurityTLSAuth([]byte(keyData), 1, crypto.SHA1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(ccs.LocalDigestKey[:len(k1)], k1) {
			t.Errorf("local key: got=%x want=%x", ccs.LocalDigestKey[:len(k1)], k1)
		}
		if !bytes.Equal(ccs.RemoteDigestKey[:len(k0)], k0) {
			t.Errorf("remote key: got=%x want=%x", ccs.RemoteDigestKey[:len(k0)], k0)
		}
	})

	t.Run("direction=0: local=key0, remote=key1", func(t *testing.T) {
		ccs, err := NewControlChannelSecurityTLSAuth([]byte(keyData), 0, crypto.SHA1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(ccs.LocalDigestKey[:len(k0)], k0) {
			t.Errorf("local key: got=%x want=%x", ccs.LocalDigestKey[:len(k0)], k0)
		}
		if !bytes.Equal(ccs.RemoteDigestKey[:len(k1)], k1) {
			t.Errorf("remote key: got=%x want=%x", ccs.RemoteDigestKey[:len(k1)], k1)
		}
	})

	t.Run("invalid direction returns error", func(t *testing.T) {
		_, err := NewControlChannelSecurityTLSAuth([]byte(keyData), 2, crypto.SHA1)
		if err == nil {
			t.Error("expected error for invalid direction, got nil")
		}
	})

	t.Run("key file with leading comments is parsed correctly", func(t *testing.T) {
		ccs, err := NewControlChannelSecurityTLSAuth([]byte(keyDataWithComments), 1, crypto.SHA1)
		if err != nil {
			t.Fatalf("unexpected error with commented key: %v", err)
		}
		if !bytes.Equal(ccs.LocalDigestKey[:len(k1)], k1) {
			t.Errorf("local key: got=%x want=%x", ccs.LocalDigestKey[:len(k1)], k1)
		}
		if !bytes.Equal(ccs.RemoteDigestKey[:len(k0)], k0) {
			t.Errorf("remote key: got=%x want=%x", ccs.RemoteDigestKey[:len(k0)], k0)
		}
	})
}

func TestGeneratePacketHMAC(t *testing.T) {
	var k1 ControlChannelKey
	hex.Decode(k1[:], []byte(key1))

	sessionId, _ := hex.DecodeString("529034d4d6b753b6")
	timestamp, _ := hex.DecodeString("67444aed")

	pack := &model.Packet{
		Opcode:         model.P_CONTROL_HARD_RESET_CLIENT_V2,
		LocalSessionID: model.SessionID(sessionId),
		Timestamp:      model.PacketTimestamp(binary.BigEndian.Uint32(timestamp)),
		ReplayPacketID: 1,
		ID:             0,
	}
	want, _ := hex.DecodeString("9f4a9edd3182c8d4a0c07702a8f7e2e2aefba299")

	t.Run("valid hmac signature calculated from packet", func(t *testing.T) {
		replay := replayProtectionBytes(pack)
		header := headerBytes(pack)
		msg, _ := controlMessageBytes(pack)
		digest := GenerateTLSAuthDigest(&k1, crypto.SHA1, header, replay, msg)

		if !bytes.Equal(digest, want) {
			t.Errorf("incorrect hmac generated got=%x want=%x", digest, want)
		}
	})
}
