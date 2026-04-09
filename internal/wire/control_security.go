package wire

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The auth keys provided by the server are 64 bytes, but tls-auth
// only uses the first 20
const CONTROL_CHANNEL_KEY_TOTAL_LENGTH = 64

// These keys are utilised by two control channel security features:
// - all except "none" - Generating an verifying HMAC digest
// - tls-crypt(-v2) - Encrypting/Decrypting control packet contents
type ControlChannelKey [CONTROL_CHANNEL_KEY_TOTAL_LENGTH]byte

// Only a prefix of the 64-byte key chunk is used for HMAC operations.
// For tls-auth the length equals the digest size (e.g. 20 for SHA1, 32 for SHA256).
// For tls-crypt the key is always 32 bytes.
const TLS_CRYPT_KEY_LENGTH = 32

// HMAC signature used for tls-crypt (always SHA256)
type SHA256HMACDigest [32]byte

// AuthNameToHash maps an OpenVPN --auth name to the corresponding crypto.Hash.
// An empty name defaults to SHA1 (OpenVPN's built-in default).
func AuthNameToHash(name string) (crypto.Hash, error) {
	switch strings.ToUpper(name) {
	case "", "SHA1", "SHA-1":
		return crypto.SHA1, nil
	case "SHA256", "SHA-256":
		return crypto.SHA256, nil
	case "SHA512", "SHA-512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported tls-auth digest: %s", name)
	}
}

const (
	OVPN_STATIC_KEY_BEGIN       = "-----BEGINOpenVPNStatickeyV1-----"
	OVPN_STATIC_KEY_END         = "-----ENDOpenVPNStatickeyV1-----"
	OVPN_TLS_CRYPT_V2_KEY_BEGIN = "-----BEGINOpenVPNtls-crypt-v2clientkey-----"
	OVPN_TLS_CRYPT_V2_KEY_END   = "-----ENDOpenVPNtls-crypt-v2clientkey-----"
)

var errParsingTLSAuth = errors.New("error parsing provided tls-auth key")

type ControlSecurityMode int

const (
	ControlSecurityModeNone ControlSecurityMode = iota
	ControlSecurityModeTLSAuth
	ControlSecurityModeTLSCrypt
	ControlSecurityModeTLSCryptV2
)

type ControlChannelSecurity struct {
	// Determines the type of control channel security in use
	Mode ControlSecurityMode

	// TLSAuthDigest is the HMAC hash algorithm used for tls-auth (from --auth).
	// Ignored for tls-crypt/tls-crypt-v2, which always use SHA256.
	TLSAuthDigest crypto.Hash

	// Used by ParsePacket() to verify HMAC digest provided by server + decrypt control channel
	RemoteCipherKey *ControlChannelKey
	RemoteDigestKey *ControlChannelKey

	// Used by SerializePacket() to calculate HMAC digest + encrypt control channel
	LocalCipherKey *ControlChannelKey
	LocalDigestKey *ControlChannelKey

	// Used exclusively for tls-cryptv2 (WKc)
	WrappedClientKey []byte
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts the
// tls-auth key material. digest is the HMAC algorithm (from --auth, e.g. crypto.SHA256).
func NewControlChannelSecurityTLSAuth(encoded []byte, direction int, digest crypto.Hash) (*ControlChannelSecurity, error) {
	buf, err := extractStaticKeyData(encoded)
	if err != nil {
		return nil, err
	}

	// keyData is divided into 4 equal 64-byte chunks.
	// For tls-auth only chunks at positions 1 and 3 are used (HMAC keys).
	n := len(buf) / 4
	a := buf[n : n+CONTROL_CHANNEL_KEY_TOTAL_LENGTH]
	b := buf[3*n : 3*n+CONTROL_CHANNEL_KEY_TOTAL_LENGTH]

	var localDigestKey, remoteDigestKey ControlChannelKey
	switch direction {
	case 0:
		copy(localDigestKey[:], a)
		copy(remoteDigestKey[:], b)
	case 1:
		copy(localDigestKey[:], b)
		copy(remoteDigestKey[:], a)
	default:
		return nil, errParsingTLSAuth
	}

	return &ControlChannelSecurity{
		Mode:            ControlSecurityModeTLSAuth,
		TLSAuthDigest:   digest,
		LocalDigestKey:  &localDigestKey,
		RemoteDigestKey: &remoteDigestKey,
	}, nil
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts into a PacketAuth struct
func NewControlChannelSecurityTLSCrypt(encoded []byte) (*ControlChannelSecurity, error) {
	buf, err := extractStaticKeyData(encoded)
	if err != nil {
		return nil, err
	}

	n := len(buf) / 4
	var localCipherKey, localDigestKey, remoteCipherKey, remoteDigestKey ControlChannelKey
	copy(remoteCipherKey[:], buf[:n])
	copy(remoteDigestKey[:], buf[n:2*n])
	copy(localCipherKey[:], buf[2*n:3*n])
	copy(localDigestKey[:], buf[3*n:])
	return &ControlChannelSecurity{Mode: ControlSecurityModeTLSCrypt, RemoteCipherKey: &remoteCipherKey, RemoteDigestKey: &remoteDigestKey, LocalCipherKey: &localCipherKey, LocalDigestKey: &localDigestKey}, nil
}

// "static" keys are used by tls-auth and tls-crypt modes.
// (fixed_header | hexadecimal key data | fixed_trailer)
func extractStaticKeyData(encoded []byte) ([]byte, error) {
	s := strings.ReplaceAll(string(encoded), "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	beginIdx := strings.Index(s, OVPN_STATIC_KEY_BEGIN)
	if beginIdx < 0 {
		return nil, errParsingTLSAuth
	}
	s = s[beginIdx+len(OVPN_STATIC_KEY_BEGIN):]

	endIdx := strings.Index(s, OVPN_STATIC_KEY_END)
	if endIdx < 0 {
		return nil, errParsingTLSAuth
	}
	s = s[:endIdx]

	return hex.DecodeString(s)
}

func NewControlChannelSecurityTLSCryptV2(encoded []byte) (*ControlChannelSecurity, error) {
	b, err := extractCryptV2KeyData(encoded)
	if err != nil {
		return nil, err
	}

	// The tls-crypt-v2 block first contains 4 * AUTH_KEY_TOTAL_LENGTH keys, then a variable length WrappedClientKey
	keyData := b[:4*CONTROL_CHANNEL_KEY_TOTAL_LENGTH]
	WKc := b[4*CONTROL_CHANNEL_KEY_TOTAL_LENGTH:]

	n := len(keyData) / 4
	var localCipherKey, localDigestKey, remoteCipherKey, remoteDigestKey ControlChannelKey
	copy(remoteCipherKey[:], keyData[:n])
	copy(remoteDigestKey[:], keyData[n:2*n])
	copy(localCipherKey[:], keyData[2*n:3*n])
	copy(localDigestKey[:], keyData[3*n:])

	return &ControlChannelSecurity{
		Mode:             ControlSecurityModeTLSCryptV2,
		RemoteCipherKey:  &remoteCipherKey,
		RemoteDigestKey:  &remoteDigestKey,
		LocalCipherKey:   &localCipherKey,
		LocalDigestKey:   &localDigestKey,
		WrappedClientKey: WKc,
	}, nil
}

// "crypt-v2" keys are used only by tls-crypt-v2.
// (fixed_header | base64 key data | fixed_trailer)
func extractCryptV2KeyData(encoded []byte) ([]byte, error) {
	s := strings.ReplaceAll(string(encoded), "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.TrimPrefix(s, OVPN_TLS_CRYPT_V2_KEY_BEGIN)
	s = strings.TrimSuffix(s, OVPN_TLS_CRYPT_V2_KEY_END)

	return base64.StdEncoding.DecodeString(s)
}

func GenerateTLSAuthDigest(key *ControlChannelKey, digest crypto.Hash, header []byte, replay []byte, message []byte) []byte {
	h := hmac.New(digest.New, key[:digest.Size()])

	h.Write(replay)
	h.Write(header)
	h.Write(message)

	return h.Sum(nil)
}

func GenerateTLSCryptDigest(key *ControlChannelKey, header []byte, replay []byte, message []byte) SHA256HMACDigest {
	h := hmac.New(crypto.SHA256.New, key[:TLS_CRYPT_KEY_LENGTH])

	// N.B. order of packet chunks is different to tls-auth
	h.Write(header)
	h.Write(replay)
	h.Write(message)

	sig := h.Sum(nil)
	return SHA256HMACDigest(sig)
}

func EncryptControlMessage(hmac SHA256HMACDigest, key ControlChannelKey, msg []byte) ([]byte, error) {
	return doControlEncryptionXOR(hmac, key, msg)
}

func DecryptControlMessage(hmac SHA256HMACDigest, key ControlChannelKey, ct []byte) ([]byte, error) {
	return doControlEncryptionXOR(hmac, key, ct)
}

// Since performing an XOR with the key stream is a symmetric function, the
// exact same operation can be performed for both encryption and decryption
// of the encrypted portion of tls-crypt(-v2) packets
func doControlEncryptionXOR(hmac SHA256HMACDigest, key ControlChannelKey, in []byte) ([]byte, error) {
	out := make([]byte, len(in))

	// OpenVPN uses first 16 bytes of HMAC as IV
	iv := hmac[:16]

	// 3. AES-256-CTR encryption
	block, err := aes.NewCipher(key[:32]) // only use first 32 bytes
	if err != nil {
		return out, err
	}
	ctr := cipher.NewCTR(block, iv)

	ctr.XORKeyStream(out, in)

	return out, nil
}
