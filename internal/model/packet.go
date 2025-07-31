package model

//
// Packet
//
// Parsing and serializing OpenVPN packets.
//

import (
	"bytes"
	"errors"
)

// Opcode is an OpenVPN packet opcode.
type Opcode byte

// OpenVPN packets opcodes.
const (
	P_CONTROL_HARD_RESET_CLIENT_V1 = Opcode(iota + 1) // 1
	P_CONTROL_HARD_RESET_SERVER_V1                    // 2
	P_CONTROL_SOFT_RESET_V1                           // 3
	P_CONTROL_V1                                      // 4
	P_ACK_V1                                          // 5
	P_DATA_V1                                         // 6
	P_CONTROL_HARD_RESET_CLIENT_V2                    // 7
	P_CONTROL_HARD_RESET_SERVER_V2                    // 8
	P_DATA_V2                                         // 9
	P_CONTROL_HARD_RESET_CLIENT_V3                    // 10
	P_CONTROL_WKC_V1                                  // 11
)

// NewOpcodeFromString returns an opcode from a string representation, and an error if it cannot parse the opcode
// representation. The zero return value is invalid and always coupled with a non-nil error.
func NewOpcodeFromString(s string) (Opcode, error) {
	switch s {
	case "CONTROL_HARD_RESET_CLIENT_V1":
		return P_CONTROL_HARD_RESET_CLIENT_V1, nil
	case "CONTROL_HARD_RESET_SERVER_V1":
		return P_CONTROL_HARD_RESET_SERVER_V1, nil
	case "CONTROL_SOFT_RESET_V1":
		return P_CONTROL_SOFT_RESET_V1, nil
	case "CONTROL_V1":
		return P_CONTROL_V1, nil
	case "ACK_V1":
		return P_ACK_V1, nil
	case "DATA_V1":
		return P_DATA_V1, nil
	case "CONTROL_HARD_RESET_CLIENT_V2":
		return P_CONTROL_HARD_RESET_CLIENT_V2, nil
	case "CONTROL_HARD_RESET_SERVER_V2":
		return P_CONTROL_HARD_RESET_SERVER_V2, nil
	case "DATA_V2":
		return P_DATA_V2, nil
	case "P_CONTROL_HARD_RESET_CLIENT_V3":
		return P_CONTROL_HARD_RESET_CLIENT_V3, nil
	case "P_CONTROL_WKC_V1":
		return P_CONTROL_WKC_V1, nil
		// 11
	default:
		return 0, errors.New("unknown opcode")
	}
}

// String returns the opcode string representation
func (op Opcode) String() string {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"

	case P_CONTROL_HARD_RESET_SERVER_V1:
		return "P_CONTROL_HARD_RESET_SERVER_V1"

	case P_CONTROL_SOFT_RESET_V1:
		return "P_CONTROL_SOFT_RESET_V1"

	case P_CONTROL_V1:
		return "P_CONTROL_V1"

	case P_ACK_V1:
		return "P_ACK_V1"

	case P_DATA_V1:
		return "P_DATA_V1"

	case P_CONTROL_HARD_RESET_CLIENT_V2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"

	case P_CONTROL_HARD_RESET_SERVER_V2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"

	case P_DATA_V2:
		return "P_DATA_V2"

	case P_CONTROL_HARD_RESET_CLIENT_V3:
		return "P_CONTROL_HARD_RESET_CLIENT_V3"

	case P_CONTROL_WKC_V1:
		return "P_CONTROL_WKC_V1"

	default:
		return "P_UNKNOWN"
	}
}

// IsControl returns true when this opcode is a control opcode.
func (op Opcode) IsControl() bool {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1,
		P_CONTROL_HARD_RESET_SERVER_V1,
		P_CONTROL_SOFT_RESET_V1,
		P_CONTROL_V1,
		P_CONTROL_HARD_RESET_CLIENT_V2,
		P_CONTROL_HARD_RESET_CLIENT_V3,
		P_CONTROL_WKC_V1,
		P_CONTROL_HARD_RESET_SERVER_V2:
		return true
	default:
		return false
	}
}

// IsData returns true when this opcode is a data opcode.
func (op Opcode) IsData() bool {
	switch op {
	case P_DATA_V1, P_DATA_V2:
		return true
	default:
		return false
	}
}

// SessionID is the session identifier.
type SessionID [8]byte

// PacketID is a packet identifier.
type PacketID uint32

// PeerID is the type of the P_DATA_V2 peer ID.
type PeerID [3]byte

// Optional timestamp field used for tls-auth (seconds since the epoch)
type PacketTimestamp uint32

// Packet is an OpenVPN packet.
type Packet struct {
	// Opcode is the packet message type (a P_* constant; high 5-bits of
	// the first packet byte).
	Opcode Opcode

	// The key_id refers to an already negotiated TLS session.
	// This is the shortened version of the key-id (low 3-bits of the first
	// packet byte).
	KeyID byte

	// PeerID is the peer ID.
	PeerID PeerID

	// LocalSessionID is the local session ID.
	LocalSessionID SessionID

	// An additional packet id used for replay protection in tls-auth mode ONLY. A seperate
	// counter is used that additional includes p_ACK packets
	ReplayPacketID PacketID

	// Optional timestamp field used for tls-auth (seconds since the epoch)
	Timestamp PacketTimestamp

	// Acks contains the remote packets we're ACKing.
	ACKs []PacketID

	// RemoteSessionID is the remote session ID.
	RemoteSessionID SessionID

	// message packet-id (4 bytes)
	ID PacketID

	// Payload is the packet's payload.
	Payload []byte
}

// NewPacket returns a packet from the passed arguments: opcode, keyID and a raw payload.
func NewPacket(opcode Opcode, keyID uint8, payload []byte) *Packet {
	return &Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          [3]byte{},
		LocalSessionID:  [8]byte{},
		ACKs:            []PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
}

// IsControl returns true if the packet is any of the control types.
func (p *Packet) IsControl() bool {
	return p.Opcode.IsControl()
}

// IsData returns true if the packet is of data type.
func (p *Packet) IsData() bool {
	return p.Opcode.IsData()
}

var pingPayload = []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}

// IsPing returns true if this packet matches a openvpn ping packet.
func (p *Packet) IsPing() bool {
	return bytes.Equal(pingPayload, p.Payload)
}

// Log writes an entry in the passed logger with a representation of this packet.
func (p *Packet) Log(logger Logger, direction Direction) {
	var dir string
	switch direction {
	case DirectionIncoming:
		dir = "<"
	case DirectionOutgoing:
		dir = ">"
	default:
		logger.Warnf("wrong direction: %d", direction)
		return
	}

	logger.Debugf(
		"%s %s {id=%d, acks=%v} localID=%x remoteID=%x [%d bytes]",
		dir,
		p.Opcode,
		p.ID,
		p.ACKs,
		p.LocalSessionID,
		p.RemoteSessionID,
		len(p.Payload),
	)
}
