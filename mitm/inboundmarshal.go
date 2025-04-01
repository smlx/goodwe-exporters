package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// InboundHeader represents the header of an inbound packet.
type InboundHeader struct {
	GW         [2]byte // GW prefix
	Length     uint32  // Off-by-one
	PacketType [2]byte // Packet type identifier
}

// MarshalBinary implements binary.Marshaler
func (h *InboundHeader) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, h); err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", h, err)
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (h *InboundHeader) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	return binary.Read(buf, binary.BigEndian, h)
}

// InboundEnvelope is the plaintext wrapper around the ciphertext.
type InboundEnvelope struct {
	DeviceID     [8]byte  // ASCII
	DeviceSerial [8]byte  // ASCII
	IV           [16]byte // AES-128 Initialization Vector
}

// InboundMetricsAck is the inbound metrics ACK cleartext.
type InboundMetricsAck struct {
	Data [16]byte // Metrics ACK payload (null bytes).
}

// InboundMetricsAckPacket represents the body of an inbound metrics ack
// packet.
type InboundMetricsAckPacket struct {
	InboundEnvelope
	InboundMetricsAck
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *InboundMetricsAckPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.InboundEnvelope)],
		data[binary.Size(p.InboundEnvelope):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.InboundEnvelope)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.InboundEnvelope, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.InboundMetricsAck) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.InboundMetricsAck)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// InboundTimeSyncResp is the cleartext body of an inbound time sync packet.
type InboundTimeSyncResp struct {
	PacketType   [4]byte   // 0x00-0x03 Packet type?
	Timestamp    Timestamp // 0x04-0x09 Y M D H m s
	UnknownBytes [6]byte   // 0x0a-0x0f Fixed null?
}

// InboundTimeSyncRespPacket represents the body of an inbound metrics ack
// packet.
type InboundTimeSyncRespPacket struct {
	InboundEnvelope
	InboundTimeSyncResp
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *InboundTimeSyncRespPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.InboundEnvelope)],
		data[binary.Size(p.InboundEnvelope):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.InboundEnvelope)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.InboundEnvelope, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.InboundTimeSyncResp) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.InboundTimeSyncResp)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}
