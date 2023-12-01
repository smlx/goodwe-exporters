package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// OutboundHeader represents the header of an outbound packet.
type OutboundHeader struct {
	PostGW     [6]byte // POSTGW prefix
	Length     uint32  // Off-by-one
	PacketType [2]byte // Packet type identifier
}

// MarshalBinary implements binary.Marshaler
func (h *OutboundHeader) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, h); err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", h, err)
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (h *OutboundHeader) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	return binary.Read(buf, binary.BigEndian, h)
}

// OutboundEnvelopeTS is the plaintext wrapper, with a timestamp, around the
// ciphertext.
type OutboundEnvelopeTS struct {
	UnknownBytes [2]byte // Fixed null alignment padding?
	DeviceID     [8]byte // ASCII
	DeviceSerial [8]byte // ASCII
	IV           [16]byte
	Timestamp    Timestamp // Y M D H m s
}

// OutboundMetrics is the cleartext body of an outbound metrics packet.
type OutboundMetrics struct {
	PacketType                                        [7]byte  // 0x00-0x06 Packet type?
	EnergyExportDecawattHoursTotal                    int32    // 0x07-0x0a Units of 10 watt-hours
	UnknownBytes1                                     [2]byte  // 0x0b-0x0c Fixed null?
	EnergyGenerationDecawattHoursTotal                int32    // 0x0d-0x10 Units of 10 watt-hours
	UnknownBytes2                                     [8]byte  // 0x11-0x18 Fixed null?
	SumOfEnergyGenerationAndExportDecawattHoursTotal  int32    // 0x19-0x1c Units of 10 watt-hours
	UnknownBytes3                                     [2]byte  // 0x1d-0x1e Fixed null?
	EnergyImportDecawattHoursTotal                    int32    // 0x1f-0x22 Units of 10 watt-hours
	UnknownBytes4                                     [16]byte // 0x23-0x32 Fixed bytes?
	SumOfEnergyImportLessGenerationDecawattHoursTotal int16    // 0x33-0x34 Units of 10 watt-hours
	UnknownInt5                                       int32    // 0x35-0x38 Fixed int value?
	UnknownInt6                                       int16    // 0x39-0x3a Gauge?
	UnknownInt7                                       int16    // 0x3b-0x3c Gauge?
	UnknownInt8                                       int16    // 0x3d-0x3e Incrementing counter?
	UnknownInt9                                       int32    // 0x3f-0x42 Gauge?
	UnknownInt10                                      int32    // 0x43-0x46 Gauge?
	UnknownInt11                                      int32    // 0x47-0x4a Fixed int zero?
	PowerExportWatts                                  int32    // 0x4b-0x4e
	PowerGenerationWatts                              int32    // 0x4f-0x52
	UnknownInt12                                      int32    // 0x53-0x56 Fixed int zero?
	SumOfPowerGenerationAndExportWatts                int32    // 0x57-0x5a Sum of GridWatts and PVWatts (sometimes slightly inaccurate?)
	UnknownBytes5                                     [21]byte // 0x5b-0x6f Fixed bytes?
}

// OutboundMetricsPacket represents the body of an outbound metrics packet.
type OutboundMetricsPacket struct {
	OutboundEnvelopeTS
	OutboundMetrics
}

// MarshalBinary implements binary.Marshaler
func (p *OutboundMetricsPacket) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// marshal envelope
	err := binary.Write(&buf, binary.BigEndian, p.OutboundEnvelopeTS)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	// unmarshal metrics
	var cleartextBuf bytes.Buffer
	err = binary.Write(&cleartextBuf, binary.BigEndian, p.OutboundMetrics)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundMetrics, err)
	}
	// encrypt metrics
	ciphertext, err := encryptCleartext(p.OutboundEnvelopeTS.IV[:],
		cleartextBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt metrics: %v", err)
	}
	// ignore error since it is defined to always be nil
	_, _ = buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundMetricsPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.OutboundEnvelopeTS.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundMetrics) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	if err := binary.Read(buf, binary.BigEndian, &p.OutboundMetrics); err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// OutboundTimeSync is the cleartext body of an outbound time sync packet.
type OutboundTimeSync struct {
	PacketType    [7]byte  // 0x00-0x06 Packet type?
	OutboundAddr  [40]byte // 0x07-0x2e Outbound TCP addr. Null-terminated ASCII.
	UnknownBytes1 [6]byte  // 0x2f-0x34 Unknown
	UnknownBytes2 [16]byte // 0x35-0x44 Serial number? ASCII.
	UnknownInt0   int32    // 0x45-0x48 Unknown
	UnknownBytes3 [4]byte  // 0x49-0x4c Unknown
	UnknownBytes4 [19]byte // 0x4d-0x5f Version numbers? Null-terminated ASCII.
}

// OutboundTimeSyncPacket represents the body of an outbound time sync packet.
type OutboundTimeSyncPacket struct {
	OutboundEnvelopeTS
	OutboundTimeSync
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundTimeSyncPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.OutboundEnvelopeTS.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundTimeSync) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	if err := binary.Read(buf, binary.BigEndian, &p.OutboundTimeSync); err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// OutboundEnvelope is the plaintext wrapper around the ciphertext.
type OutboundEnvelope struct {
	DeviceID     [8]byte // ASCII
	DeviceSerial [8]byte // ASCII
	IV           [16]byte
}

// OutboundTimeSyncRespAck is the cleartext body of an outbound time sync
// response ACK packet.
type OutboundTimeSyncRespAck struct {
	Data [16]byte // hard-coded bytes?
}

// OutboundTimeSyncRespAckPacket represents the body of an outbound time sync
// response ack packet.
type OutboundTimeSyncRespAckPacket struct {
	OutboundEnvelope
	OutboundTimeSyncRespAck
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundTimeSyncRespAckPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelope)],
		data[binary.Size(p.OutboundEnvelope):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelope)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelope, err)
	}
	cleartext, err := decryptCiphertext(p.OutboundEnvelope.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundTimeSyncRespAck) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.OutboundTimeSyncRespAck)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}
