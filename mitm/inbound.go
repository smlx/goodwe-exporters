package mitm

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"
)

const (
	// packet structure constants
	inboundEnvelopeLen = 0x20
	// cleartext body constants
	timeSyncRespLen = 0x10
)

var (
	// yes, this differs between inbound and outbound
	inboundCRCByteOrder = binary.LittleEndian
	// inbound packet types
	packetTypeMetricsAck0  = []byte{0x03, 0x04}
	packetTypeMetricsAck1  = []byte{0x03, 0x45}
	packetTypeMetricsAck2  = []byte{0x03, 0x03}
	packetTypeTimeSyncResp = []byte{0x01, 0x16}
)

// InboundHeader represents the header of an inbound packet.
type InboundHeader struct {
	GW         [2]byte // GW prefix
	Length     uint32  // Off-by-one
	PacketType [2]byte // Packet type identifier
}

// InboundEnvelope is the plaintext wrapper around the ciphertext.
type InboundEnvelope struct {
	DeviceID     [8]byte  // ASCII
	DeviceSerial [8]byte  // ASCII
	IV           [16]byte // AES-128 Initialization Vector
}

// InboundTimeSyncResp is the cleartext body of an inbound time sync packet.
type InboundTimeSyncResp struct {
	PacketType   [4]byte   // 0x00-0x03 Packet type?
	Timestamp    Timestamp // 0x04-0x09 Y M D H m s
	UnknownBytes [6]byte   // 0x0a-0x0f Fixed null?
}

// handleMetricsAckPacket handles metrics ack packet envelope and ciphertext.
func handleMetricsAckPacket(
	buf *bytes.Buffer,
	headerLen uint32,
	log *slog.Logger,
) error {
	envelope := InboundEnvelope{}
	if err := binary.Read(buf, binary.BigEndian, &envelope); err != nil {
		return fmt.Errorf("couldn't read envelope: %v", err)
	}
	// -2 for packet type field in header and +1 for off-by-one = -1
	ciphertext := buf.Next(int(headerLen - inboundEnvelopeLen - 1))
	cleartext, err := decryptCiphertext(envelope.IV[:], ciphertext)
	if err != nil {
		log.Debug("couldn't decrypt ciphertext", slog.Any("ciphertext", ciphertext))
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if !slices.Equal(metricsAck, cleartext) {
		log.Debug("unknown cleartext in metrics ack",
			slog.Any("cleartext", cleartext))
		return fmt.Errorf("unknown cleartext in metrics ack")
	}
	log.Debug("metrics ack")
	return nil
}

// parseTimeSyncResp unmarshals the time sync response body.
func parseTimeSyncResp(cleartext []byte) (*InboundTimeSyncResp, error) {
	if len(cleartext) != timeSyncRespLen {
		return nil, fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	body := InboundTimeSyncResp{}
	buf := bytes.NewBuffer(cleartext)
	if err := binary.Read(buf, binary.BigEndian, &body); err != nil {
		return nil, fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return &body, nil
}

// handleTimeSyncRespPacket handles time sync response packet envelope and
// ciphertext.
func handleTimeSyncRespPacket(
	buf *bytes.Buffer,
	headerLen uint32,
	log *slog.Logger,
) error {
	envelope := InboundEnvelope{}
	if err := binary.Read(buf, binary.BigEndian, &envelope); err != nil {
		return fmt.Errorf("couldn't read envelope: %v", err)
	}
	// -2 for packet type field in header and +1 for off-by-one = -1
	ciphertext := buf.Next(int(headerLen - inboundEnvelopeLen - 1))
	cleartext, err := decryptCiphertext(envelope.IV[:], ciphertext)
	if err != nil {
		log.Debug("couldn't decrypt ciphertext", slog.Any("ciphertext", ciphertext))
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	tsResp, err := parseTimeSyncResp(cleartext)
	if err != nil {
		return fmt.Errorf("couldn't parse time sync response: %v", err)
	}
	log.Debug("inbound time sync response",
		slog.Any("cleartext", cleartext),
		slog.Time("response", tsResp.Timestamp.Time()))
	return nil
}

// handleUnknownInboundPacket decrypts and logs the cleartext of an
// unrecognized inbound packet.
func handleUnknownInboundPacket(
	buf *bytes.Buffer,
	headerLen uint32,
	log *slog.Logger,
) error {
	envelope := InboundEnvelope{}
	if err := binary.Read(buf, binary.BigEndian, &envelope); err != nil {
		return fmt.Errorf("couldn't read envelope: %v", err)
	}
	// -2 for packet type field in header and +1 for off-by-one = -1
	ciphertext := buf.Next(int(headerLen - inboundEnvelopeLen - 1))
	cleartext, err := decryptCiphertext(envelope.IV[:], ciphertext)
	if err != nil {
		log.Debug("couldn't decrypt ciphertext", slog.Any("ciphertext", ciphertext))
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	log.Info("unknown packet", slog.Any("cleartext", cleartext))
	return nil
}

// handleInboundPacket is a handlePacketFunc for inbound packets.
func handleInboundPacket(
	ctx context.Context,
	log *slog.Logger,
	data []byte,
) error {
	if err := validateCRC(data, inboundCRCByteOrder); err != nil {
		return fmt.Errorf("couldn't validate CRC: %v", err)
	}
	header := InboundHeader{}
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &header); err != nil {
		return fmt.Errorf("couldn't read header: %v", err)
	}
	switch {
	case slices.Equal(packetTypeMetricsAck0, header.PacketType[:]):
		fallthrough
	case slices.Equal(packetTypeMetricsAck1, header.PacketType[:]):
		fallthrough
	case slices.Equal(packetTypeMetricsAck2, header.PacketType[:]):
		if err := handleMetricsAckPacket(buf, header.Length, log); err != nil {
			return fmt.Errorf("couldn't handle metrics ack packet: %v", err)
		}
		return nil
	case slices.Equal(packetTypeTimeSyncResp, header.PacketType[:]):
		if err := handleTimeSyncRespPacket(buf, header.Length, log); err != nil {
			return fmt.Errorf("couldn't handle time sync response packet: %v", err)
		}
		return nil
	default:
		if err := handleUnknownInboundPacket(buf, header.Length, log); err != nil {
			return fmt.Errorf("couldn't handle unknown packet: %v", err)
		}
		return fmt.Errorf("unknown packet type")
	}
}
