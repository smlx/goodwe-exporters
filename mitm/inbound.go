package mitm

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// yes, this differs between inbound and outbound
	inboundCRCByteOrder = binary.LittleEndian
	// HK 1000 smart meter inbound packet types
	meterMetricsAck0  = PacketType{0x03, 0x04}
	meterMetricsAck1  = PacketType{0x03, 0x45}
	meterMetricsAck2  = PacketType{0x03, 0x03}
	meterTimeSyncResp = PacketType{0x01, 0x16}
	// DNS G3 inbound packet types
	inverterMetricsAck0  = PacketType{0x01, 0x04}
	inverterMetricsAck1  = PacketType{0x01, 0x45}
	inverterTimeSyncResp = PacketType{0x01, 0x03}
	// protocol constants
	// metricsAckData is sent by the server when it receives data sucessfully
	metricsAckData = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// metricsNackData is sent by the server when it receives data unsucessfully
	// (e.g. bad CRC)
	metricsNackData = []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// prometheus metrics
	inboundUnknownPacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "inbound_unknown_packets_total",
		Help: "Count of inbound unknown packets.",
	})
)

// handleMetricsAckPacket handles metrics ack packet envelope and ciphertext.
func handleMetricsAckPacket(
	data []byte,
	log *slog.Logger,
) error {
	var metricsAck InboundMetricsAckPacket
	err := metricsAck.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal metrics ack: %v", err)
	}
	devInfo, ok := deviceInfo[metricsAck.DeviceID]
	if !ok {
		return fmt.Errorf("unknown device ID: %v", metricsAck.DeviceID)
	}
	switch {
	case slices.Equal(metricsAck.Data[:], metricsAckData):
		log.Debug("metrics ack",
			slog.String("device", devInfo[0]),
			slog.String("model", devInfo[1]),
			slog.String("serial", string(metricsAck.DeviceSerial[:])))
	case slices.Equal(metricsAck.Data[:], metricsNackData):
		log.Warn("metrics nack. bad metrics CRC?",
			slog.String("device", devInfo[0]),
			slog.String("model", devInfo[1]),
			slog.String("serial", string(metricsAck.DeviceSerial[:])))
	default:
		log.Warn("unknown cleartext in metrics ack",
			slog.Any("cleartext", metricsAck.Data[:]),
			slog.String("device", devInfo[0]),
			slog.String("model", devInfo[1]),
			slog.String("serial", string(metricsAck.DeviceSerial[:])))
	}
	return nil
}

// handleTimeSyncRespPacket handles time sync response packet envelope and
// ciphertext.
func handleTimeSyncRespPacket(
	data []byte,
	log *slog.Logger,
) error {
	var timeSyncResp InboundTimeSyncRespPacket
	err := timeSyncResp.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal time sync response: %v", err)
	}
	log.Debug("inbound time sync response",
		slog.Time("responseTimestamp", timeSyncResp.Timestamp.Time()))
	return nil
}

// handleUnknownInboundPacket decrypts and logs the cleartext of an
// unrecognized inbound packet.
func handleUnknownInboundPacket(
	data []byte,
	log *slog.Logger,
) error {
	log.Info("unknown packet", slog.Any("data", data))
	inboundUnknownPacketsTotal.Inc()
	envelope := InboundEnvelope{}
	envData, bodyData := data[:binary.Size(envelope)], data[binary.Size(envelope):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &envelope)
	if err != nil {
		return fmt.Errorf("couldn't unmarshal envelope %T: %v", envelope, err)
	}
	cleartext, err := decryptCiphertext(envelope.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	log.Info("unknown packet cleartext", slog.Any("cleartext", cleartext))
	return nil
}

// InboundPacketHandler is a PacketHandler for inbound packets.
type InboundPacketHandler struct{}

// NewInboundPacketHandler constructs an InboundPacketHandler.
func NewInboundPacketHandler() *InboundPacketHandler {
	return &InboundPacketHandler{}
}

// HandlePacket implements the PacketHandler interface.
func (h *InboundPacketHandler) HandlePacket(
	ctx context.Context,
	log *slog.Logger,
	data []byte,
) ([]byte, error) {
	if err := validateCRC(data, inboundCRCByteOrder); err != nil {
		return nil, fmt.Errorf("couldn't validate CRC: %v", err)
	}
	// slice up the header and body, and discard CRC bytes
	header := InboundHeader{}
	headerData, bodyData :=
		data[:binary.Size(header)], data[binary.Size(header):len(data)-2]
	if err := header.UnmarshalBinary(headerData); err != nil {
		return nil, fmt.Errorf("couldn't unmarshal header: %v", err)
	}
	// validate size: -2 for packet type field and +1 for length off-by-one = -1
	expectedBodySize := header.Length - 1
	if len(bodyData) != int(expectedBodySize) {
		return nil, fmt.Errorf("expected body size %d, got %d",
			expectedBodySize, len(bodyData))
	}
	switch header.PacketType {
	case meterMetricsAck0, meterMetricsAck1, meterMetricsAck2,
		inverterMetricsAck0, inverterMetricsAck1:
		if err := handleMetricsAckPacket(bodyData, log); err != nil {
			return nil, fmt.Errorf("couldn't handle metrics ack packet: %v", err)
		}
		return nil, nil
	case meterTimeSyncResp, inverterTimeSyncResp:
		if err := handleTimeSyncRespPacket(bodyData, log); err != nil {
			return nil,
				fmt.Errorf("couldn't handle time sync response packet: %v", err)
		}
		return nil, nil
	default:
		if err := handleUnknownInboundPacket(bodyData, log); err != nil {
			return nil, fmt.Errorf("couldn't handle unknown packet: %v", err)
		}
		return nil, fmt.Errorf("unknown packet type")
	}
}
