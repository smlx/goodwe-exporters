package mitm

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/smlx/goodwe"
)

var (
	// byte order of the packet CRC field.
	// yes, this differs between inbound and outbound.
	outboundCRCByteOrder = binary.BigEndian
	// Packet type values.
	//
	// *Metrics1 possibly means stale/cached metrics that the device has not
	// been able to successfully send before. i.e. after network problems.
	//
	// HK 1000 smart meter outbound packet types
	meterTimeSync        = PacketType{0x03, 0x03}
	meterMetrics0        = PacketType{0x03, 0x04}
	meterMetrics1        = PacketType{0x03, 0x45}
	meterTimeSyncRespAck = PacketType{0x03, 0x10}
	// DNS G3 inverter outbound packet types
	inverterTimeSync        = PacketType{0x01, 0x03}
	inverterMetrics0        = PacketType{0x01, 0x04}
	inverterMetrics1        = PacketType{0x01, 0x45}
	inverterTimeSyncRespAck = PacketType{0x01, 0x10}
	// protocol constants
	// timeSyncRespAckData occasionally sent by device after a timeSyncResp (?)
	timeSyncRespAckData = []byte{
		0x12, 0x16, 0x12, 0x18, 0x00, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	outboundUnknownPacketsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "outbound_unknown_packets_total",
		Help: "Count of outbound unknown packets.",
	})
)

// handleUnknownOutboundPacket assumes the packet is a metrics packet with a
// weird packet type, so tries to decrypt and parse it as such. This is mostly
// useful when occasionally the device sends a metrics packet with an unknown
// packet type header.
func handleUnknownOutboundPacket(
	data []byte,
	log *slog.Logger,
) error {
	log.Info("unknown packet", slog.Any("data", data))
	outboundUnknownPacketsTotal.Inc()
	envelope := OutboundEnvelope{}
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

// OutboundPacketHandler is a PacketHandler for outbound packets.
type OutboundPacketHandler struct {
	batsignal bool
}

// NewOutboundPacketHandler constructs an OutboundPacketHandler.
func NewOutboundPacketHandler(batsignal bool) *OutboundPacketHandler {
	return &OutboundPacketHandler{
		batsignal: batsignal,
	}
}

// HandlePacket implements the PacketHandler interface.
func (h *OutboundPacketHandler) HandlePacket(
	ctx context.Context,
	log *slog.Logger,
	data []byte,
) ([]byte, []byte, error) {
	if err := validateCRC(data, outboundCRCByteOrder); err != nil {
		return nil, nil, fmt.Errorf("couldn't validate CRC: %v", err)
	}
	// slice up the header and body, and discard CRC bytes
	header := OutboundHeader{}
	headerData, bodyData :=
		data[:binary.Size(header)], data[binary.Size(header):len(data)-2]
	if err := header.UnmarshalBinary(headerData); err != nil {
		return nil, nil, fmt.Errorf("couldn't unmarshal header: %v", err)
	}
	// validate size: -2 for packet type field and +1 for length off-by-one = -1
	expectedBodySize := header.Length - 1
	if len(bodyData) != int(expectedBodySize) {
		return nil, nil, fmt.Errorf("expected body size %d, got %d",
			expectedBodySize, len(bodyData))
	}
	switch header.PacketType {
	case meterTimeSync:
		if err := handleMeterTimeSyncPacket(bodyData, log); err != nil {
			return nil, nil,
				fmt.Errorf("couldn't handle meter time sync packet: %v", err)
		}
		return nil, nil, nil
	case meterMetrics0, meterMetrics1:
		metrics, err := handleMeterMetricsPacket(bodyData, log)
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't handle meter metrics packet: %v", err)
		}
		if h.batsignal {
			newBodyData, err := batsignal(metrics)
			if err != nil {
				return nil, nil, fmt.Errorf("couldn't signal batman: %v", err)
			}
			var fullPacket []byte
			fullPacket = append(headerData, newBodyData...)
			fullPacket =
				outboundCRCByteOrder.AppendUint16(fullPacket, goodwe.CRC(fullPacket))
			return nil, fullPacket, nil
		}
		return nil, nil, nil
	case meterTimeSyncRespAck, inverterTimeSyncRespAck:
		if err := handleTimeSyncRespAckPacket(bodyData, log); err != nil {
			return nil, nil,
				fmt.Errorf("couldn't handle time sync response ack packet: %v", err)
		}
		return nil, nil, nil
	case inverterMetrics0:
		if err := handleInverterMetrics0Packet(bodyData, log); err != nil {
			return nil, nil,
				fmt.Errorf("couldn't handle inverter metrics packet: %v", err)
		}
		return nil, nil, nil
	case inverterMetrics1:
		if err := handleInverterMetrics1Packet(bodyData, log); err != nil {
			return nil, nil,
				fmt.Errorf("couldn't handle inverter metrics packet: %v", err)
		}
		return nil, nil, nil
	case inverterTimeSync:
		if err := handleInverterTimeSyncPacket(bodyData, log); err != nil {
			return nil, nil,
				fmt.Errorf("couldn't handle inverter time sync packet: %v", err)
		}
		return nil, nil, nil
	default:
		if err := handleUnknownOutboundPacket(bodyData, log); err != nil {
			return nil, nil, fmt.Errorf("couldn't handle unknown packet: %v", err)
		}
		return nil, nil, fmt.Errorf("unknown packet type")
	}
}
