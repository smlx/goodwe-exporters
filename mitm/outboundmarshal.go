package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// OutboundHeader represents the header of an outbound packet.
type OutboundHeader struct {
	PostGW     [6]byte    // POSTGW prefix
	Length     uint32     // Off-by-one
	PacketType PacketType // Packet type identifier
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

// OutboundMeterMetrics is the cleartext body of an outbound metrics packet.
type OutboundMeterMetrics struct {
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

// OutboundMeterMetricsPacket represents the body of an outbound meter metrics
// packet.
type OutboundMeterMetricsPacket struct {
	OutboundEnvelopeTS
	OutboundMeterMetrics
}

// MarshalBinary implements binary.Marshaler
func (p *OutboundMeterMetricsPacket) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// marshal envelope
	err := binary.Write(&buf, binary.BigEndian, p.OutboundEnvelopeTS)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	// marshal metrics
	var cleartextBuf bytes.Buffer
	err = binary.Write(&cleartextBuf, binary.BigEndian, p.OutboundMeterMetrics)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundMeterMetrics, err)
	}
	// encrypt metrics
	ciphertext, err := encryptCleartext(p.IV[:],
		cleartextBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt metrics: %v", err)
	}
	// ignore error since it is defined to always be nil
	_, _ = buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundMeterMetricsPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundMeterMetrics) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.OutboundMeterMetrics)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// OutboundMeterTimeSync is the cleartext body of an outbound time sync packet.
type OutboundMeterTimeSync struct {
	PacketType    [7]byte  // 0x00-0x06 Packet type?
	OutboundAddr  [40]byte // 0x07-0x2e Outbound TCP addr. Null-terminated ASCII.
	UnknownBytes1 [6]byte  // 0x2f-0x34 Unknown
	UnknownBytes2 [16]byte // 0x35-0x44 Serial number? ASCII.
	UnknownInt0   int32    // 0x45-0x48 Unknown
	UnknownBytes3 [4]byte  // 0x49-0x4c Unknown
	Version       [19]byte // 0x4d-0x5f Version numbers? Null-terminated ASCII.
}

// OutboundMeterTimeSyncPacket represents the body of an outbound time sync packet.
type OutboundMeterTimeSyncPacket struct {
	OutboundEnvelopeTS
	OutboundMeterTimeSync
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundMeterTimeSyncPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundMeterTimeSync) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	if err := binary.Read(buf, binary.BigEndian, &p.OutboundMeterTimeSync); err != nil {
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
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
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

// outboundInverterMetricsCommon0 is the first common block of fields in
// outbound inverter metrics.
type outboundInverterMetricsCommon0 struct {
	InnerTimestamp              Timestamp
	VoltageInputDCDecivolts     int16
	CurrentInputDCDeciamps      int16
	UnknownBytes1               [8]byte  // fixed 0x00?
	UnknownBytes2               [18]byte // fixed 0xff?
	VoltageOutputACDecivolts    int16
	UnknownBytes3               [4]byte // fixed 0xff?
	CurrentOutputACDeciamps     int16
	UnknownBytes4               [4]byte // fixed 0xff?
	FrequencyOutputACCentihertz int16
	UnknownBytes5               [4]byte // fixed 0xff?
	UnknownInt0                 int16
	PowerOutputWatts            int16
	UnknownInt1                 int16
}

// outboundInverterMetricsCommon1 is the second common block of fields in
// outbound inverter metrics.
type outboundInverterMetricsCommon1 struct {
	UnknownInt2                           int16
	UnknownInt3                           int16
	UnknownBytes6                         [2]byte // fixed 0xff?
	UnknownInt4                           int16
	UnknownBytes7                         [4]byte // fixed 0xff?
	UnknownInt5                           int16
	UnknownBytes8                         [2]byte // fixed 0xff?
	InternalTemperatureDecidegreesCelsius int16
	UnknownBytes9                         [4]byte // fixed 0xff?
	EnergyOutputHectowattHoursToday       int16
	EnergyOutputHectowattHoursTotal       int32
	UptimeHoursTotal                      int32
	UnknownInt7                           int16
	UnknownInt8                           int16
	UnknownInt9                           int16
}

// outboundInverterMetricsCommon1 is the third common block of fields in
// outbound inverter metrics.
type outboundInverterMetricsCommon2 struct {
	UnknownInt10   int16
	UnknownInt11   int16
	UnknownInt12   int16
	UnknownInt13   int16
	UnknownInt14   int16
	UnknownBytes10 [2]byte // fixed 0xff?
	UnknownInt15   int32
	UnknownInt16   int32
	UnknownInt17   int16
	UnknownInt18   int16
	UnknownInt19   int16
	UnknownInt20   int16
	UnknownBytes11 [4]byte // fixed 0x00?
	UnknownInt21   int32
	UnknownBytes12 [8]byte // fixed 0x00
}

// outboundInverterMetricsCommon1 is the fourth common block of fields in
// outbound inverter metrics.
type outboundInverterMetricsCommon3 struct {
	UnknownInt22   int16
	UnknownInt23   int16
	UnknownInt24   int16
	UnknownBytes13 [56]byte // fixed 0x00?
	UnknownInt25   int16
	UnknownInt26   int16
	UnknownInt27   int16
	UnknownInt28   int16
	UnknownInt29   int16
	UnknownInt30   int16
	UnknownBytes14 [10]byte // fixed 0xff?
	UnknownInt31   int16
	UnknownInt32   int16
}

// OutboundInverterMetrics0 is the cleartext body of an outbound metrics packet.
type OutboundInverterMetrics0 struct {
	// This field differs by a single byte between OutboundInverterMetrics0/1 so
	// I guess it is packet type?
	PacketType    [5]byte
	UnknownBytes0 [16]byte

	outboundInverterMetricsCommon0

	UnknownBytes15 [6]byte // fixed 0xff?

	outboundInverterMetricsCommon1

	UnknownBytes16 [2]byte // fixed 0xff?

	UnknownInt33   int16
	UnknownBytes17 [16]byte // fixed 0xff?
	RSSIPercent    int16

	UnknownBytes18 [4]byte // fixed 0xff?

	outboundInverterMetricsCommon2

	UnknownBytes19 [8]byte // fixed 0xff?
	UnknownInt34   int16
	UnknownInt35   int16
	UnknownInt36   int16
	UnknownBytes20 [12]byte // ASCII
	UnknownInt37   int16
	UnknownInt38   int16
	UnknownInt39   int16
	UnknownBytes21 [2]byte  // fixed 0xff?
	UnknownBytes22 [16]byte // fixed 0x00?
	UnknownInt40   int16
	UnknownInt41   int16
	UnknownBytes23 [4]byte // fixed 0x00?
	UnknownInt42   int16
	UnknownInt43   int16
	UnknownBytes24 [74]byte // fixed 0x00?
	UnknownBytes25 [2]byte  // fixed 0xff?
	UnknownInt44   int16
	UnknownInt45   int16
	UnknownBytes26 [28]byte // fixed 0x00?
	UnknownBytes27 [4]byte  // fixed 0xff?

	outboundInverterMetricsCommon3

	UnknownInt46   int16
	UnknownInt47   int16
	UnknownBytes28 [14]byte // fixed 0x00?
	UnknownInt48   int16
	UnknownInt49   int16
	UnknownBytes29 [4]byte // fixed 0x00?
	UnknownInt50   int16
	UnknownInt51   int16
	UnknownBytes30 [2]byte // fixed 0x00?
	UnknownBytes31 [7]byte // fixed 0xff?
}

// OutboundInverterMetrics0Packet represents the body of an outbound meter
// metrics packet.
type OutboundInverterMetrics0Packet struct {
	OutboundEnvelopeTS
	OutboundInverterMetrics0
}

// MarshalBinary implements binary.Marshaler
func (p *OutboundInverterMetrics0Packet) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// marshal envelope
	err := binary.Write(&buf, binary.BigEndian, p.OutboundEnvelopeTS)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	// marshal metrics
	var cleartextBuf bytes.Buffer
	err = binary.Write(&cleartextBuf, binary.BigEndian, p.OutboundInverterMetrics0)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't marshal %T: %v", p.OutboundInverterMetrics0, err)
	}
	// encrypt metrics
	ciphertext, err := encryptCleartext(p.IV[:],
		cleartextBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt metrics: %v", err)
	}
	// ignore error since it is defined to always be nil
	_, _ = buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundInverterMetrics0Packet) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundInverterMetrics0) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.OutboundInverterMetrics0)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// OutboundInverterMetrics1 is the cleartext body of an outbound metrics packet.
type OutboundInverterMetrics1 struct {
	// This field differs by a single byte between OutboundInverterMetrics0/1 so
	// I guess it is packet type?
	PacketType     [5]byte
	UnknownBytes32 [14]byte

	outboundInverterMetricsCommon0

	UnknownInt53 int16
	UnknownInt54 int16

	outboundInverterMetricsCommon1

	UnknownInt55   int16
	UnknownBytes33 [16]byte // fixed 0xff?
	RSSIPercent    int16

	UnknownInt56   int16
	UnknownInt57   int16
	UnknownBytes34 [2]byte // fixed 0xff?

	outboundInverterMetricsCommon2

	UnknownInt58   int16
	UnknownInt59   int16
	UnknownBytes35 [20]byte // fixed 0x00?
	UnknownInt60   int16
	UnknownInt61   int16
	UnknownInt62   int16
	UnknownInt63   int16
	UnknownInt64   int16
	UnknownInt65   int16
	UnknownBytes36 [18]byte // fixed 0x00?
	UnknownInt66   int16
	UnknownInt67   int16
	UnknownInt68   int16

	outboundInverterMetricsCommon3

	UnknownInt69   int16
	UnknownInt70   int16
	UnknownBytes37 [9]byte // fixed 0xff?
}

// OutboundInverterMetrics1Packet represents the body of an outbound meter
// metrics packet.
type OutboundInverterMetrics1Packet struct {
	OutboundEnvelopeTS
	OutboundInverterMetrics1
}

// MarshalBinary implements binary.Marshaler
func (p *OutboundInverterMetrics1Packet) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// marshal envelope
	err := binary.Write(&buf, binary.BigEndian, p.OutboundEnvelopeTS)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	// marshal metrics
	var cleartextBuf bytes.Buffer
	err = binary.Write(&cleartextBuf, binary.BigEndian, p.OutboundInverterMetrics1)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't marshal %T: %v", p.OutboundInverterMetrics1, err)
	}
	// encrypt metrics
	ciphertext, err := encryptCleartext(p.IV[:],
		cleartextBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt metrics: %v", err)
	}
	// ignore error since it is defined to always be nil
	_, _ = buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundInverterMetrics1Packet) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundInverterMetrics1) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.OutboundInverterMetrics1)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}

// OutboundInverterTimeSync is the cleartext body of an outbound metrics packet.
type OutboundInverterTimeSync struct {
	PacketType     [7]byte
	UnknownInt0    int32
	UnknownInt1    int16
	UnknownInt2    int16
	UnknownInt3    int16
	UnknownBytes1  [8]byte // fixed 0x00
	UnknownInt4    int16
	UnknownInt5    int16
	Version        [16]byte // Version number? Null-terminated ASCII.
	UnknownInt6    int16
	UnknownInt7    int16
	UnknownInt8    int16
	UnknownInt9    int16
	UnknownInt10   int16
	UnknownInt11   int32
	UnknownInt12   int16
	UnknownInt13   int32
	UnknownBytes2  [6]byte // fixed 0x00
	UnknownInt14   int16
	UnknownInt15   int16
	UnknownInt16   int32
	UnknownInt17   int16
	UnknownBytes3  [20]byte // fixed 0x00
	UnknownInt18   int16
	UnknownInt19   int16
	UnknownBytes4  [16]byte // fixed 0x00
	UnknownInt20   int16
	UnknownInt21   int16
	UnknownInt22   int16
	UnknownInt23   int16
	UnknownInt24   int16
	UnknownInt25   int16
	UnknownInt26   int16
	UnknownInt27   int16
	UnknownBytes5  [74]byte // fixed 0x00
	UnknownInt28   int16
	UnknownInt29   int16
	UnknownInt30   int16
	UnknownInt31   int16
	UnknownInt32   int16
	UnknownInt33   int16
	UnknownInt34   int16
	UnknownInt35   int32
	UnknownInt36   int32
	UnknownInt37   int16
	UnknownBytes6  [4]byte // fixed 0xff
	UnknownBytes7  [8]byte // fixed 0x00
	UnknownInt38   int16
	UnknownInt39   int16
	OutboundDomain [52]byte // Outbound domain name. ASCII.
	UnknownInt40   int16
	UnknownInt41   int16
	UnknownInt42   int16
	UnknownInt43   int16
	UnknownBytes8  [4]byte // fixed 0xff
	UnknownInt44   int16
	UnknownInt45   int16
	UnknownInt46   int16
	UnknownInt47   int16
	DeviceModel    [32]byte // Device model. Null-terminated ASCII.
	UnknownInt48   int16
	UnknownInt49   int16
	UnknownBytes9  [4]byte // fixed 0x00
	UnknownInt50   int16
	UnknownInt51   int16
	UnknownInt52   int16
	UnknownInt53   int16
	UnknownInt54   int16
	UnknownInt55   int16
	UnknownInt56   int16
	UnknownInt57   int16
	UnknownInt58   int16
	UnknownInt59   int16
	UnknownInt60   int32
	UnknownInt61   int32
	UnknownInt62   int32
	UnknownInt63   int32
	UnknownBytes10 [4]byte // fixed 0xff
	UnknownBytes11 [4]byte // fixed 0x00
	UnknownInt64   int16
	UnknownInt65   int16
	UnknownBytes12 [14]byte // fixed 0xff
	UnknownInt66   int16
	UnknownInt67   int16
	UnknownInt68   int16
	UnknownBytes13 [4]byte // fixed 0xff
	UnknownInt69   int32
	UnknownInt70   int32
	UnknownInt71   int16
	UnknownInt72   int16
	UnknownInt73   int16
	UnknownInt74   int16
	UnknownInt75   int32
	UnknownInt76   int32
	UnknownInt77   int16
	UnknownInt78   int16
	UnknownInt79   int16
	UnknownInt80   int16
	UnknownInt81   int16
	UnknownInt82   int16
	UnknownInt83   int16
	UnknownInt84   int16
	UnknownInt85   int16
	UnknownInt86   int16
	UnknownInt87   int16
	UnknownInt88   int16
	UnknownInt89   int16
	UnknownInt90   int16
	UnknownInt91   int16
	UnknownInt92   int16
	UnknownInt93   int16
	UnknownInt94   int16
	UnknownInt95   int16
	UnknownInt96   int16
	UnknownInt97   int16
	UnknownInt98   int16
	UnknownInt99   int16
	UnknownInt100  int16
	UnknownInt101  int16
	UnknownInt102  int16
	UnknownInt103  int16
	UnknownInt104  int16
	UnknownInt105  int16
	UnknownInt106  int16
	UnknownInt107  int16
	UnknownInt108  int16
	UnknownInt109  int16
	UnknownInt110  int16
	UnknownInt111  int16
	UnknownInt112  int16
	UnknownInt113  int16
	UnknownInt114  int32
	UnknownInt115  int16
	UnknownInt116  int16
	UnknownInt117  int16
	UnknownInt118  int16
	UnknownInt119  int16
	UnknownInt120  int16
	UnknownInt121  int16
	UnknownInt122  int16
	UnknownInt123  int16
	UnknownInt124  int16
	UnknownInt125  int16
	UnknownInt126  int32
	UnknownInt127  int16
	UnknownInt128  int16
	UnknownInt129  int16
	UnknownInt130  int16
	UnknownInt131  int16
	UnknownInt132  int16
	UnknownInt133  int16
	UnknownInt134  int16
	UnknownInt135  int16
	UnknownInt136  int16
	UnknownInt137  int16
	UnknownInt138  int16
	UnknownInt139  int16
	UnknownInt140  int32
	UnknownInt141  int16
	UnknownInt142  int16
	UnknownInt143  int16
	UnknownInt144  int16
	UnknownBytes14 [12]byte // fixed 0xff
	UnknownInt145  int32
	UnknownInt146  int32
	UnknownBytes15 [8]byte  // fixed 0xff
	UnknownBytes16 [48]byte // fixed 0xff
	UnknownInt147  int32
	UnknownInt148  int32
	UnknownInt149  int16
	UnknownInt150  int16
	UnknownInt151  int32
	UnknownInt152  int16
	UnknownInt153  int16
	UnknownInt154  int16
	UnknownInt155  int16
	UnknownInt156  int16
	UnknownInt157  int16
	UnknownInt158  int16
	UnknownInt159  int16
	UnknownInt160  int16
	UnknownInt161  int16
	UnknownInt162  int16
	UnknownInt163  int16
	UnknownInt164  int16
	UnknownInt165  int16
	UnknownInt166  int16
	UnknownInt167  int16
	UnknownInt168  int16
	UnknownInt169  int16
	UnknownInt170  int32
	UnknownBytes18 [3]byte // fixed 0xff
}

// OutboundInverterTimeSyncPacket represents the body of an outbound time sync
// packet.
type OutboundInverterTimeSyncPacket struct {
	OutboundEnvelopeTS
	OutboundInverterTimeSync
}

// MarshalBinary implements binary.Marshaler
func (p *OutboundInverterTimeSyncPacket) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	// marshal envelope
	err := binary.Write(&buf, binary.BigEndian, p.OutboundEnvelopeTS)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	// marshal metrics
	var cleartextBuf bytes.Buffer
	err = binary.Write(&cleartextBuf, binary.BigEndian, p.OutboundInverterTimeSync)
	if err != nil {
		return nil,
			fmt.Errorf("couldn't marshal %T: %v", p.OutboundInverterTimeSync, err)
	}
	// encrypt metrics
	ciphertext, err := encryptCleartext(p.IV[:],
		cleartextBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't encrypt metrics: %v", err)
	}
	// ignore error since it is defined to always be nil
	_, _ = buf.Write(ciphertext)
	return buf.Bytes(), nil
}

// UnmarshalBinary implements binary.Unmarshaler
func (p *OutboundInverterTimeSyncPacket) UnmarshalBinary(data []byte) error {
	envData, bodyData := data[:binary.Size(p.OutboundEnvelopeTS)],
		data[binary.Size(p.OutboundEnvelopeTS):]
	envBuf := bytes.NewBuffer(envData)
	err := binary.Read(envBuf, binary.BigEndian, &p.OutboundEnvelopeTS)
	if err != nil {
		return fmt.Errorf("couldn't read unmarshal %T: %v", p.OutboundEnvelopeTS, err)
	}
	cleartext, err := decryptCiphertext(p.IV[:], bodyData)
	if err != nil {
		return fmt.Errorf("couldn't decrypt ciphertext: %v", err)
	}
	if len(cleartext) != binary.Size(p.OutboundInverterTimeSync) {
		return fmt.Errorf("invalid cleartext length: %d", len(cleartext))
	}
	buf := bytes.NewBuffer(cleartext)
	err = binary.Read(buf, binary.BigEndian, &p.OutboundInverterTimeSync)
	if err != nil {
		return fmt.Errorf("couldn't read cleartext: %v", err)
	}
	return nil
}
