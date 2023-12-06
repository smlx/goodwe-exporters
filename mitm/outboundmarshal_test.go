package mitm

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestUnmarshalMetrics(t *testing.T) {
	var testCases = map[string]struct {
		input   []byte
		metrics OutboundMetricsPacket
	}{
		"metrics": {
			input: []byte{
				//0x50, 0x4f, 0x53, 0x54, 0x47, 0x57, 0x00, 0x00, 0x00, 0x99, 0x03, 0x04,
				0x00, 0x00, 0x39, 0x31,
				0x30, 0x30, 0x30, 0x48, 0x4b, 0x55, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x17, 0x09,
				0x12, 0x09, 0x09, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x09,
				0x12, 0x09, 0x09, 0x1b, 0xde, 0xde, 0x93, 0x57, 0xfe, 0x05, 0x28, 0x76, 0x42, 0xac, 0x63, 0xcf,
				0xdd, 0x7a, 0xae, 0x6d, 0xca, 0x77, 0x85, 0xca, 0x23, 0x99, 0x4c, 0x72, 0x7d, 0x33, 0x59, 0x81,
				0x3b, 0xc8, 0xf2, 0x37, 0x22, 0x69, 0x71, 0x9d, 0xc8, 0x46, 0x62, 0xa2, 0xc0, 0xef, 0xe7, 0x44,
				0xb3, 0x58, 0x2a, 0x2f, 0xbd, 0x2f, 0x68, 0x4c, 0xe0, 0x98, 0x0b, 0x24, 0xbf, 0x04, 0xc4, 0x4f,
				0xa8, 0x01, 0x81, 0x8c, 0xf6, 0x5f, 0x05, 0x52, 0x73, 0x86, 0x32, 0xaa, 0x16, 0xd2, 0x9f, 0xfe,
				0x0e, 0x52, 0xb3, 0xcc, 0x9f, 0x0a, 0xaf, 0xef, 0x6d, 0x28, 0xce, 0xad, 0x52, 0xe7, 0x9f, 0x7f,
				0x9b, 0xe3, 0x3c, 0xa0, 0x1b, 0x22, 0xc9, 0x59, 0x33, 0x04, 0xf2, 0x39, 0x8d, 0xd1, 0x20, 0xfc,
				0x88, 0xaa, 0x1d, 0x99,
				//	0x4b, 0xcd,
			},
			metrics: OutboundMetricsPacket{
				OutboundEnvelopeTS: OutboundEnvelopeTS{
					DeviceID:     [8]byte{0x39, 0x31, 0x30, 0x30, 0x30, 0x48, 0x4b, 0x55},
					DeviceSerial: [8]byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}, // test serial
				},
				OutboundMetrics: OutboundMetrics{
					PowerGenerationWatts: 2601,
					PowerExportWatts:     1557,
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			var metrics OutboundMetricsPacket
			assert.NoError(tt, metrics.UnmarshalBinary(tc.input))
			assert.Equal(tt, metrics.DeviceID, tc.metrics.DeviceID)
			assert.Equal(tt, metrics.PowerGenerationWatts, tc.metrics.PowerGenerationWatts)
			assert.Equal(tt, metrics.PowerExportWatts, tc.metrics.PowerExportWatts)
			assert.Equal(tt, metrics.DeviceSerial, tc.metrics.DeviceSerial)
		})
	}
}

func TestMarshalMetrics(t *testing.T) {
	var testCases = map[string]struct {
		metrics OutboundMetricsPacket
		data    []byte
	}{
		"metrics": {
			metrics: OutboundMetricsPacket{
				OutboundEnvelopeTS: OutboundEnvelopeTS{
					DeviceID:     [8]byte{0x39, 0x31, 0x30, 0x30, 0x30, 0x48, 0x4b, 0x55},
					DeviceSerial: [8]byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}, // test serial
					IV: [16]byte{
						0x17, 0x09, 0x12, 0x09, 0x09, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					},
					Timestamp: [6]byte{0x17, 0x09, 0x12, 0x09, 0x09, 0x1b},
				},
				OutboundMetrics: OutboundMetrics{
					PacketType: [7]byte{
						0x04, 0x08, 0x00, 0x08, 0x17, 0x00, 0x00,
					},
					EnergyExportDecawattHoursTotal:                   27078,
					EnergyGenerationDecawattHoursTotal:               57941,
					SumOfEnergyGenerationAndExportDecawattHoursTotal: 78340,
					EnergyImportDecawattHoursTotal:                   80155,
					UnknownBytes4: [16]byte{
						0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					},
					SumOfEnergyImportLessGenerationDecawattHoursTotal: 7948,
					UnknownInt5:                        137365568,
					UnknownInt6:                        2438,
					UnknownInt7:                        2440,
					UnknownInt9:                        660,
					UnknownInt10:                       1092,
					PowerExportWatts:                   1557,
					PowerGenerationWatts:               2601,
					SumOfPowerGenerationAndExportWatts: 4159,
					UnknownBytes5: [21]byte{
						0x15, 0x00, 0x15, 0x03, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x16, 0x00, 0x16, 0x00,
						0x00, 0x02, 0xff, 0xff, 0xff,
					},
				},
			},
			data: []byte{
				// packet is copied from outbound_test.go
				// 0x50, 0x4f, 0x53, 0x54, 0x47, 0x57, 0x00, 0x00, 0x00, 0x99, 0x03, 0x04,
				0x00, 0x00, 0x39, 0x31,
				0x30, 0x30, 0x30, 0x48, 0x4b, 0x55, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x17, 0x09,
				0x12, 0x09, 0x09, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x09,
				0x12, 0x09, 0x09, 0x1b, 0xde, 0xde, 0x93, 0x57, 0xfe, 0x05, 0x28, 0x76, 0x42, 0xac, 0x63, 0xcf,
				0xdd, 0x7a, 0xae, 0x6d, 0xca, 0x77, 0x85, 0xca, 0x23, 0x99, 0x4c, 0x72, 0x7d, 0x33, 0x59, 0x81,
				0x3b, 0xc8, 0xf2, 0x37, 0x22, 0x69, 0x71, 0x9d, 0xc8, 0x46, 0x62, 0xa2, 0xc0, 0xef, 0xe7, 0x44,
				0xb3, 0x58, 0x2a, 0x2f, 0xbd, 0x2f, 0x68, 0x4c, 0xe0, 0x98, 0x0b, 0x24, 0xbf, 0x04, 0xc4, 0x4f,
				0xa8, 0x01, 0x81, 0x8c, 0xf6, 0x5f, 0x05, 0x52, 0x73, 0x86, 0x32, 0xaa, 0x16, 0xd2, 0x9f, 0xfe,
				0x0e, 0x52, 0xb3, 0xcc, 0x9f, 0x0a, 0xaf, 0xef, 0x6d, 0x28, 0xce, 0xad, 0x52, 0xe7, 0x9f, 0x7f,
				0x9b, 0xe3, 0x3c, 0xa0, 0x1b, 0x22, 0xc9, 0x59, 0x33, 0x04, 0xf2, 0x39, 0x8d, 0xd1, 0x20, 0xfc,
				0x88, 0xaa, 0x1d, 0x99,
				//	0x4b, 0xcd,
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			data, err := tc.metrics.MarshalBinary()
			assert.NoError(tt, err)
			assert.Equal(tt, data, tc.data)
		})
	}
}