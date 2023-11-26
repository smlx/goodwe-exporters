package mitm

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestTimestamp(t *testing.T) {
	chinaStandardTime, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Error(err)
	}
	var testCases = map[string]struct {
		input  [6]byte
		expect time.Time
	}{
		"timestamp_1": {
			input:  [6]byte{0x17, 0x0b, 0x1a, 0x16, 0x04, 0x21},
			expect: time.Date(2023, time.November, 26, 22, 04, 33, 0, chinaStandardTime),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ts := Timestamp(tc.input)
			assert.True(tt, tc.expect.Equal(ts.Time()),
				"expected: %v, got %v", tc.expect, ts.Time())
		})
	}
}
