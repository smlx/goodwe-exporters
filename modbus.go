// Package goodwe implements various functions used by Goodwe hardware.
package goodwe

// CRC computes and returns the Modbus cyclic redundancy check (CRC16) of the
// given byte slice.
//
// See page 112 of https://modbus.org/docs/PI_MBUS_300.pdf.
func CRC(data []byte) uint16 {
	var crc16 uint16 = 0xffff
	l := len(data)
	for i := 0; i < l; i++ {
		crc16 ^= uint16(data[i])
		for j := 0; j < 8; j++ {
			if crc16&0x0001 > 0 {
				crc16 = (crc16 >> 1) ^ 0xA001
			} else {
				crc16 >>= 1
			}
		}
	}
	return crc16
}
