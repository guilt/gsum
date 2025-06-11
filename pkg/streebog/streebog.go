package streebog

import (
	"encoding/binary"
	"math/bits"
)

// Constants for Streebog (GOST R 34.11-2012)
const (
	BlockSize     = 64 // 512 bits
	DigestSize512 = 64 // 512 bits (for Streebog-512)
	DigestSize256 = 32 // 256 bits (for Streebog-256)
)

// S-box for non-linear transformation
var sbox = [256]uint8{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 183, 120, 111, 43, 155, 108, 177, 154, 159,
	163, 126, 88, 3, 182, 213, 44, 214, 112, 127, 21, 162, 247, 105, 39, 74,
	76, 94, 166, 63, 124, 235, 217, 121, 138, 245, 40, 253, 104, 152, 142, 67,
	171, 56, 84, 243, 146, 180, 8, 232, 222, 65, 228, 179, 148, 87, 176, 150,
	169, 241, 33, 202, 216, 91, 55, 234, 66, 128, 7, 184, 223, 185, 230, 83,
	122, 149, 60, 254, 229, 106, 158, 175, 68, 194, 98, 190, 41, 86, 96, 11,
	164, 178, 14, 199, 132, 9, 82, 157, 80, 37, 131, 24, 242, 187, 141, 30,
	100, 57, 130, 69, 145, 18, 172, 188, 115, 51, 12, 135, 160, 236, 167, 53,
	23, 31, 189, 226, 97, 227, 99, 61, 137, 174, 73, 45, 116, 64, 58, 206,
	113, 28, 42, 201, 47, 36, 208, 209, 102, 72, 125, 133, 0, 181, 20, 246,
	255, 95, 70, 198, 129, 52, 19, 220, 168, 93, 136, 248, 151, 114, 29, 237,
	139, 62, 85, 16, 144, 1, 186, 118, 71, 140, 34, 156, 225, 25, 203, 109,
	92, 26, 161, 48, 75, 205, 27, 195, 117, 173, 6, 224, 123, 89, 38, 231,
	249, 239, 101, 81, 165, 170, 143, 32, 244, 13, 212, 107, 192, 90, 78, 200,
	215, 5, 191, 211, 79, 204, 2, 10, 103, 193, 50, 54, 210, 59, 15, 134,
}

// Linear transformation matrix (simplified for demo)
var lps = [8][8]uint64{
	{148, 32, 133, 16, 194, 192, 1, 251},
	{1, 148, 32, 133, 16, 194, 192, 251},
	{251, 1, 148, 32, 133, 16, 194, 192},
	{192, 251, 1, 148, 32, 133, 16, 194},
	{194, 192, 251, 1, 148, 32, 133, 16},
	{16, 194, 192, 251, 1, 148, 32, 133},
	{133, 16, 194, 192, 251, 1, 148, 32},
	{32, 133, 16, 194, 192, 251, 1, 148},
}

// Streebog hash state
type digest struct {
	h      [8]uint64 // Current hash state
	n      [8]uint64 // Message length counter
	sigma  [8]uint64 // Checksum
	buffer [BlockSize]byte
	bufLen int
	size   int // Digest size in bytes (32 for 256-bit, 64 for 512-bit)
}

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int {
	return d.size
}

// New512 creates a new Streebog-512 hash instance
func New512() *digest {
	d := &digest{size: DigestSize512}
	d.Reset()
	return d
}

// New256 creates a new Streebog-256 hash instance
func New256() *digest {
	d := &digest{size: DigestSize256}
	d.Reset()
	// Initialize h with 0x01 for 256-bit variant
	for i := 0; i < 8; i++ {
		d.h[i] = 0x0101010101010101
	}
	return d
}

// Reset initializes the hash state
func (d *digest) Reset() {
	d.h = [8]uint64{0}
	d.n = [8]uint64{0}
	d.sigma = [8]uint64{0}
	d.bufLen = 0
}

// Write adds data to the hash
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)
	for len(p) > 0 {
		// Fill buffer
		space := BlockSize - d.bufLen
		if space > len(p) {
			copy(d.buffer[d.bufLen:], p)
			d.bufLen += len(p)
			return
		}
		copy(d.buffer[d.bufLen:], p[:space])
		d.processBlock(d.buffer[:])
		p = p[space:]
		d.bufLen = 0
	}
	return
}

// Sum finalizes the hash and returns the digest
func (d *digest) Sum(b []byte) []byte {
	// Pad and process remaining data
	d.pad()

	// Finalize with length and checksum
	var lenBlock [BlockSize]byte
	binary.LittleEndian.PutUint64(lenBlock[:8], uint64(d.n[0]))
	d.processBlock(lenBlock[:])

	var sigmaBlock [BlockSize]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(sigmaBlock[i*8:], d.sigma[i])
	}
	d.processBlock(sigmaBlock[:])

	// Convert hash to bytes
	var result [DigestSize512]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(result[i*8:], d.h[i])
	}
	// Truncate to 256 bits if size is DigestSize256
	if d.size == DigestSize256 {
		return append(b, result[:DigestSize256]...)
	}
	return append(b, result[:]...)
}

// pad adds padding to the buffer
func (d *digest) pad() {
	d.buffer[d.bufLen] = 0x01
	d.bufLen++
	for d.bufLen < BlockSize {
		d.buffer[d.bufLen] = 0
		d.bufLen++
	}
	d.processBlock(d.buffer[:])
}

// processBlock processes a 512-bit block
func (d *digest) processBlock(block []byte) {
	var m [8]uint64
	for i := 0; i < 8; i++ {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	// Update counters
	d.n[0] += 512 // Update bit length
	d.addMod512(m[:])

	// Compression function
	d.g(m[:])

	// Update checksum
	for i := 0; i < 8; i++ {
		d.sigma[i] += m[i]
	}
}

// addMod512 adds two 512-bit vectors modulo 2^512
func (d *digest) addMod512(x []uint64) {
	var carry uint64
	for i := 7; i >= 0; i-- {
		d.n[i], carry = bits.Add64(d.n[i], x[i], carry)
	}
}

// g applies the compression function
func (d *digest) g(m []uint64) {
	var k, t [8]uint64
	copy(k[:], d.h[:])
	for i := 0; i < 12; i++ {
		// Key schedule
		d.lps(&k)
		// Round
		var mArray [8]uint64
		copy(mArray[:], m)
		d.e(&k, &mArray)
	}

	// Mix
	for i := 0; i < 8; i++ {
		t[i] = d.h[i] ^ k[i] ^ m[i]
	}
	copy(d.h[:], t[:])
}

// lps applies linear, permutation, and substitution
func (d *digest) lps(state *[8]uint64) {
	var temp [8]uint64
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			temp[i] ^= state[j] * lps[i][j]
		}
	}
	for i := 0; i < 8; i++ {
		state[i] = uint64(sbox[temp[i]&0xFF])
	}
}

// e applies the encryption round
func (d *digest) e(k, m *[8]uint64) {
	for i := 0; i < 8; i++ {
		k[i] ^= m[i]
	}
	d.lps(k)
}
