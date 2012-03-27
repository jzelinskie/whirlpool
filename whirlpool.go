// Copyright 2012 Jimmy Zelinskie. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package whirlpool implements the ISO/IEC 10118-3:2004 whirlpool
// cryptographic hash. Whirlpool is defined in
// http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html

package whirlpool

import (
	"hash"
)

type whirlpool struct {
	bitLength  [lengthBytes]byte       // Number of hashed bits.
	buffer     [wblockBytes]byte       // Buffer of data to be hashed.
	bufferBits int                     // Current number of bits on the buffer.
	bufferPos  int                     // Current byte location on buffer.
	hash       [digestBytes / 8]uint64 // Hash state.
}

func New() hash.Hash {
	return new(whirlpool)
}

func (w *whirlpool) Reset() {
	// Cleanup the buffer.
	w.buffer = [wblockBytes]byte{}
	w.bufferBits = 0
	w.bufferPos = 0

	// Cleanup the digest.
	w.hash = [digestBytes / 8]uint64{}

	// Clean up the number of hashed bits.
	w.bitLength = [lengthBytes]byte{}
}

func (w *whirlpool) Size() int {
	return digestBytes
}

func (w *whirlpool) BlockSize() int {
	return wblockBytes
}

func (w *whirlpool) transform() {
	var (
		K     [8]uint64 // Round key.
		block [8]uint64 // Mu(buffer).
		state [8]uint64 // Cipher state.
		L     [8]uint64
	)

	// Map the buffer to a block.
	for i := 0; i < 8; i++ {
		b := 8 * i
		block[i] = ((uint64(w.buffer[b]) << 56) ^
			(uint64(w.buffer[b+1]) & 0xff << 48) ^
			(uint64(w.buffer[b+2]) & 0xff << 40) ^
			(uint64(w.buffer[b+3]) & 0xff << 32) ^
			(uint64(w.buffer[b+4]) & 0xff << 24) ^
			(uint64(w.buffer[b+5]) & 0xff << 16) ^
			(uint64(w.buffer[b+6]) & 0xff << 8) ^
			(uint64(w.buffer[b+7]) & 0xff))
	}

	// Compute & apply K^0 to the cipher state.
	for i := 0; i < 8; i++ {
		K[i] = w.hash[i]
		state[i] = block[i] ^ K[i]
	}

	// Iterate over all the rounds.
	for r := 1; r <= rounds; r++ {
		// Compute K^rounds from K^(rounds-1).
		for i := 0; i < 8; i++ {
			L[i] = C0[byte(K[i%8]>>56)] ^
				C1[byte(K[(i+7)%8]>>48)] ^
				C2[byte(K[(i+6)%8]>>40)] ^
				C3[byte(K[(i+5)%8]>>32)] ^
				C4[byte(K[(i+4)%8]>>24)] ^
				C5[byte(K[(i+3)%8]>>16)] ^
				C6[byte(K[(i+2)%8]>>8)] ^
				C7[byte(K[(i+1)%8])]
		}
		L[0] ^= rc[r]

		for i := 0; i < 8; i++ {
			K[i] = L[i]
		}

		// Apply r-th round transformation.
		L[0] = C0[int(state[0]>>56)] ^
			C1[int((state[7]>>48)&0xff)] ^
			C2[int((state[6]>>40)&0xff)] ^
			C3[int((state[5]>>32)&0xff)] ^
			C4[int((state[4]>>24)&0xff)] ^
			C5[int((state[3]>>16)&0xff)] ^
			C6[int((state[2]>>8)&0xff)] ^
			C7[int(state[1]&0xff)] ^
			K[0]

		L[1] = C0[int(state[1]>>56)] ^
			C1[int((state[0]>>48)&0xff)] ^
			C2[int((state[7]>>40)&0xff)] ^
			C3[int((state[6]>>32)&0xff)] ^
			C4[int((state[5]>>24)&0xff)] ^
			C5[int((state[4]>>16)&0xff)] ^
			C6[int((state[3]>>8)&0xff)] ^
			C7[int(state[2]&0xff)] ^
			K[1]

		L[2] = C0[int(state[2]>>56)] ^
			C1[int((state[1]>>48)&0xff)] ^
			C2[int((state[0]>>40)&0xff)] ^
			C3[int((state[7]>>32)&0xff)] ^
			C4[int((state[6]>>24)&0xff)] ^
			C5[int((state[5]>>16)&0xff)] ^
			C6[int((state[4]>>8)&0xff)] ^
			C7[int(state[3]&0xff)] ^
			K[2]

		L[3] = C0[int(state[3]>>56)] ^
			C1[int((state[2]>>48)&0xff)] ^
			C2[int((state[1]>>40)&0xff)] ^
			C3[int((state[0]>>32)&0xff)] ^
			C4[int((state[7]>>24)&0xff)] ^
			C5[int((state[6]>>16)&0xff)] ^
			C6[int((state[5]>>8)&0xff)] ^
			C7[int(state[4]&0xff)] ^
			K[3]

		L[4] = C0[int(state[4]>>56)] ^
			C1[int((state[3]>>48)&0xff)] ^
			C2[int((state[2]>>40)&0xff)] ^
			C3[int((state[1]>>32)&0xff)] ^
			C4[int((state[0]>>24)&0xff)] ^
			C5[int((state[7]>>16)&0xff)] ^
			C6[int((state[6]>>8)&0xff)] ^
			C7[int(state[5]&0xff)] ^
			K[4]

		L[5] = C0[int(state[5]>>56)] ^
			C1[int((state[4]>>48)&0xff)] ^
			C2[int((state[3]>>40)&0xff)] ^
			C3[int((state[2]>>32)&0xff)] ^
			C4[int((state[1]>>24)&0xff)] ^
			C5[int((state[0]>>16)&0xff)] ^
			C6[int((state[7]>>8)&0xff)] ^
			C7[int(state[6]&0xff)] ^
			K[5]

		L[6] = C0[int(state[6]>>56)] ^
			C1[int((state[5]>>48)&0xff)] ^
			C2[int((state[4]>>40)&0xff)] ^
			C3[int((state[3]>>32)&0xff)] ^
			C4[int((state[2]>>24)&0xff)] ^
			C5[int((state[1]>>16)&0xff)] ^
			C6[int((state[0]>>8)&0xff)] ^
			C7[int(state[7]&0xff)] ^
			K[6]

		L[7] = C0[int(state[7]>>56)] ^
			C1[int((state[6]>>48)&0xff)] ^
			C2[int((state[5]>>40)&0xff)] ^
			C3[int((state[4]>>32)&0xff)] ^
			C4[int((state[3]>>24)&0xff)] ^
			C5[int((state[2]>>16)&0xff)] ^
			C6[int((state[1]>>8)&0xff)] ^
			C7[int(state[0]&0xff)] ^
			K[7]

		for i := 0; i < 8; i++ {
			state[i] = L[i]
		}
	}

	// Apply the Miyaguchi-Preneel compression function.
	for i := 0; i < 8; i++ {
		w.hash[i] ^= state[i] ^ block[i]
	}
}

func (w *whirlpool) Write(source []byte) (int, error) {
	var (
		sourcePos  int                                            // index of the leftmost source
		nn         int    = len(source)                           // num of bytes to process
		sourceBits uint64 = uint64(nn * 8)                        // num of bits to process
		value      uint64 = sourceBits                            // value
		sourceGap  uint   = uint((8 - (int(sourceBits & 7))) & 7) // space on source[sourcePos]
		bufferRem  uint   = uint(w.bufferBits & 7)                // occupied bits on buffer[bufferPos]
		b          uint32                                         // current byte
	)

	// Tally the length of the data added.
	for i, carry := 31, uint32(0); i >= 0 && (carry != 0 || value != 0); i-- {
		carry += uint32(w.bitLength[i]) + (uint32(value & 0xff))
		w.bitLength[i] = byte(carry)
		carry >>= 8
		value >>= 8
	}

	// Process data in chunks of 8 bits.
	for sourceBits > 8 {
		// Take a byte form the source.
		b = uint32(((source[sourcePos] << sourceGap) & 0xff) |
			((source[sourcePos+1] & 0xff) >> (8 - sourceGap)))

		// Process this byte.
		w.buffer[w.bufferPos] |= uint8(b >> bufferRem)
		w.bufferPos++
		w.bufferBits += int(8 - bufferRem)

		if w.bufferBits == digestBits {
			// Process this block.
			w.transform()
			// Reset the buffer.
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = byte(b << (8 - bufferRem))
		w.bufferBits += int(bufferRem)

		// Proceed to remaining data.
		sourceBits -= 8
		sourcePos++
	}

	// 0 <= sourceBits <= 8; All data leftover is in source[sourcePos].
	if sourceBits > 0 {
		b = uint32((source[sourcePos] << sourceGap) & 0xff) // bits are left-justified

		// Process the remaining bits.
		w.buffer[w.bufferPos] |= byte(b) >> bufferRem
	} else {
		b = 0
	}

	if uint64(bufferRem)+sourceBits < 8 {
		// The remaining data fits on the buffer[bufferPos].
		w.bufferBits += int(sourceBits)
	} else {
		// The buffer[bufferPos] is full.
		w.bufferPos++
		w.bufferBits += 8 - int(bufferRem) // bufferBits = 8*bufferPos
		sourceBits -= uint64(8 - bufferRem)

		// Now, 0 <= sourceBits <= 8; all data leftover is in source[sourcePos].
		if w.bufferBits == digestBits {
			// Process this data block.
			w.transform()
			// Reset buffer.
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = byte(b << (8 - bufferRem))
		w.bufferBits += int(sourceBits)
	}
	return nn, nil
}

func (w *whirlpool) Sum(in []byte) []byte {
	// Copy the whirlpool so that the caller can keep summing.
	n := *w

	// Append a 1-bit.
	n.buffer[n.bufferPos] |= 0x80 >> (uint(n.bufferBits) & 7)
	n.bufferPos++

	// The remaining bits should be 0. Pad with 0s to be complete.
	if n.bufferPos > wblockBytes-lengthBytes {
		if n.bufferPos < wblockBytes {
			for i := 0; i < wblockBytes-n.bufferPos; i++ {
				n.buffer[n.bufferPos+i] = 0
			}
		}
		// Process this data block.
		n.transform()
		// Reset the buffer.
		n.bufferPos = 0
	}

	if n.bufferPos < wblockBytes-lengthBytes {
		for i := 0; i < (wblockBytes-lengthBytes)-n.bufferPos; i++ {
			n.buffer[n.bufferPos+i] = 0
		}
	}
	n.bufferPos = wblockBytes - lengthBytes

	// Append the bit length of the hashed data.
	for i := 0; i < lengthBytes; i++ {
		n.buffer[n.bufferPos+i] = n.bitLength[i]
	}

	// Process this data block.
	n.transform()

	// Return the final digest as []byte.
	var digest [digestBytes]byte
	for i := 0; i < digestBytes/8; i++ {
		digest[i*8] = byte(n.hash[i] >> 56)
		digest[i*8+1] = byte(n.hash[i] >> 48)
		digest[i*8+2] = byte(n.hash[i] >> 40)
		digest[i*8+3] = byte(n.hash[i] >> 32)
		digest[i*8+4] = byte(n.hash[i] >> 24)
		digest[i*8+5] = byte(n.hash[i] >> 16)
		digest[i*8+6] = byte(n.hash[i] >> 8)
		digest[i*8+7] = byte(n.hash[i])
	}

	return append(in, digest[:digestBytes]...)
}
