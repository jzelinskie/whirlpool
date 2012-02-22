package whirlpool

import "hash"

type whirlpool struct {
	bitLength  [lengthBytes]byte
	buffer     [wblockBytes]byte
	bufferBits int
	bufferPos  int
	hash       [digestBytes / 8]uint64
}

func NewWhirlpool() hash.Hash {
	d := new(whirlpool)
	d.Reset()
	return d
}

func (w *whirlpool) Reset() {
	w.bufferBits = 0
	w.bufferPos = 0
	w.buffer[0] = 0 // only necessary to clean bufferPos
	for i := 0; i < 8; i++ {
		w.hash[i] = 0
	}

}

func (w *whirlpool) Size() int {
	return digestBytes
}

func (w *whirlpool) BlockSize() int {
	return digestBytes
}

func (w *whirlpool) processBuffer() {
	var (
		K     [8]uint64
		block [8]uint64
		state [8]uint64
		L     [8]uint64
	)

	// map buffer to a block
	for i := 0; i < 8; i++ {
		b := 8 * i

		block[i] = ((uint64(w.buffer[k]) << 56) ^
			(uint64(w.buffer[b+1]) & 0xff << 48) ^
			(uint64(w.buffer[b+2]) & 0xff << 40) ^
			(uint64(w.buffer[b+3]) & 0xff << 32) ^
			(uint64(w.buffer[b+4]) & 0xff << 24) ^
			(uint64(w.buffer[b+5]) & 0xff << 16) ^
			(uint64(w.buffer[b+6]) & 0xff << 8) ^
			(uint64(w.buffer[b+7]) & 0xff))
	}

	// compute & apply K^0 to cipher state
	for i := 0; i < 8; i++ {
		K[i] = w.hash[i]
		state[i] = block[i] ^ K[i]
	}

	// iterate over all rounds
	for r := 1; r <= rounds; r++ {

		// compute K^rounds from K^(rounds-1)
		L[0] = (C0[int(K[0]>>56)] ^
			C1[int((K[7]>>48)&0xff)] ^
			C2[int((K[6]>>40)&0xff)] ^
			C3[int((K[5]>>32)&0xff)] ^
			C4[int((K[4]>>24)&0xff)] ^
			C5[int((K[3]>>16)&0xff)] ^
			C6[int((K[2]>>8)&0xff)] ^
			C7[int(K[1]&0xff)] ^
			rc[rounds])

		L[1] = (C0[int(K[1]>>56)] ^
			C1[int((K[0]>>48)&0xff)] ^
			C2[int((K[7]>>40)&0xff)] ^
			C3[int((K[6]>>32)&0xff)] ^
			C4[int((K[5]>>24)&0xff)] ^
			C5[int((K[4]>>16)&0xff)] ^
			C6[int((K[3]>>8)&0xff)] ^
			C7[int(K[2]&0xff)])

		L[2] = (C0[int(K[2]>>56)] ^
			C1[int((K[1]>>48)&0xff)] ^
			C2[int((K[0]>>40)&0xff)] ^
			C3[int((K[7]>>32)&0xff)] ^
			C4[int((K[6]>>24)&0xff)] ^
			C5[int((K[5]>>16)&0xff)] ^
			C6[int((K[4]>>8)&0xff)] ^
			C7[int(K[3]&0xff)])

		L[3] = (C0[int(K[3]>>56)] ^
			C1[int((K[2]>>48)&0xff)] ^
			C2[int((K[1]>>40)&0xff)] ^
			C3[int((K[0]>>32)&0xff)] ^
			C4[int((K[7]>>24)&0xff)] ^
			C5[int((K[6]>>16)&0xff)] ^
			C6[int((K[5]>>8)&0xff)] ^
			C7[int(K[4]&0xff)])

		L[4] = (C0[int(K[4]>>56)] ^
			C1[int((K[3]>>48)&0xff)] ^
			C2[int((K[2]>>40)&0xff)] ^
			C3[int((K[1]>>32)&0xff)] ^
			C4[int((K[0]>>24)&0xff)] ^
			C5[int((K[7]>>16)&0xff)] ^
			C6[int((K[6]>>8)&0xff)] ^
			C7[int(K[5]&0xff)])

		L[5] = (C0[int(K[5]>>56)] ^
			C1[int((K[4]>>48)&0xff)] ^
			C2[int((K[3]>>40)&0xff)] ^
			C3[int((K[2]>>32)&0xff)] ^
			C4[int((K[1]>>24)&0xff)] ^
			C5[int((K[0]>>16)&0xff)] ^
			C6[int((K[7]>>8)&0xff)] ^
			C7[int(K[6]&0xff)])

		L[6] = (C0[int(K[6]>>56)] ^
			C1[int((K[5]>>48)&0xff)] ^
			C2[int((K[4]>>40)&0xff)] ^
			C3[int((K[3]>>32)&0xff)] ^
			C4[int((K[2]>>24)&0xff)] ^
			C5[int((K[1]>>16)&0xff)] ^
			C6[int((K[0]>>8)&0xff)] ^
			C7[int(K[7]&0xff)])

		L[7] = (C0[int(K[7]>>56)] ^
			C1[int((K[6]>>48)&0xff)] ^
			C2[int((K[5]>>40)&0xff)] ^
			C3[int((K[4]>>32)&0xff)] ^
			C4[int((K[3]>>24)&0xff)] ^
			C5[int((K[2]>>16)&0xff)] ^
			C6[int((K[1]>>8)&0xff)] ^
			C7[int(K[0]&0xff)])

		for i := 0; i < 8; i++ {
			K[i] = L[i]
		}

		// apply the round transformation
		L[0] = (C0[int(state[0]>>56)] ^
			C1[int((state[7]>>48)&0xff)] ^
			C2[int((state[6]>>40)&0xff)] ^
			C3[int((state[5]>>32)&0xff)] ^
			C4[int((state[4]>>24)&0xff)] ^
			C5[int((state[3]>>16)&0xff)] ^
			C6[int((state[2]>>8)&0xff)] ^
			C7[int(state[1]&0xff)]) ^
			K[0]

		L[1] = (C0[int(state[1]>>56)] ^
			C1[int((state[0]>>48)&0xff)] ^
			C2[int((state[7]>>40)&0xff)] ^
			C3[int((state[6]>>32)&0xff)] ^
			C4[int((state[5]>>24)&0xff)] ^
			C5[int((state[4]>>16)&0xff)] ^
			C6[int((state[3]>>8)&0xff)] ^
			C7[int(state[2]&0xff)]) ^
			K[1]

		L[2] = (C0[int(state[2]>>56)] ^
			C1[int((state[1]>>48)&0xff)] ^
			C2[int((state[0]>>40)&0xff)] ^
			C3[int((state[7]>>32)&0xff)] ^
			C4[int((state[6]>>24)&0xff)] ^
			C5[int((state[5]>>16)&0xff)] ^
			C6[int((state[4]>>8)&0xff)] ^
			C7[int(state[3]&0xff)]) ^
			K[2]

		L[3] = (C0[int(state[3]>>56)] ^
			C1[int((state[2]>>48)&0xff)] ^
			C2[int((state[1]>>40)&0xff)] ^
			C3[int((state[0]>>32)&0xff)] ^
			C4[int((state[7]>>24)&0xff)] ^
			C5[int((state[6]>>16)&0xff)] ^
			C6[int((state[5]>>8)&0xff)] ^
			C7[int(state[4]&0xff)]) ^
			K[3]

		L[4] = (C0[int(state[4]>>56)] ^
			C1[int((state[3]>>48)&0xff)] ^
			C2[int((state[2]>>40)&0xff)] ^
			C3[int((state[1]>>32)&0xff)] ^
			C4[int((state[0]>>24)&0xff)] ^
			C5[int((state[7]>>16)&0xff)] ^
			C6[int((state[6]>>8)&0xff)] ^
			C7[int(state[5]&0xff)]) ^
			K[4]

		L[5] = (C0[int(state[5]>>56)] ^
			C1[int((state[4]>>48)&0xff)] ^
			C2[int((state[3]>>40)&0xff)] ^
			C3[int((state[2]>>32)&0xff)] ^
			C4[int((state[1]>>24)&0xff)] ^
			C5[int((state[0]>>16)&0xff)] ^
			C6[int((state[7]>>8)&0xff)] ^
			C7[int(state[6]&0xff)]) ^
			K[5]

		L[6] = (C0[int(state[6]>>56)] ^
			C1[int((state[5]>>48)&0xff)] ^
			C2[int((state[4]>>40)&0xff)] ^
			C3[int((state[3]>>32)&0xff)] ^
			C4[int((state[2]>>24)&0xff)] ^
			C5[int((state[1]>>16)&0xff)] ^
			C6[int((state[0]>>8)&0xff)] ^
			C7[int(state[7]&0xff)]) ^
			K[6]

		L[7] = (C0[int(state[7]>>56)] ^
			C1[int((state[6]>>48)&0xff)] ^
			C2[int((state[5]>>40)&0xff)] ^
			C3[int((state[4]>>32)&0xff)] ^
			C4[int((state[3]>>24)&0xff)] ^
			C5[int((state[2]>>16)&0xff)] ^
			C6[int((state[1]>>8)&0xff)] ^
			C7[int(state[0]&0xff)]) ^
			K[7]

		for i := 0; i < 8; i++ {
			state[i] = L[i]
		}

		// apply miyaguchi-preneel compression function
		for i := 0; i < 8; i++ {
			w.hash[i] ^= state[i] ^ block[i]
		}
	}
}

func (w *whirlpool) Write(source []byte) (nn int, err error) {
	nn = len(source)

	var (
		sourcePos  int
		sourceBits uint32 = uint32(len(source) * 8)
		sourceGap  int    = 8 - (int(sourceBits&7))&7
		bufferRem  int    = w.bufferBits & 7
		value      uint64 = sourceBits
		b          uint32
	)

	for i, carry := 31, uint32(0); i >= 0 && (carry != 0 || value != 0); i-- {
		carry += w.bitLength[i] + (uint32(value & 0xff))
		w.bitLength[i] = uint8(carry)
		carry >>= 8
		value >>= 8
	}

	// process data in chunks of 8 bits
	for sourceBits > 8 {
		// take a byte form the source
		b = (((source[sourcePos] << sourceGap) & 0xff) |
			((source[sourcePost+1] & 0xff) >> (8 - sourceGap)))

		// process this byte
		w.bufferPos++
		w.buffer[w.bufferPos] |= uint8(b >> bufferRem)
		w.bufferBits += 8 - bufferRem
		if w.bufferBits == digestBits {
			// process this block
			w.processBuffer()

			// reset the buffer
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = uint8(b << (8 - bufferRem))
		w.bufferBits += bufferRem

		// proceed to remaining data
		sourceBits -= 8
		sourcePos++
	}

	// 0 <= sourceBits <= 8; all data leftover is in source[sourcePos]
	if sourceBits > 0 {
		b = (source[sourcePos] << sourceGap) & 0xff // bits are left-justified

		// process remaining bits
		w.buffer[w.bufferPos] |= b >> bufferRem
	} else {
		b = 0
	}

	if bufferRem+sourceBits < 8 {
		w.bufferBits += sourceBits
	} else {
		w.bufferPos++
		w.bufferBits += 8 - bufferRem // w.bufferBits = 8*w.bufferPos
		sourceBits -= 8 - bufferRem
		// now 0 <= sourceBits <= 8; all data leftover is in source[sourcePos]
		if w.bufferBits == digestBits {
			// process data block
			w.processBuffer()

			// reset buffer
			w.bufferBits = 0
			w.bufferPost = 0
		}
		w.buffer[w.bufferPos] = uint8(b << (8 - bufferRem))
		w.bufferBits += int(sourceBits)
	}
}

func (w *whirlpool) Sum(in []byte) []byte {
	var digest *[]byte

	// copy the whirlpool so that the caller can keep summing
	n := *w

	// append a 1-bit
	n.buffer[n.bufferPos] |= 0x80 >> (n.bufferBits & 7)
	n.bufferPos++ // remaining bits are 0

	// pad with 0 bits
	if n.bufferPos > wblockBytes-lengthBytes {
		if n.bufferPos < wblockBytes {
			//TODO memset
		}
		// process data block
		n.processBuffer()
		// reset buffer
		n.bufferPos = 0
	}

	if n.bufferPos < wblockBytes-lengthBytes {
		//TODO memset
	}
	n.bufferPos = wblockBytes - lengthBytes

	// append bit length of hashed data
	//TODO memcpy

	// process data block
	n.processBuffer()

	// return the final digest as []byte
	for i := 0; i < digestBytes/8; i++ {
		digest[0] = uint8(n.hash[i] >> 56)
		digest[1] = uint8(n.hash[i] >> 48)
		digest[2] = uint8(n.hash[i] >> 40)
		digest[3] = uint8(n.hash[i] >> 32)
		digest[4] = uint8(n.hash[i] >> 24)
		digest[5] = uint8(n.hash[i] >> 16)
		digest[6] = uint8(n.hash[i] >> 8)
		digest[7] = uint8(n.hash[i])
		digest += 8
	}

	return append(in, digest[:lengthBytes])
}
