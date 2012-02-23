package whirlpool

import (
	"fmt"
	"hash"
)

type whirlpool struct {
	bitLength  [lengthBytes]byte       // number of hashed bits
	buffer     [wblockBytes]byte       // buffer of data to be hashed
	bufferBits int                     // current number of bits on the buffer
	bufferPos  int                     // current byte location on buffer
	hash       [digestBytes / 8]uint64 // hash state
}

func New() hash.Hash {
	d := new(whirlpool)
	return d
}

func (w *whirlpool) Reset() {
	// cleanup buffer
	w.bufferBits = 0
	w.bufferPos = 0
	w.buffer[0] = 0 // only necessary to clean bufferPos

	// cleanup digest
	w.hash = [digestBytes / 8]uint64{}

	// clean number of hashed bits
	w.bitLength = [lengthBytes]byte{}
}

func (w *whirlpool) Size() int {
	return digestBytes
}

func (w *whirlpool) BlockSize() int {
	return wblockBytes
}

func (w *whirlpool) transform() {
	fmt.Println("transform starts")
	var (
		K     [8]uint64 // round key
		block [8]uint64 // mu(buffer)
		state [8]uint64 // cipher state
		L     [8]uint64
	)

	/* TRACE */
	fmt.Printf("The 8x8 matrix Z' derived from the data-string is as follows.\n")
	for i := 0; i < wblockBytes/8; i++ {
		fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X\n",
			w.buffer[8*i], w.buffer[8*i+1], w.buffer[8*i+2], w.buffer[8*i+3],
			w.buffer[8*i+4], w.buffer[8*i+5], w.buffer[8*i+6], w.buffer[8*i+7])
	}

	// map buffer to a block
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

	// compute & apply K^0 to cipher state
	for i := 0; i < 8; i++ {
		state[i] = block[i] ^ K[i]
		w.hash[i] = state[i]
	}

	/* TRACE */
	fmt.Printf("\nThe K_0 matrix (from the initialization value IV) and X'' matrix are as follows.\n")
	for i := 0; i < digestBytes/8; i++ {
		fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X        %02X %02X %02X %02X %02X %02X %02X %02X\n",
			byte(K[i]>>56),
			byte(K[i]>>48),
			byte(K[i]>>40),
			byte(K[i]>>32),
			byte(K[i]>>24),
			byte(K[i]>>16),
			byte(K[i]>>8),
			byte(K[i]),
			byte(state[i]>>56),
			byte(state[i]>>48),
			byte(state[i]>>40),
			byte(state[i]>>32),
			byte(state[i]>>24),
			byte(state[i]>>16),
			byte(state[i]>>8),
			byte(state[i]))
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

		// apply r-th round transformation
		L[0] = (C0[int(state[0]>>56)] ^
			C1[int((state[7]>>48)&0xff)] ^
			C2[int((state[6]>>40)&0xff)] ^
			C3[int((state[5]>>32)&0xff)] ^
			C4[int((state[4]>>24)&0xff)] ^
			C5[int((state[3]>>16)&0xff)] ^
			C6[int((state[2]>>8)&0xff)] ^
			C7[int(state[1]&0xff)] ^
			K[0])

		L[1] = (C0[int(state[1]>>56)] ^
			C1[int((state[0]>>48)&0xff)] ^
			C2[int((state[7]>>40)&0xff)] ^
			C3[int((state[6]>>32)&0xff)] ^
			C4[int((state[5]>>24)&0xff)] ^
			C5[int((state[4]>>16)&0xff)] ^
			C6[int((state[3]>>8)&0xff)] ^
			C7[int(state[2]&0xff)] ^
			K[1])

		L[2] = (C0[int(state[2]>>56)] ^
			C1[int((state[1]>>48)&0xff)] ^
			C2[int((state[0]>>40)&0xff)] ^
			C3[int((state[7]>>32)&0xff)] ^
			C4[int((state[6]>>24)&0xff)] ^
			C5[int((state[5]>>16)&0xff)] ^
			C6[int((state[4]>>8)&0xff)] ^
			C7[int(state[3]&0xff)] ^
			K[2])

		L[3] = (C0[int(state[3]>>56)] ^
			C1[int((state[2]>>48)&0xff)] ^
			C2[int((state[1]>>40)&0xff)] ^
			C3[int((state[0]>>32)&0xff)] ^
			C4[int((state[7]>>24)&0xff)] ^
			C5[int((state[6]>>16)&0xff)] ^
			C6[int((state[5]>>8)&0xff)] ^
			C7[int(state[4]&0xff)] ^
			K[3])

		L[4] = (C0[int(state[4]>>56)] ^
			C1[int((state[3]>>48)&0xff)] ^
			C2[int((state[2]>>40)&0xff)] ^
			C3[int((state[1]>>32)&0xff)] ^
			C4[int((state[0]>>24)&0xff)] ^
			C5[int((state[7]>>16)&0xff)] ^
			C6[int((state[6]>>8)&0xff)] ^
			C7[int(state[5]&0xff)] ^
			K[4])

		L[5] = (C0[int(state[5]>>56)] ^
			C1[int((state[4]>>48)&0xff)] ^
			C2[int((state[3]>>40)&0xff)] ^
			C3[int((state[2]>>32)&0xff)] ^
			C4[int((state[1]>>24)&0xff)] ^
			C5[int((state[0]>>16)&0xff)] ^
			C6[int((state[7]>>8)&0xff)] ^
			C7[int(state[6]&0xff)] ^
			K[5])

		L[6] = (C0[int(state[6]>>56)] ^
			C1[int((state[5]>>48)&0xff)] ^
			C2[int((state[4]>>40)&0xff)] ^
			C3[int((state[3]>>32)&0xff)] ^
			C4[int((state[2]>>24)&0xff)] ^
			C5[int((state[1]>>16)&0xff)] ^
			C6[int((state[0]>>8)&0xff)] ^
			C7[int(state[7]&0xff)] ^
			K[6])

		L[7] = (C0[int(state[7]>>56)] ^
			C1[int((state[6]>>48)&0xff)] ^
			C2[int((state[5]>>40)&0xff)] ^
			C3[int((state[4]>>32)&0xff)] ^
			C4[int((state[3]>>24)&0xff)] ^
			C5[int((state[2]>>16)&0xff)] ^
			C6[int((state[1]>>8)&0xff)] ^
			C7[int(state[0]&0xff)] ^
			K[7])

		for i := 0; i < 8; i++ {
			state[i] = L[i]
		}

		/* TRACE */
		fmt.Printf("The following are (hexadecimal representations of) the successive values of the variables K_i for i = 1 to 10 and W'.\n")
		fmt.Printf("i = %d\n", r)
		for i := 0; i < digestBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X        %02X %02X %02X %02X %02X %02X %02X %02X\n",
				byte(K[i]>>56),
				byte(K[i]>>48),
				byte(K[i]>>40),
				byte(K[i]>>32),
				byte(K[i]>>24),
				byte(K[i]>>16),
				byte(K[i]>>8),
				byte(K[i]),

				byte(state[i]>>56),
				byte(state[i]>>48),
				byte(state[i]>>40),
				byte(state[i]>>32),
				byte(state[i]>>24),
				byte(state[i]>>16),
				byte(state[i]>>8),
				byte(state[i]))
		}
		fmt.Printf("\n")

	}

	// apply miyaguchi-preneel compression function
	for i := 0; i < 8; i++ {
		w.hash[i] ^= state[i] ^ block[i]
	}
}

func (w *whirlpool) Write(source []byte) (nn int, err error) {
	nn = len(source)
	fmt.Println("write starts")

	var (
		sourcePos  int                                         // index of the leftmost source
		sourceBits uint64 = uint64(len(source) * 8)            // num of bits to process
		sourceGap  uint64 = uint64((8 - (sourceBits & 7)) & 7) // space on source[sourcePos]
		bufferRem  uint64 = uint64(w.bufferBits & 7)           // occupied bits on buffer[bufferPos]
		value      uint64 = uint64(sourceBits)
		b          byte
	)

	/* TRACE */
	//fmt.Printf("%X\n%X\n%X\n%X\n%X\n%X\n", sourcePos, sourceBits, sourceGap, bufferRem, value, b)

	// tally length of data added
	for i, carry := 31, uint32(0); i >= 0 && (carry != 0 || value != 0); i-- {
		carry += uint32(w.bitLength[i]) + (uint32(value & 0xff))
		w.bitLength[i] = byte(carry)
		carry >>= 8
		value >>= 8
	}

	// process data in chunks of 8 bits
	for sourceBits > 8 {
		// take a byte form the source
		b = (((source[sourcePos] << sourceGap) & 0xff) |
			((source[sourcePos+1] & 0xff) >> (8 - sourceGap)))

		// process this byte
		w.bufferPos++
		w.buffer[w.bufferPos] |= uint8(b >> bufferRem)
		w.bufferBits += int(8 - bufferRem)

		if w.bufferBits == digestBits {
			// process this block
			w.transform()
			// reset the buffer
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = uint8(b << (8 - bufferRem))
		w.bufferBits += int(bufferRem)

		// proceed to remaining data
		sourceBits -= 8
		sourcePos++
	}

	// 0 <= sourceBits <= 8; all data leftover is in source[sourcePos]
	if sourceBits > 0 {
		b = byte((source[sourcePos] << sourceGap) & 0xff) // bits are left-justified

		// process remaining bits
		w.buffer[w.bufferPos] |= b >> bufferRem
	} else {
		b = 0
	}

	if bufferRem+sourceBits < 8 {
		// remaining data fits on buffer[bufferPos]
		w.bufferBits += int(sourceBits)
	} else {
		// buffer[bufferPos] is full
		w.bufferPos++
		w.bufferBits += 8 - int(bufferRem) // bufferBits = 8*bufferPos
		sourceBits -= 8 - bufferRem

		// now 0 <= sourceBits <= 8; all data leftover is in source[sourcePos]
		if w.bufferBits == digestBits {
			// process data block
			w.transform()
			// reset buffer
			w.bufferBits = 0
			w.bufferPos = 0
		}
		w.buffer[w.bufferPos] = byte(b << (8 - bufferRem))
		w.bufferBits += int(sourceBits)
	}
	return
}

func (w *whirlpool) Sum(in []byte) []byte {
	// copy the whirlpool so that the caller can keep summing
	n := *w

	// append a 1-bit
	n.buffer[n.bufferPos] |= 0x80 >> (uint(n.bufferBits) & 7)
	n.bufferPos++ // remaining bits are left 0

	if n.bufferPos > wblockBytes-lengthBytes {
		// process data block
		n.transform()
		// reset buffer
		n.bufferPos = 0
	}

	if n.bufferPos < wblockBytes-lengthBytes {
		for n.bufferPos < (wblockBytes - lengthBytes - n.bufferPos) {
			n.buffer[n.bufferPos] = 0
			n.bufferPos++
		}
	}
	n.bufferPos = wblockBytes - lengthBytes

	// append bit length of hashed data
	for i := 0; n.bufferPos < wblockBytes; i++ {
		n.buffer[n.bufferPos] = n.bitLength[i]
		n.bufferPos++
	}

	// process data block
	n.transform()

	// return the final digest as []byte
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
