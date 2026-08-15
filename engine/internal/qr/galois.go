package qr

// Reed-Solomon error correction over GF(256), and the bit stream that feeds it.

// GF(256) with the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), which
// is the one QR specifies. Logarithm and antilogarithm tables turn multiplication
// into addition, which is the only reason this is fast enough to do per block.
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	// Doubled so a product of two logs can be indexed without a modulo.
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator builds the generator polynomial for n error correction codewords.
func rsGenerator(n int) []byte {
	g := []byte{1}
	for i := 0; i < n; i++ {
		// Multiply by (x - a^i).
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g
}

// reedSolomon computes n error correction codewords for data.
func reedSolomon(data []byte, n int) []byte {
	gen := rsGenerator(n)
	rem := make([]byte, len(data)+n)
	copy(rem, data)

	for i := 0; i < len(data); i++ {
		lead := rem[i]
		if lead == 0 {
			continue
		}
		for j, g := range gen {
			rem[i+j] ^= gfMul(g, lead)
		}
	}
	return rem[len(data):]
}

// bitStream accumulates bits most-significant first.
type bitStream struct {
	buf  []byte
	nBit int
}

func (b *bitStream) write(value, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if b.nBit%8 == 0 {
			b.buf = append(b.buf, 0)
		}
		if (value>>i)&1 == 1 {
			b.buf[b.nBit/8] |= 1 << (7 - b.nBit%8)
		}
		b.nBit++
	}
}

func (b *bitStream) len() int      { return b.nBit }
func (b *bitStream) bytes() []byte { return b.buf }
