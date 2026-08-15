// Package qr encodes a QR code, in byte mode at error correction level M.
//
// # Why this is written here rather than imported
//
// TOTP enrolment showed the shared secret as text for manual typing. Most people
// expect to point a camera at a square, and the ones who do not expect it often
// cannot manage the alternative on a phone keyboard. That gap was flagged twice
// in this project's own notes and never closed.
//
// The obvious library, github.com/skip2/go-qrcode, is archived and has not been
// touched since 2020. Adding an unmaintained dependency to an identity provider
// -- to render, of all things, the enrolment secret for the second factor -- is a
// worse trade than the code below.
//
// # Scope, deliberately narrow
//
// Byte mode only, error correction level M only, versions 1 to 12. That covers
// every otpauth:// URI this product produces (they run 90-160 bytes; version 12
// holds 288) and nothing else. A general encoder would be several times the size
// and every extra path would be one nothing here exercises.
//
// # How it is known to be right
//
// Not by inspection. The output is checked two independent ways in the tests:
// against Python's `qrcode` reference implementation module-for-module, and by
// decoding the rendered image with OpenCV's detector. An encoder nobody can
// decode is worse than printing the secret, because it looks like it works.
package qr

import (
	"fmt"
	"strings"
)

// ecLevelM is the only error correction level supported. Roughly 15% of the
// symbol can be lost and still read, which is the usual choice for something
// displayed on a screen rather than printed on a box.
const ecLevelM = 0

// blockSpec describes how a version's codewords are split for error correction.
type blockSpec struct {
	ecPerBlock int
	g1Blocks   int
	g1Data     int
	g2Blocks   int
	g2Data     int
}

// specsM is the block layout per version at level M, from the standard's tables.
var specsM = map[int]blockSpec{
	1:  {10, 1, 16, 0, 0},
	2:  {16, 1, 28, 0, 0},
	3:  {26, 1, 44, 0, 0},
	4:  {18, 2, 32, 0, 0},
	5:  {24, 2, 43, 0, 0},
	6:  {16, 4, 27, 0, 0},
	7:  {18, 4, 31, 0, 0},
	8:  {22, 2, 38, 2, 39},
	9:  {22, 3, 36, 2, 37},
	10: {26, 4, 43, 1, 44},
	11: {30, 1, 50, 4, 51},
	12: {22, 6, 36, 2, 37},
}

// alignmentCenters are the row/column centres of the alignment patterns.
var alignmentCenters = map[int][]int{
	1: nil, 2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
	11: {6, 30, 54}, 12: {6, 32, 58},
}

func (b blockSpec) dataCodewords() int {
	return b.g1Blocks*b.g1Data + b.g2Blocks*b.g2Data
}

// Code is an encoded symbol.
type Code struct {
	Size    int
	modules []bool // row-major, Size*Size
}

// Dark reports whether the module at (x, y) is dark.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.modules[y*c.Size+x]
}

// Encode builds a QR code for data.
func Encode(data []byte) (*Code, error) {
	version, spec, err := pickVersion(len(data))
	if err != nil {
		return nil, err
	}

	codewords := buildCodewords(data, version, spec)
	size := 17 + 4*version

	// Every mask is applied and scored; the lowest penalty wins. This is not
	// cosmetic -- masking is what stops long runs and finder-like shapes forming
	// in the data area, which is what makes a symbol unreadable at an angle.
	var best *Code
	bestPenalty := -1
	for mask := 0; mask < 8; mask++ {
		c := &Code{Size: size, modules: make([]bool, size*size)}
		reserved := make([]bool, size*size)
		c.placeFunctionPatterns(reserved)
		c.placeFormatInfo(mask, reserved)
		if version >= 7 {
			c.placeVersionInfo(version, reserved)
		}
		c.placeData(codewords, reserved, mask)

		p := c.penalty()
		if bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = c, p
		}
	}
	return best, nil
}

func pickVersion(n int) (int, blockSpec, error) {
	for v := 1; v <= 12; v++ {
		spec := specsM[v]
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*n <= spec.dataCodewords()*8 {
			return v, spec, nil
		}
	}
	return 0, blockSpec{}, fmt.Errorf("qr: %d bytes does not fit in version 12 at level M "+
		"(288 codewords); this encoder is deliberately limited to what otpauth URIs need", n)
}

// buildCodewords produces the interleaved data and error correction stream.
func buildCodewords(data []byte, version int, spec blockSpec) []byte {
	countBits := 8
	if version >= 10 {
		countBits = 16
	}

	var bs bitStream
	bs.write(0b0100, 4) // byte mode
	bs.write(len(data), countBits)
	for _, b := range data {
		bs.write(int(b), 8)
	}

	capacity := spec.dataCodewords() * 8
	// Terminator: up to four zero bits, fewer if the symbol is nearly full.
	if rem := capacity - bs.len(); rem > 0 {
		bs.write(0, min(4, rem))
	}
	for bs.len()%8 != 0 {
		bs.write(0, 1)
	}
	// Alternating pad bytes, fixed by the standard.
	for pad := 0; bs.len() < capacity; pad++ {
		if pad%2 == 0 {
			bs.write(0xEC, 8)
		} else {
			bs.write(0x11, 8)
		}
	}
	dataBytes := bs.bytes()

	// Split into blocks, compute ECC per block.
	var dataBlocks, ecBlocks [][]byte
	pos := 0
	for i := 0; i < spec.g1Blocks; i++ {
		blk := dataBytes[pos : pos+spec.g1Data]
		pos += spec.g1Data
		dataBlocks = append(dataBlocks, blk)
		ecBlocks = append(ecBlocks, reedSolomon(blk, spec.ecPerBlock))
	}
	for i := 0; i < spec.g2Blocks; i++ {
		blk := dataBytes[pos : pos+spec.g2Data]
		pos += spec.g2Data
		dataBlocks = append(dataBlocks, blk)
		ecBlocks = append(ecBlocks, reedSolomon(blk, spec.ecPerBlock))
	}

	// Interleave: one codeword from each block in turn. This is what makes a
	// burst of damage spread across blocks instead of destroying one entirely.
	var out []byte
	maxData := max(spec.g1Data, spec.g2Data)
	for i := 0; i < maxData; i++ {
		for _, blk := range dataBlocks {
			if i < len(blk) {
				out = append(out, blk[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, blk := range ecBlocks {
			out = append(out, blk[i])
		}
	}
	return out
}

// SVG renders the code as a scalable image.
//
// SVG rather than PNG so there is no image encoder, no rasterising, and no
// blurring when a browser scales it -- and so it can be inlined in the page,
// which matters because the enrolment page carries a Content-Security-Policy
// that forbids external sources.
func (c *Code) SVG(moduleSize, quiet int) string {
	if moduleSize <= 0 {
		moduleSize = 4
	}
	// The quiet zone is four modules in the specification and is NOT decoration:
	// detectors look for the finder patterns against clear space, and a symbol
	// flush against page content is measurably harder to read.
	if quiet < 0 {
		quiet = 4
	}
	dim := (c.Size + 2*quiet) * moduleSize

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" `+
		`viewBox="0 0 %d %d" role="img" aria-label="QR code for authenticator enrolment" `+
		`shape-rendering="crispEdges">`, dim, dim, dim, dim)
	// White is drawn explicitly rather than left transparent: on a dark-themed
	// page a transparent background puts dark modules on dark, and the symbol
	// simply does not scan.
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, dim, dim)
	b.WriteString(`<path fill="#000000" d="`)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Dark(x, y) {
				fmt.Fprintf(&b, "M%d %dh%dv%dh-%dz",
					(x+quiet)*moduleSize, (y+quiet)*moduleSize,
					moduleSize, moduleSize, moduleSize)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
