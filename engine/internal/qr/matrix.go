package qr

// Module placement: function patterns, format and version information, the data
// zigzag, masking and the penalty score.

func (c *Code) set(x, y int, dark bool) {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return
	}
	c.modules[y*c.Size+x] = dark
}

func (c *Code) reserve(reserved []bool, x, y int) {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return
	}
	reserved[y*c.Size+x] = true
}

// placeFunctionPatterns draws everything whose position is fixed by the version:
// the three finders, their separators, the timing lines, the alignment patterns
// and the one permanently dark module.
func (c *Code) placeFunctionPatterns(reserved []bool) {
	n := c.Size

	// Finders, at three corners. Their absence in the fourth is what tells a
	// detector the symbol's orientation.
	for _, p := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		c.placeFinder(p[0], p[1], reserved)
	}

	// Timing patterns: alternating modules along row 6 and column 6, which give
	// a detector the module pitch.
	for i := 8; i < n-8; i++ {
		dark := i%2 == 0
		c.set(i, 6, dark)
		c.reserve(reserved, i, 6)
		c.set(6, i, dark)
		c.reserve(reserved, 6, i)
	}

	// Alignment patterns, skipping the three that would collide with finders.
	centers := alignmentCenters[(n-17)/4]
	for _, cy := range centers {
		for _, cx := range centers {
			if (cx == 6 && cy == 6) || (cx == 6 && cy == n-7) || (cx == n-7 && cy == 6) {
				continue
			}
			c.placeAlignment(cx, cy, reserved)
		}
	}

	// The dark module, always at (8, 4*version+9).
	c.set(8, n-8, true)
	c.reserve(reserved, 8, n-8)
}

func (c *Code) placeFinder(ox, oy int, reserved []bool) {
	// 7x7 pattern plus a one-module separator all round.
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			x, y := ox+dx, oy+dy
			if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
				continue
			}
			inRing := dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 &&
				(dx == 0 || dx == 6 || dy == 0 || dy == 6)
			inCore := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			c.set(x, y, inRing || inCore)
			c.reserve(reserved, x, y)
		}
	}
}

func (c *Code) placeAlignment(cx, cy int, reserved []bool) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			dark := dx == -2 || dx == 2 || dy == -2 || dy == 2 || (dx == 0 && dy == 0)
			c.set(cx+dx, cy+dy, dark)
			c.reserve(reserved, cx+dx, cy+dy)
		}
	}
}

// placeFormatInfo writes the 15-bit format information, twice.
//
// It is duplicated in two places on purpose: the format bits say which mask was
// used, so losing them makes the entire symbol undecodable no matter how intact
// the data is.
func (c *Code) placeFormatInfo(mask int, reserved []bool) {
	bits := formatBits(ecLevelM, mask)
	n := c.Size

	for i := 0; i < 15; i++ {
		// LEAST significant bit first. The standard numbers the format bits from
		// bit 0 outwards along each arm, not from the top of the 15-bit word, and
		// reversing them produces a symbol whose function patterns are perfect and
		// which no scanner can read -- the format field is how a decoder learns
		// which mask to undo, so getting it wrong loses the entire payload while
		// the picture looks flawless.
		dark := (bits>>i)&1 == 1

		// First copy: around the top-left finder.
		switch {
		case i < 6:
			c.set(8, i, dark)
			c.reserve(reserved, 8, i)
		case i == 6:
			c.set(8, 7, dark)
			c.reserve(reserved, 8, 7)
		case i == 7:
			c.set(8, 8, dark)
			c.reserve(reserved, 8, 8)
		case i == 8:
			c.set(7, 8, dark)
			c.reserve(reserved, 7, 8)
		default:
			c.set(14-i, 8, dark)
			c.reserve(reserved, 14-i, 8)
		}

		// Second copy: split between the other two finders.
		if i < 8 {
			c.set(n-1-i, 8, dark)
			c.reserve(reserved, n-1-i, 8)
		} else {
			c.set(8, n-15+i, dark)
			c.reserve(reserved, 8, n-15+i)
		}
	}
}

// placeVersionInfo writes the 18-bit version information, for version 7 and up.
func (c *Code) placeVersionInfo(version int, reserved []bool) {
	bits := versionBits(version)
	n := c.Size
	for i := 0; i < 18; i++ {
		dark := (bits>>i)&1 == 1
		x, y := i/3, n-11+i%3
		c.set(x, y, dark)
		c.reserve(reserved, x, y)
		c.set(y, x, dark)
		c.reserve(reserved, y, x)
	}
}

// placeData walks the symbol in the standard zigzag and writes the codeword
// stream, applying the mask as it goes.
//
// The walk is two columns wide, upward then downward, right to left, skipping
// column 6 entirely because the vertical timing pattern lives there. Getting the
// skip wrong shifts every subsequent bit and produces a symbol that looks
// perfectly plausible and decodes to nothing.
func (c *Code) placeData(codewords []byte, reserved []bool, mask int) {
	n := c.Size
	bit := 0
	total := len(codewords) * 8

	upward := true
	for right := n - 1; right > 0; right -= 2 {
		if right == 6 {
			right = 5 // skip the timing column
		}
		for i := 0; i < n; i++ {
			y := i
			if upward {
				y = n - 1 - i
			}
			for _, x := range []int{right, right - 1} {
				if reserved[y*n+x] {
					continue
				}
				dark := false
				if bit < total {
					dark = (codewords[bit/8]>>(7-bit%8))&1 == 1
					bit++
				}
				// Remainder bits past the end of the stream stay light before
				// masking, which is what the standard specifies.
				if maskAt(mask, x, y) {
					dark = !dark
				}
				c.set(x, y, dark)
			}
		}
		upward = !upward
	}
}

// maskAt reports whether the mask inverts the module at (x, y).
func maskAt(mask, x, y int) bool {
	switch mask {
	case 0:
		return (y+x)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (y+x)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (y*x)%2+(y*x)%3 == 0
	case 6:
		return ((y*x)%2+(y*x)%3)%2 == 0
	default:
		return ((y+x)%2+(y*x)%3)%2 == 0
	}
}

// penalty scores a masked symbol; lower is better.
//
// The four rules come straight from the standard and exist to discourage
// patterns a scanner mistakes for structure -- long runs, solid blocks, and
// especially the 1:1:3:1:1 ratio that looks like a finder.
func (c *Code) penalty() int {
	n := c.Size
	score := 0

	// Rule 1: runs of five or more identical modules in a row or column.
	for _, byRow := range []bool{true, false} {
		for a := 0; a < n; a++ {
			run, prev := 0, false
			for b := 0; b < n; b++ {
				var v bool
				if byRow {
					v = c.Dark(b, a)
				} else {
					v = c.Dark(a, b)
				}
				if b > 0 && v == prev {
					run++
				} else {
					if run >= 5 {
						score += run - 2
					}
					run = 1
				}
				prev = v
			}
			if run >= 5 {
				score += run - 2
			}
		}
	}

	// Rule 2: every 2x2 block of one colour.
	for y := 0; y < n-1; y++ {
		for x := 0; x < n-1; x++ {
			v := c.Dark(x, y)
			if v == c.Dark(x+1, y) && v == c.Dark(x, y+1) && v == c.Dark(x+1, y+1) {
				score += 3
			}
		}
	}

	// Rule 3: the finder-like 1:1:3:1:1 sequence with four light modules beside it.
	//
	// Checked as one ELEVEN-module window, which is how the standard states it,
	// rather than as a seven-module pattern with a separate look outwards. The
	// difference shows up at the edges: treating off-symbol positions as light
	// makes every near-edge occurrence score, the totals come out high, and a
	// worse mask wins -- a symbol that is valid and harder to scan, which is the
	// one failure this scoring exists to prevent.
	var p1 = [11]bool{true, false, true, true, true, false, true, false, false, false, false}
	var p2 = [11]bool{false, false, false, false, true, false, true, true, true, false, true}
	window := func(get func(int) bool, start int) bool {
		var w [11]bool
		for i := 0; i < 11; i++ {
			w[i] = get(start + i)
		}
		return w == p1 || w == p2
	}
	for a := 0; a < n; a++ {
		row := func(i int) bool { return c.Dark(i, a) }
		col := func(i int) bool { return c.Dark(a, i) }
		for _, get := range []func(int) bool{row, col} {
			for b := 0; b+11 <= n; b++ {
				if window(get, b) {
					score += 40
				}
			}
		}
	}

	// Rule 4: deviation from an even balance of dark and light.
	dark := 0
	for _, m := range c.modules {
		if m {
			dark++
		}
	}
	percent := dark * 100 / (n * n)
	dev := percent - 50
	if dev < 0 {
		dev = -dev
	}
	score += (dev / 5) * 10

	return score
}

// formatBits builds the 15-bit format information: two bits of error correction
// level, three of mask, then a BCH(15,5) check, all XORed with a fixed mask so
// an all-zero format is impossible.
func formatBits(ecLevel, mask int) int {
	// Level M is 0b00 in the format field.
	data := (ecLevel << 3) | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem <<= 1
		if rem&(1<<10) != 0 {
			rem ^= 0x537
		}
	}
	return ((data << 10) | rem) ^ 0x5412
}

// versionBits builds the 18-bit version information: six bits of version and a
// BCH(18,6) check.
func versionBits(version int) int {
	rem := version
	for i := 0; i < 12; i++ {
		rem <<= 1
		if rem&(1<<12) != 0 {
			rem ^= 0x1F25
		}
	}
	return version<<12 | rem
}
