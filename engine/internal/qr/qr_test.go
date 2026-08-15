package qr

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A realistic enrolment URI, which is the only input this package exists for.
const enrolURI = "otpauth://totp/Signari:alice@example.test?secret=" +
	"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Signari&algorithm=SHA1&digits=6&period=30"

func python(t *testing.T, script string, args ...string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "script.py")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("python3", append([]string{path}, args...)...).CombinedOutput()
	if err != nil {
		t.Logf("python3 unavailable or failed, skipping: %v\n%s", err, out)
		return "", false
	}
	return string(out), true
}

// matrixString renders the symbol as rows of 0/1 for comparison.
func (c *Code) matrixString() string {
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Dark(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// encodeWithMask builds a symbol with the mask fixed, so placement can be
// compared without mask SELECTION getting in the way.
func encodeWithMask(data []byte, mask int) *Code {
	version, spec, err := pickVersion(len(data))
	if err != nil {
		panic(err)
	}
	codewords := buildCodewords(data, version, spec)
	size := 17 + 4*version
	c := &Code{Size: size, modules: make([]bool, size*size)}
	reserved := make([]bool, size*size)
	c.placeFunctionPatterns(reserved)
	c.placeFormatInfo(mask, reserved)
	if version >= 7 {
		c.placeVersionInfo(version, reserved)
	}
	c.placeData(codewords, reserved, mask)
	return c
}

// TestMatchesReferenceEncoder compares our output module-for-module against
// Python's `qrcode`, an independent implementation of the same standard.
//
// This is the check that matters. Everything here -- Galois field arithmetic,
// block interleaving, the zigzag walk, format bit order -- is the kind of code
// that produces a plausible-looking square while being wrong, and reading it back
// does not tell you which. Reversed format bits produced a symbol with flawless
// finder patterns that no scanner on earth could read.
//
// Two things are pinned so the comparison means something:
//
//   - The reference is forced into single-segment BYTE mode. Left to itself it
//     switches to alphanumeric for uppercase input, which is a denser and equally
//     valid encoding of different bits -- comparing against it would report a
//     difference that is not an error.
//   - The MASK is fixed on both sides. Selection is compared separately in
//     TestPenaltyMatchesTheReferenceScorer, because the two implementations
//     legitimately disagree there (see that test).
func TestMatchesReferenceEncoder(t *testing.T) {
	const script = `
import sys, qrcode
from qrcode.util import QRData, MODE_8BIT_BYTE
q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0,
                  mask_pattern=int(sys.argv[2]))
q.add_data(QRData(sys.argv[1].encode(), mode=MODE_8BIT_BYTE))
q.make(fit=True)
for row in q.get_matrix():
    print(''.join('1' if v else '0' for v in row))
`
	inputs := []string{
		"otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP",
		enrolURI,
		strings.Repeat("x", 40),
		strings.Repeat("y", 100),
		strings.Repeat("z", 200),
		strings.Repeat("w", 280), // version 12, the ceiling
	}
	for _, in := range inputs {
		for mask := 0; mask < 8; mask++ {
			out, ok := python(t, script, in, fmt.Sprint(mask))
			if !ok {
				t.Skip("python3 with the qrcode module is not available")
			}
			want := strings.TrimSpace(out) + "\n"
			got := encodeWithMask([]byte(in), mask).matrixString()
			if got == want {
				continue
			}
			t.Errorf("%d bytes, mask %d: our symbol differs from the reference encoder",
				len(in), mask)
			// The first differing row localises the failure: row 0 is function
			// patterns, row 8 is format information, anything else is data.
			gr, wr := strings.Split(got, "\n"), strings.Split(want, "\n")
			for i := range gr {
				if i < len(wr) && gr[i] != wr[i] {
					t.Errorf("  first difference at row %d:\n    ours: %s\n    ref : %s",
						i, gr[i], wr[i])
					break
				}
			}
			break
		}
	}
}

// TestPenaltyMatchesTheReferenceScorer.
//
// Mask choice is not cosmetic: it is what stops long runs and finder-like shapes
// forming in the data, and a badly chosen mask is a valid symbol that is harder
// to scan. The scores must therefore be right, and "right" is checkable because
// the reference exposes its scorer.
//
// Note this compares SCORES, not the chosen mask. Python's library scores mask 2
// lowest for some inputs and then returns mask 5 anyway -- a quirk in its
// selection, not its scoring. The standard says the lowest penalty wins, which is
// what this package does.
func TestPenaltyMatchesTheReferenceScorer(t *testing.T) {
	const script = `
import sys, qrcode, qrcode.util
from qrcode.util import QRData, MODE_8BIT_BYTE
for mp in range(8):
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0,
                      mask_pattern=mp)
    q.add_data(QRData(sys.argv[1].encode(), mode=MODE_8BIT_BYTE))
    q.make(fit=True)
    print(qrcode.util.lost_point(q.get_matrix()))
`
	for _, in := range []string{
		strings.Repeat("a", 15),
		strings.Repeat("b", 100),
		enrolURI,
	} {
		out, ok := python(t, script, in)
		if !ok {
			t.Skip("python3 with the qrcode module is not available")
		}
		want := strings.Fields(out)
		if len(want) != 8 {
			t.Fatalf("expected 8 scores, got %q", out)
		}
		for mask := 0; mask < 8; mask++ {
			got := encodeWithMask([]byte(in), mask).penalty()
			if fmt.Sprint(got) != want[mask] {
				t.Errorf("%d bytes, mask %d: penalty %d, reference says %s",
					len(in), mask, got, want[mask])
			}
		}
	}
}

// TestDecodesWithOpenCV renders the symbol and reads it back with a real
// detector.
//
// Matching a reference encoder proves the modules agree. This proves the thing an
// operator actually cares about: that a camera pointed at it recovers the URI.
func TestDecodesWithOpenCV(t *testing.T) {
	c, err := Encode([]byte(enrolURI))
	if err != nil {
		t.Fatal(err)
	}

	// Rasterise at a size a phone camera would cope with, quiet zone included.
	const scale, quiet = 8, 4
	dim := (c.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, dim, dim))
	for i := range img.Pix {
		img.Pix[i] = 0xFF
	}
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !c.Dark(x, y) {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{Y: 0})
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "qr.png")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	const script = `
import sys, cv2
img = cv2.imread(sys.argv[1])
data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
print(data)
`
	out, ok := python(t, script, path)
	if !ok {
		t.Skip("python3 with OpenCV is not available")
	}
	if got := strings.TrimSpace(out); got != enrolURI {
		t.Errorf("the detector read back something else:\n  got:  %q\n  want: %q", got, enrolURI)
	}
}

// TestVersionGrowsWithInput. Silently overflowing into a version that cannot
// hold the data would corrupt the payload rather than fail.
func TestVersionGrowsWithInput(t *testing.T) {
	prev := 0
	for _, n := range []int{10, 40, 80, 150, 250} {
		c, err := Encode(bytes.Repeat([]byte("a"), n))
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if c.Size < prev {
			t.Errorf("%d bytes produced a smaller symbol (%d) than the previous input (%d)",
				n, c.Size, prev)
		}
		prev = c.Size
	}
}

// TestOversizedInputIsRefused. Refusing beats truncating: a QR code that decodes
// to half an enrolment URI is worse than no QR code, because the user will scan
// it and get a broken credential.
func TestOversizedInputIsRefused(t *testing.T) {
	if _, err := Encode(bytes.Repeat([]byte("a"), 400)); err == nil {
		t.Fatal("400 bytes was accepted; version 12 at level M holds 288")
	}
}

// TestFinderPatternsArePresent -- the cheapest structural check, and the one that
// catches a completely broken placement pass.
func TestFinderPatternsArePresent(t *testing.T) {
	c, err := Encode([]byte(enrolURI))
	if err != nil {
		t.Fatal(err)
	}
	n := c.Size
	for _, o := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		for i := 0; i < 7; i++ {
			if !c.Dark(o[0]+i, o[1]) || !c.Dark(o[0]+i, o[1]+6) {
				t.Fatalf("finder at (%d,%d) has a broken outer ring", o[0], o[1])
			}
		}
		if c.Dark(o[0]+1, o[1]+1) {
			t.Errorf("finder at (%d,%d) has no light separator ring", o[0], o[1])
		}
		if !c.Dark(o[0]+3, o[1]+3) {
			t.Errorf("finder at (%d,%d) has no dark centre", o[0], o[1])
		}
	}
	// The fourth corner must NOT have one; that absence is what gives a detector
	// the symbol's orientation. Checked by the shape a finder actually has -- a
	// solid 7-module edge -- rather than by sampling three modules, which any
	// data pattern can satisfy by chance.
	solid := true
	for i := 0; i < 7; i++ {
		if !c.Dark(n-7+i, n-7) {
			solid = false
			break
		}
	}
	if solid {
		t.Error("the fourth corner has a solid seven-module edge, which is what a " +
			"finder pattern looks like; orientation detection depends on its absence")
	}
}

func TestSVGIsSelfContained(t *testing.T) {
	c, err := Encode([]byte(enrolURI))
	if err != nil {
		t.Fatal(err)
	}
	svg := c.SVG(4, 4)

	// The enrolment page sets a Content-Security-Policy; anything fetched would
	// be blocked and the user would see an empty box.
	// The xmlns declaration is not a fetch, so it is excluded deliberately --
	// checking for "http://" alone would fail on every valid SVG ever written.
	body := strings.SplitN(svg, ">", 2)[1]
	for _, forbidden := range []string{"http://", "https://", "<image", "<script", "url("} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the SVG references %q, which the page's CSP would block", forbidden)
		}
	}
	// An explicit white background: on a dark theme a transparent one puts dark
	// modules on dark and the symbol does not scan.
	if !strings.Contains(svg, `fill="#ffffff"`) {
		t.Error("no opaque background; the symbol would be unreadable on a dark theme")
	}
	if !strings.Contains(svg, "aria-label") {
		t.Error("no accessible label")
	}
}

// TestGaloisFieldRoundTrip checks the arithmetic underneath everything else.
func TestGaloisFieldRoundTrip(t *testing.T) {
	for a := 1; a < 256; a++ {
		for _, b := range []int{1, 2, 3, 127, 255} {
			p := gfMul(byte(a), byte(b))
			if p == 0 {
				t.Fatalf("gfMul(%d,%d) = 0; the field has no zero divisors", a, b)
			}
		}
	}
	if gfMul(0, 5) != 0 || gfMul(5, 0) != 0 {
		t.Error("multiplication by zero is not zero")
	}
}

// TestFormatBitsMatchTheStandard pins the published values. These are what tell
// a decoder which mask was used; wrong bits make the whole symbol unreadable
// however perfect the data is.
func TestFormatBitsMatchTheStandard(t *testing.T) {
	// Level M, masks 0-7, from ISO/IEC 18004 Annex C.
	want := []int{
		0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
	}
	for mask, w := range want {
		if got := formatBits(ecLevelM, mask); got != w {
			t.Errorf("formatBits(M, %d) = %#x, want %#x", mask, got, w)
		}
	}
}

// TestVersionBitsMatchTheStandard, likewise, for versions 7 and up.
func TestVersionBitsMatchTheStandard(t *testing.T) {
	want := map[int]int{7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3, 12: 0x0C762}
	for v, w := range want {
		if got := versionBits(v); got != w {
			t.Errorf("versionBits(%d) = %#x, want %#x", v, got, w)
		}
	}
}

func TestReedSolomonKnownAnswer(t *testing.T) {
	// The worked example from the standard's tutorial material: this data with
	// 10 EC codewords produces this remainder.
	data := []byte{0x40, 0xD2, 0x75, 0x47, 0x76, 0x17, 0x32, 0x06,
		0x27, 0x26, 0x96, 0xC6, 0xC6, 0x96, 0x70, 0xEC}
	want := []byte{0xBC, 0x2A, 0x90, 0x13, 0x6B, 0xAF, 0xEF, 0xFD, 0x4B, 0xE0}
	got := reedSolomon(data, 10)
	if !bytes.Equal(got, want) {
		t.Errorf("reedSolomon mismatch\n  got:  %s\n  want: %s", hexOf(got), hexOf(want))
	}
}

func hexOf(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, " ")
}

// TestSVGContainsNothingButGeneratedMarkup.
//
// The enrolment page inserts this with template.HTML, which turns off escaping.
// That is only safe while the SVG is built entirely from integers and literals,
// so the property is asserted here rather than argued in a comment: hostile bytes
// go in, and nothing resembling them comes out.
func TestSVGContainsNothingButGeneratedMarkup(t *testing.T) {
	hostile := `</svg><script>alert(1)</script><svg onload="alert(2)" a='b"c'`
	c, err := Encode([]byte(hostile))
	if err != nil {
		t.Fatal(err)
	}
	svg := c.SVG(4, 4)

	// Exactly four tags, whatever the input: <svg>, <rect/>, <path/>, </svg>.
	// Any injected markup would raise the bracket count, so this is a complete
	// check rather than a search for known-bad strings.
	if got := strings.Count(svg, "<"); got != 4 {
		t.Errorf("the SVG has %d opening brackets, want exactly 4 "+
			"(svg, rect, path, /svg) -- input reached the markup", got)
	}
	if got := strings.Count(svg, ">"); got != 4 {
		t.Errorf("the SVG has %d closing brackets, want exactly 4", got)
	}
	for _, bad := range []string{"script", "onload", "alert", "javascript:"} {
		if strings.Contains(strings.ToLower(svg), bad) {
			t.Errorf("hostile input reached the output: %q appears in the SVG", bad)
		}
	}
	// And it still encodes the payload rather than dropping it.
	if c.Size < 21 {
		t.Error("no symbol was produced")
	}
}
