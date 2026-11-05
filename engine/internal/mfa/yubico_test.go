package mfa

import (
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Made by the reference implementation, libyubikey 1.13's ykgenerate, from this key
// and private ID, and read back by its ykparse. Each is the 32 encrypted characters,
// with the use counter (top bit caps lock), timestamp and session counter it was made
// with, and the counter this package must read from it: use<<8 | session.
var (
	yubicoTestKey, _       = hex.DecodeString("47077bb37e5298413989c9ef9fcb1dad")
	yubicoTestPrivateID, _ = hex.DecodeString("aa994855e455")
)

// The public ID is the one in specs/yubico-otps-explained.txt:23-25; any token's will do.
const yubicoTestPublicID = "cccjgjgkhcbb"

var yubicoVectors = []struct {
	token   string
	args    string // ykgenerate's counter, timestamp low, high, session
	counter int64
}{
	{"hfbkfjghgbjibhlvjfibfvujblhgbfnf", "0001 1234 56 00", 0x0100},
	{"dvhtenbcidccjcbvrjtheicebfleckuh", "0001 1239 56 01", 0x0101},
	{"gfbhkgrbjdghehdgvclijvekcidkdgrk", "0002 0a00 11 00", 0x0200},
	// Typed with caps lock on: the top bit of the use counter field, not part of it.
	{"knjjvhlgcvlcilbjetrnvnbdvujugukh", "8003 0b00 11 05", 0x0305},
	{"ilbuetglktkifbcjguughuufgrlijnkn", "7fff ffff ff ff", 0x7fffff},
}

func TestAYubicoOTPFromTheReferenceImplementationIsAccepted(t *testing.T) {
	for _, v := range yubicoVectors {
		got, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID,
			yubicoTestPublicID+v.token, 0)
		if err != nil || got != v.counter {
			t.Errorf("ykgenerate %s: counter %#x, %v; want %#x", v.args, got, err, v.counter)
		}
	}
	// As typed: a newline from the token's Enter, and capitals from caps lock.
	otp := "  " + strings.ToUpper(yubicoTestPublicID+yubicoVectors[3].token) + "\r\n"
	if got, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, otp, 0); err != nil ||
		got != 0x0305 {
		t.Errorf("typed with caps lock and Enter: %#x, %v", got, err)
	}
}

// Each OTP the token makes counts higher than the one before, so the counter of the
// last accepted is all that has to be kept for none to be accepted twice.
func TestAYubicoOTPIsAcceptedOnce(t *testing.T) {
	var last int64
	for i, v := range yubicoVectors {
		otp := yubicoTestPublicID + v.token
		got, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, otp, last)
		if err != nil {
			t.Fatalf("vector %d after %#x: %v", i, last, err)
		}
		if _, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, otp, got); !errors.Is(err, ErrReplay) {
			t.Errorf("vector %d a second time: %v, want ErrReplay", i, err)
		}
		if i > 0 {
			earlier := yubicoTestPublicID + yubicoVectors[i-1].token
			if _, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, earlier, got); !errors.Is(err, ErrReplay) {
				t.Errorf("vector %d after %d: %v, want ErrReplay", i-1, i, err)
			}
		}
		last = got
	}
}

func TestAYubicoOTPThatIsNotTheTokensIsRefused(t *testing.T) {
	good := yubicoTestPublicID + yubicoVectors[0].token
	otherKey, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	otherID, _ := hex.DecodeString("aa994855e456")
	flipped := []byte(good)
	flipped[len(flipped)-1] = 'c' // the last character was 'f'
	cases := map[string]struct {
		key, id  []byte
		publicID string
		otp      string
	}{
		"another key":                   {otherKey, yubicoTestPrivateID, yubicoTestPublicID, good},
		"another private ID":            {yubicoTestKey, otherID, yubicoTestPublicID, good},
		"another token's public ID":     {yubicoTestKey, yubicoTestPrivateID, "cccjgjgkhcbc", good},
		"one character changed":         {yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, string(flipped)},
		"without its public ID":         {yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, yubicoVectors[0].token},
		"a character modhex has not":    {yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, "a" + good[1:]},
		"half a byte of public ID more": {yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, "c" + good},
		"a six-digit code":              {yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID, "287082"},
	}
	for name, c := range cases {
		if _, err := VerifyYubicoOTP(c.key, c.id, c.publicID, c.otp, 0); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("%s: %v, want ErrInvalidCode", name, err)
		}
	}
}

// Only a submission that has this token's public ID is a guess at it, and charged.
func TestOnlyAYubicoOTPWithTheTokensPublicIDIsAGuessAtIt(t *testing.T) {
	for otp, want := range map[string]bool{
		yubicoTestPublicID + yubicoVectors[0].token:                      true,
		yubicoTestPublicID + strings.Repeat("c", 32):                     true,
		" " + strings.ToUpper(yubicoTestPublicID+yubicoVectors[1].token): true,
		"cccjgjgkhcbc" + yubicoVectors[0].token:                          false,
		yubicoVectors[0].token:                                           false,
		"287082":                                                         false,
		"ABCD-EFGH-JKMN-PQRS-TUVW":                                       false,
	} {
		if got := PlausibleYubicoOTP(otp, yubicoTestPublicID); got != want {
			t.Errorf("PlausibleYubicoOTP(%q) = %v, want %v", otp, got, want)
		}
	}
}

// The residue is what says this is the token's CRC: computed over a block with its CRC
// appended, little-endian and complemented, it comes to 0xf0b8 whatever the block.
func TestTheCRCHasTheResidueTheSpecificationGives(t *testing.T) {
	for _, s := range []string{"", "a", "123456789", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"} {
		c := ^crc16([]byte(s))
		if got := crc16(append([]byte(s), byte(c), byte(c>>8))); got != crcResidue {
			t.Errorf("over %q: residue %#04x, want %#04x", s, got, crcResidue)
		}
	}
}

// A Yubico OTP is one AES-128 block, which the module runs, so a FIPS 140-only
// deployment can take them where it cannot take a SHA-1 code.
func TestAYubicoOTPIsCheckedUnderFIPSOnly(t *testing.T) {
	if !fips140.Enforced() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAYubicoOTPIsCheckedUnderFIPSOnly$", "-test.count=1")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}
	if got, err := VerifyYubicoOTP(yubicoTestKey, yubicoTestPrivateID, yubicoTestPublicID,
		yubicoTestPublicID+yubicoVectors[2].token, 0); err != nil || got != 0x0200 {
		t.Errorf("under fips140=only: %#x, %v", got, err)
	}
}

func TestAYubicoPublicIDIsWholeBytesOfModhex(t *testing.T) {
	for id, want := range map[string]bool{
		"cccjgjgkhcbb": true, "cb": true, strings.Repeat("v", 32): true,
		"": false, "c": false, "cccjgjgkhcb": false, strings.Repeat("v", 34): false, "cccjgjgkhcba": false,
	} {
		if got := ValidYubicoPublicID(id); got != want {
			t.Errorf("ValidYubicoPublicID(%q) = %v, want %v", id, got, want)
		}
	}
}
