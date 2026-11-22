package mfa

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
)

// Yubico OTP (4.27): the characters a YubiKey types when it is touched, checked here
// against the token's own AES key, so no validation service is asked and none has to
// be trusted or reachable. The layout is specs/yubico-otps-explained.txt:71-116.
//
// An OTP is the token's public ID, which it types unchanged every time, followed by
// 32 characters: one AES-128 block, sixteen bytes, in modhex. Decrypted under the
// token's key the block is
//
//	uid (6) | use counter (2, little-endian) | timestamp (3) | session counter (1) | random (2) | CRC (2)
//
// Only the holder of the key can make a block whose uid and CRC come out right, and
// the two counters only go up, so a block already accepted cannot be accepted again.

const (
	// YubicoKeySize is the token's AES-128 key.
	YubicoKeySize = 16
	// YubicoPrivateIDSize is the uid inside every block, set when the token was
	// configured; a block decrypted under the wrong key does not reproduce it
	// (specs/yubico-otps-explained.txt:96-99).
	YubicoPrivateIDSize = 6
	// yubicoTokenChars is the encrypted block in modhex.
	yubicoTokenChars = 32
	// A public ID is up to sixteen bytes.
	yubicoMaxPublicIDChars = 32
)

// modhex is hex written with the letters a keyboard puts in the same place in most
// Latin layouts, so a token typing scan codes is read the same whatever the layout
// says: 0-f in order (specs/yubico-otps-explained.txt:32-67).
const modhex = "cbdefghijklnrtuv"

// crcResidue is what the CRC of the whole block, its own CRC included, comes to when
// the block is intact (specs/yubico-otps-explained.txt:113-116).
const crcResidue = 0xf0b8

// ValidYubicoPublicID reports whether s can be a token's public ID: modhex, a whole
// number of bytes, one to sixteen of them.
func ValidYubicoPublicID(s string) bool {
	return len(s) >= 2 && len(s) <= yubicoMaxPublicIDChars && len(s)%2 == 0 && isModhex(s)
}

// SplitYubicoOTP separates a submission into the public ID it was typed with and the
// encrypted part, normalised: surrounding space trimmed and lower case, since a token
// typing with caps lock on comes out in capitals.
func SplitYubicoOTP(otp string) (publicID, token string, ok bool) {
	otp = strings.ToLower(strings.TrimSpace(otp))
	if len(otp) <= yubicoTokenChars || !isModhex(otp) {
		return "", "", false
	}
	publicID, token = otp[:len(otp)-yubicoTokenChars], otp[len(otp)-yubicoTokenChars:]
	if !ValidYubicoPublicID(publicID) {
		return "", "", false
	}
	return publicID, token, true
}

// PlausibleYubicoOTP reports whether a submission is an OTP from the token with this
// public ID. Anything else cannot be accepted for it, so a caller charges a failure
// to the token only when this is true, as Plausible is used for a code.
func PlausibleYubicoOTP(otp, publicID string) bool {
	got, _, ok := SplitYubicoOTP(otp)
	return ok && got == publicID
}

// VerifyYubicoOTP checks an OTP from the token whose public ID, key and private ID
// are given, and returns its counter: the use counter and the session counter as one
// number that every later OTP exceeds. lastUsed is the counter of the last OTP
// accepted. The caller MUST persist the returned counter, or an OTP can be replayed.
//
// An OTP that decrypts correctly but whose counter has not advanced is ErrReplay. It
// was made by the token, so it is no guess, and charging it would let anyone holding
// an old one spend the person's factor toward being disabled.
func VerifyYubicoOTP(key, privateID []byte, publicID, otp string, lastUsed int64) (int64, error) {
	if len(key) != YubicoKeySize || len(privateID) != YubicoPrivateIDSize || !ValidYubicoPublicID(publicID) {
		return 0, errors.New("mfa: a Yubico token needs a 16-byte key, a 6-byte private ID and a public ID")
	}
	gotID, token, ok := SplitYubicoOTP(otp)
	if !ok || gotID != publicID {
		return 0, ErrInvalidCode
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	var plain [16]byte
	block.Decrypt(plain[:], decodeModhex(token))

	// The CRC first: a block decrypted under another key is noise, and so is one
	// altered in transit. Then the private ID, which a block made under another key
	// with a good CRC by chance still does not reproduce.
	if crc16(plain[:]) != crcResidue || subtle.ConstantTimeCompare(plain[:6], privateID) != 1 {
		return 0, ErrInvalidCode
	}
	if c := yubicoCounter(plain); c > lastUsed {
		return c, nil
	}
	return 0, ErrReplay
}

// yubicoCounter is the use counter and session counter as one number. The use counter
// goes up at each power-up, and also when the session counter wraps from 0xff to 0
// (specs/yubico-otps-explained.txt:100-106); the session counter starts at zero with
// it and goes up at each OTP. So use<<8|session goes up at every OTP the token makes.
// The use counter is fifteen bits wide (line 104); the top bit of its field is not part
// of it.
func yubicoCounter(plain [16]byte) int64 {
	use := binary.LittleEndian.Uint16(plain[6:8]) & 0x7fff
	return int64(use)<<8 | int64(plain[11])
}

// crc16 is the ISO 13239 CRC the block carries (reflected, polynomial 0x8408, from
// 0xffff). Over the whole block, its own CRC included, an intact block gives
// crcResidue; the residue is what tests this is the right CRC, since another comes
// to some other value.
func crc16(b []byte) uint16 {
	crc := uint16(0xffff)
	for _, x := range b {
		crc ^= uint16(x)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func isModhex(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(modhex, s[i]) < 0 {
			return false
		}
	}
	return true
}

// decodeModhex decodes a string isModhex accepted, of even length.
func decodeModhex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = byte(strings.IndexByte(modhex, s[2*i])<<4 | strings.IndexByte(modhex, s[2*i+1]))
	}
	return out
}
