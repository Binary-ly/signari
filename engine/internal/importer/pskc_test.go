package importer

import (
	"bytes"
	"crypto/fips140"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/mfa"
)

// Figure 6 of RFC 6030, specs/rfc6030.txt:1315-1381, whole: AES-128-CBC with HMAC-SHA1, a
// MAC key sealed in the file. Its plaintext is said in the text at :1298.
const pskcFigure6 = `<?xml version="1.0" encoding="UTF-8"?>
<KeyContainer Version="1.0"
    xmlns="urn:ietf:params:xml:ns:keyprov:pskc"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
    <EncryptionKey>
        <ds:KeyName>Pre-shared-key</ds:KeyName>
    </EncryptionKey>
    <MACMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
        <MACKey>
            <xenc:EncryptionMethod
            Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            <xenc:CipherData>
                <xenc:CipherValue>
    ESIzRFVmd4iZABEiM0RVZgKn6WjLaTC1sbeBMSvIhRejN9vJa2BOlSaMrR7I5wSX
                </xenc:CipherValue>
            </xenc:CipherData>
        </MACKey>
    </MACMethod>
    <KeyPackage>
        <DeviceInfo>
            <Manufacturer>Manufacturer</Manufacturer>
            <SerialNo>987654321</SerialNo>
        </DeviceInfo>
        <CryptoModuleInfo>
            <Id>CM_ID_001</Id>
        </CryptoModuleInfo>
        <Key Id="12345678"
            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
            <Issuer>Issuer</Issuer>
            <AlgorithmParameters>
                <ResponseFormat Length="8" Encoding="DECIMAL"/>
            </AlgorithmParameters>
            <Data>
                <Secret>
                    <EncryptedValue>
                        <xenc:EncryptionMethod
            Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
                        <xenc:CipherData>
                            <xenc:CipherValue>
    AAECAwQFBgcICQoLDA0OD+cIHItlB3Wra1DUpxVvOx2lef1VmNPCMl8jwZqIUqGv
                            </xenc:CipherValue>
                        </xenc:CipherData>
                    </EncryptedValue>
                    <ValueMAC>Su+NvtQfmvfJzF6bmQiJqoLRExc=
                    </ValueMAC>
                </Secret>
                <Counter>
                    <PlainValue>0</PlainValue>
                </Counter>
            </Data>
        </Key>
    </KeyPackage>
</KeyContainer>`

// Figure 2 of RFC 6030, with its seed made long enough to be one.
const pskcPlain = `<?xml version="1.0" encoding="UTF-8"?>
<KeyContainer Version="1.0" Id="exampleID1" xmlns="urn:ietf:params:xml:ns:keyprov:pskc">
    <KeyPackage>
        <Key Id="12345678" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
            <Issuer>Issuer-A</Issuer>
            <Data><Secret><PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
            </PlainValue></Secret></Data>
        </Key>
    </KeyPackage>
</KeyContainer>`

func TestTheRFCsSealedTokenOpens(t *testing.T) {
	key, err := hex.DecodeString("12345678901234567890123456789012")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePSKC(strings.NewReader(pskcFigure6), key)
	// The module refuses HMAC-SHA1, and what an operator should get is a sentence.
	if fips140.Enforced() {
		if err == nil || !strings.Contains(err.Error(), "fips140=only") {
			t.Errorf("under the module it answered %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	if len(got) != 1 || got[0].Serial != "987654321" || !got[0].HOTP || got[0].Params.Digits != 8 || !bytes.Equal(got[0].Seed, want) {
		t.Errorf("%+v", got)
	}
}

func TestAPlainTokenReads(t *testing.T) {
	got, err := ParsePSKC(strings.NewReader(pskcPlain), nil)
	if err != nil {
		t.Fatal(err)
	}
	// With no serial number the key's Id is what a file offers.
	if len(got) != 1 || got[0].Serial != "12345678" || string(got[0].Seed) != "12345678901234567890" {
		t.Errorf("%+v", got)
	}
}

func TestATimeBasedTokenSaysHow(t *testing.T) {
	file := `<KeyContainer Version="1.0" xmlns="urn:ietf:params:xml:ns:keyprov:pskc"><KeyPackage>
		<DeviceInfo><SerialNo>T1</SerialNo></DeviceInfo>
		<Key Id="k" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">
			<AlgorithmParameters><Suite>HMAC-SHA256</Suite><ResponseFormat Length="8" Encoding="DECIMAL"/></AlgorithmParameters>
			<Data><Secret><PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</PlainValue></Secret>
			<TimeInterval><PlainValue>60</PlainValue></TimeInterval></Data>
		</Key></KeyPackage></KeyContainer>`
	got, err := ParsePSKC(strings.NewReader(file), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := (mfa.Params{Algorithm: mfa.SHA256, Digits: 8, Period: 60 * time.Second}); got[0].HOTP || got[0].Params != want {
		t.Errorf("%+v", got[0])
	}
}

func TestWhatRefusesAFile(t *testing.T) {
	key, _ := hex.DecodeString("12345678901234567890123456789012")
	wrong, _ := hex.DecodeString("00000000000000000000000000000000")
	replace := func(file, from, to string) string {
		if !strings.Contains(file, from) {
			t.Fatalf("%q is not in the file", from)
		}
		return strings.Replace(file, from, to, 1)
	}
	for name, c := range map[string]struct {
		file string
		key  []byte
	}{
		"no key":          {pskcFigure6, nil},
		"the wrong key":   {pskcFigure6, wrong},
		"a short key":     {pskcFigure6, key[:8]},
		"a changed value": {replace(pskcFigure6, "AAECAwQFBgcICQoLDA0OD+cI", "AAECAwQFBgcICQoLDA0OD+cJ"), key},
		"a changed MAC":   {replace(pskcFigure6, "Su+NvtQfmvfJzF6bmQiJqoLRExc=", "Tu+NvtQfmvfJzF6bmQiJqoLRExc="), key},
		"no MAC method":   {replace(pskcFigure6, `<MACMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">`, `<NotMACMethod Algorithm="x">`), key},
		"another MAC":     {replace(pskcFigure6, "xmldsig#hmac-sha1", "xmldsig#hmac-md5"), key},
		"another cipher":  {replace(pskcFigure6, "xmlenc#aes128-cbc", "xmlenc#tripledes-cbc"), key},
		"version 2":       {replace(pskcPlain, `Version="1.0"`, `Version="2.0"`), nil},
		"no version":      {replace(pskcPlain, `Version="1.0"`, ``), nil},
		"another kind":    {replace(pskcPlain, "pskc:hotp", "pskc:pin"), nil},
		"not base64":      {replace(pskcPlain, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", "!!!"), nil},
		"nothing":         {`<KeyContainer Version="1.0"></KeyContainer>`, nil},
		"not XML":         {"not xml at all", nil},
		"a passphrase": {replace(pskcFigure6, "<ds:KeyName>Pre-shared-key</ds:KeyName>",
			`<DerivedKey xmlns="http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"/>`), key},
		"no secret": {replace(pskcPlain, "<Secret><PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\n            </PlainValue></Secret>", ""), nil},
	} {
		if got, err := ParsePSKC(strings.NewReader(c.file), c.key); err == nil {
			t.Errorf("%s was accepted: %+v", name, got)
		}
	}
	twice := strings.Replace(pskcPlain, "</KeyPackage>", `</KeyPackage><KeyPackage><Key Id="12345678"
		Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp"><Data><Secret><PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</PlainValue></Secret></Data></Key></KeyPackage>`, 1)
	if _, err := ParsePSKC(strings.NewReader(twice), nil); err == nil {
		t.Error("two tokens with one serial number were accepted")
	}
}
