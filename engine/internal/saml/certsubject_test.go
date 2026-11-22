package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Each key's certificate has a name of its own (2.51). Metadata publishes the
// active, next and passive certificates together, and when all three were
// `O=Signari, CN=<host>` a provider that trusted them all and looked the signer
// up by name took whichever it had loaded last: xmlsec1 verified a response
// with the certificates in one order and answered KEY-NOT-FOUND in another.
func TestAProviderTrustingEveryPublishedCertificateVerifiesInAnyOrder(t *testing.T) {
	bin, err := exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("xmlsec1 not installed; it is the independent check")
	}
	dir := t.TempDir()
	var signer *rsa.PrivateKey
	var signerDER []byte
	var paths []string
	var subjects [][]byte
	for i := 0; i < 3; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, _, err := selfSign("https://auth.example.com", fmt.Sprintf("kid-%d", i), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subjects {
			if bytes.Equal(s, cert.RawSubject) {
				t.Fatalf("two keys' certificates are both named %s", cert.Subject)
			}
		}
		subjects = append(subjects, cert.RawSubject)
		p := filepath.Join(dir, fmt.Sprintf("cert-%d.pem", i))
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		if i == 0 {
			signer, signerDER = key, der
		}
	}

	in := testInput()
	in.SignResponse = true
	out, err := BuildResponse(in, "kid-0", signer, signerDER)
	if err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(dir, "response.xml")
	if err := os.WriteFile(docPath, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		for _, node := range []string{responseSignature, assertionSignature} {
			args := []string{"--verify"}
			for _, i := range order {
				args = append(args, "--trusted-pem", paths[i])
			}
			args = append(args,
				"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
				"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
				"--node-xpath", node, docPath)
			if combined, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
				t.Errorf("trusting the three certificates in order %v, xmlsec1 rejected %s:\n%s",
					order, node, combined)
			}
		}
	}
}
