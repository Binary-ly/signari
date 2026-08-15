package posture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func cert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func request(remote string, certs []*x509.Certificate, headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://idp.test/", nil)
	r.RemoteAddr = remote
	if certs != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func mustNets(t *testing.T, spec string) []*net.IPNet {
	t.Helper()
	n, err := ParseNetworks(spec)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDeviceCertificateEstablishesManaged. The strong source: the private key
// lives on the device and cannot be copied into a request by somebody who knows
// a header name.
func TestDeviceCertificateEstablishesManaged(t *testing.T) {
	ca, caKey := cert(t, "Device CA", nil, nil, true)
	device, _ := cert(t, "laptop-42", ca, caKey, false)
	stranger, _ := cert(t, "laptop-42", nil, nil, false) // same name, self-signed

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	c := &Config{DeviceCAs: roots}

	st := c.Evaluate(request("1.2.3.4:1", []*x509.Certificate{device}, nil))
	if !st.Managed || st.Source != "device-certificate" {
		t.Fatalf("a device certificate did not establish management: %+v", st)
	}
	// A certificate is not a compliance report. Saying otherwise would let a
	// stolen managed laptop satisfy a rule meant to check its state.
	if st.Compliant {
		t.Error("a certificate alone was treated as a compliance attestation")
	}

	// Same common name, signed by nobody: proves nothing.
	st = c.Evaluate(request("1.2.3.4:1", []*x509.Certificate{stranger}, nil))
	if st.Managed {
		t.Error("a self-signed certificate with the right name established management")
	}
	// And it is "none", not a failure: an unmanaged personal device is an
	// ordinary request, not an error.
	if st.Source != "none" {
		t.Errorf("source = %q, want none", st.Source)
	}
}

// TestHeadersAreIgnoredFromUntrustedSources is the one that matters.
//
// Accepting a posture header from anywhere turns device trust into "send this
// header", which is worse than no device trust: the policy reads as enforced and
// nobody questions it again.
func TestHeadersAreIgnoredFromUntrustedSources(t *testing.T) {
	c := &Config{
		TrustedProxies:  mustNets(t, "10.0.0.0/8"),
		ManagedHeader:   "X-Device-Managed",
		CompliantHeader: "X-Device-Compliant",
	}
	headers := map[string]string{
		"X-Device-Managed":   "true",
		"X-Device-Compliant": "true",
	}

	// From the proxy: believed.
	st := c.Evaluate(request("10.1.2.3:5000", nil, headers))
	if !st.Managed || !st.Compliant || st.Source != "trusted-proxy" {
		t.Fatalf("the trusted proxy was not believed: %+v", st)
	}

	// From anywhere else: ignored entirely.
	st = c.Evaluate(request("203.0.113.9:5000", nil, headers))
	if st.Managed || st.Compliant {
		t.Fatal("a posture header from an untrusted address was believed")
	}
	if st.Source != "none" {
		t.Errorf("source = %q; an untrusted assertion must look like no evidence", st.Source)
	}
}

// TestNoTrustedProxiesMeansHeadersAreDead. The allow-list is mandatory, not a
// refinement: with none configured the header source is off.
func TestNoTrustedProxiesMeansHeadersAreDead(t *testing.T) {
	c := &Config{ManagedHeader: "X-Device-Managed"}
	st := c.Evaluate(request("10.1.2.3:1", nil, map[string]string{"X-Device-Managed": "true"}))
	if st.Managed {
		t.Error("a header was believed with no trusted proxies configured")
	}
}

// TestFalseIsNotTrue. Treating any non-empty value as true would make
// `X-Device-Managed: false` mean managed -- a bug that survives review because
// the header is present and the policy passes.
func TestFalseIsNotTrue(t *testing.T) {
	c := &Config{
		TrustedProxies: mustNets(t, "10.0.0.0/8"),
		ManagedHeader:  "X-Device-Managed",
	}
	for _, v := range []string{"false", "0", "no", "unmanaged", "", "maybe"} {
		st := c.Evaluate(request("10.0.0.1:1", nil, map[string]string{"X-Device-Managed": v}))
		if st.Managed {
			t.Errorf("header value %q was read as managed", v)
		}
	}
	for _, v := range []string{"true", "1", "yes", "TRUE", " managed "} {
		st := c.Evaluate(request("10.0.0.1:1", nil, map[string]string{"X-Device-Managed": v}))
		if !st.Managed {
			t.Errorf("header value %q was not read as managed", v)
		}
	}
}

// TestComplianceRequiresManagement. A proxy claiming an unmanaged device is
// compliant is claiming something it cannot know.
func TestComplianceRequiresManagement(t *testing.T) {
	c := &Config{
		TrustedProxies:  mustNets(t, "10.0.0.0/8"),
		ManagedHeader:   "X-Device-Managed",
		CompliantHeader: "X-Device-Compliant",
	}
	st := c.Evaluate(request("10.0.0.1:1", nil, map[string]string{
		"X-Device-Managed":   "false",
		"X-Device-Compliant": "true",
	}))
	if st.Compliant {
		t.Error("an unmanaged device was reported compliant")
	}
}

func TestCertificateBeatsHeader(t *testing.T) {
	ca, caKey := cert(t, "Device CA", nil, nil, true)
	device, _ := cert(t, "laptop", ca, caKey, false)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	c := &Config{
		DeviceCAs:      roots,
		TrustedProxies: mustNets(t, "10.0.0.0/8"),
		ManagedHeader:  "X-Device-Managed",
	}
	st := c.Evaluate(request("10.0.0.1:1", []*x509.Certificate{device},
		map[string]string{"X-Device-Managed": "false"}))
	if st.Source != "device-certificate" || !st.Managed {
		t.Errorf("a header overrode cryptographic evidence: %+v", st)
	}
}

func TestParseNetworksRefusesEverything(t *testing.T) {
	if _, err := ParseNetworks("0.0.0.0/0"); err == nil {
		t.Error("trusting the whole internet to assert its own posture was accepted")
	}
	if _, err := ParseNetworks("not-a-cidr"); err == nil {
		t.Error("garbage was accepted")
	}
	n, err := ParseNetworks("10.0.0.0/8, 192.168.0.0/16")
	if err != nil || len(n) != 2 {
		t.Errorf("ParseNetworks = %v, %v", n, err)
	}
}

func TestNilConfigIsSafe(t *testing.T) {
	var c *Config
	st := c.Evaluate(request("1.2.3.4:1", nil, nil))
	if st.Managed || st.Compliant || st.Source != "none" {
		t.Errorf("a nil config produced %+v", st)
	}
}
