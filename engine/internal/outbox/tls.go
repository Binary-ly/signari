package outbox

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"
)

// outboundClient builds the HTTP client used for every outbound delivery.
//
// # Why an extra certificate authority is offered at all
//
// Back-channel logout endpoints, SCIM targets and CAEP receivers are frequently
// INTERNAL services behind a private CA. Without a way to trust one, the thing
// operators actually do is disable verification — so a narrow, explicit way to
// trust the right authority is offered instead of leaving them to reach for the
// blunt one.
//
// It ADDS to the system pool rather than replacing it, so trusting an internal
// CA does not quietly stop public endpoints from verifying.
//
// SIGNARI_CA_BUNDLE is the general setting. SIGNARI_SCIM_CA_BUNDLE predates it
// and still works, because it is documented and somebody may have set it.
func outboundClient(timeout time.Duration) *http.Client {
	bundle := os.Getenv("SIGNARI_CA_BUNDLE")
	if bundle == "" {
		bundle = os.Getenv("SIGNARI_SCIM_CA_BUNDLE")
	}
	if bundle == "" {
		return &http.Client{Timeout: timeout}
	}
	pem, err := os.ReadFile(bundle)
	if err != nil {
		// Not fatal: delivery still works for anything the system pool trusts,
		// and refusing to start over a misconfigured optional setting would take
		// the whole engine down for a feature nobody may be using.
		return &http.Client{Timeout: timeout}
	}
	pool, perr := x509.SystemCertPool()
	if perr != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}
