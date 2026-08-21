package outbox

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"time"

	"signari.dev/engine/internal/safedial"
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
// AllowPrivateDelivery is the environment variable that permits delivery to
// private, loopback and link-local addresses.
//
// # Why this exists, and why it is off by default
//
// A `backchannel_logout_uri` is chosen by the CLIENT, at registration. A webhook
// subscription is chosen by an OPERATOR. Webhook delivery has gone through
// `safedial` since it was written -- at save time and again in the dialler -- and
// back-channel logout delivery went through a plain `http.Client`.
//
// So the LESS trusted of the two destinations had no address check at all. A
// client registering `http://169.254.169.254/latest/meta-data/` would have had a
// signed logout token POSTed there every time one of its users signed out: a
// repeatable request into the private network, from inside the trust boundary,
// triggered by an ordinary user action.
//
// The reason it was not guarded is real and is written in the comment below:
// back-channel logout endpoints are frequently internal services. Guarding them
// by default breaks those deployments, and not guarding them leaves the hole.
// So it is guarded, and an operator whose relying parties are genuinely internal
// says so explicitly.
//
// Naming the variable rather than inferring it from the CA bundle is deliberate:
// trusting an internal certificate authority and permitting requests into the
// private network are two different decisions, and a deployment can want the
// first without the second.
const AllowPrivateDelivery = "SIGNARI_ALLOW_PRIVATE_DELIVERY"

// privateDeliveryAllowed reports whether the operator has opted out of the
// address check.
func privateDeliveryAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(AllowPrivateDelivery)))
	return v == "1" || v == "true" || v == "yes"
}

func outboundClient(timeout time.Duration) *http.Client {
	// The dialler decides which addresses may be reached; the TLS config decides
	// which certificates are trusted. They are independent, so they are built
	// independently and then combined.
	var transport *http.Transport
	if privateDeliveryAllowed() {
		transport = &http.Transport{}
	} else {
		transport = safedial.Transport()
	}

	bundle := os.Getenv("SIGNARI_CA_BUNDLE")
	if bundle == "" {
		bundle = os.Getenv("SIGNARI_SCIM_CA_BUNDLE")
	}
	if bundle != "" {
		if pem, err := os.ReadFile(bundle); err == nil {
			pool, perr := x509.SystemCertPool()
			if perr != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			// A bundle that does not parse is ignored rather than fatal: delivery
			// still works for anything the system pool trusts, and refusing to
			// start over a misconfigured optional setting would take the whole
			// engine down for a feature nobody may be using.
			if pool.AppendCertsFromPEM(pem) {
				transport.TLSClientConfig = &tls.Config{
					RootCAs: pool, MinVersion: tls.VersionTLS12,
				}
			}
		}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
