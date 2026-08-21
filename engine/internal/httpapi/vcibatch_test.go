package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/oid4vci"
)

// OID4VCI 1.0 (Final, 16 September 2025) §12.2.4:
//
//	batch_credential_issuance: "Object containing information about the Credential
//	Issuer's support for issuance of multiple Credentials in a batch in the
//	Credential Endpoint. The presence of this parameter means that the issuer
//	supports more than one key proof in the proofs parameter in the Credential
//	Request..."
//
//	batch_size: "REQUIRED. Integer value specifying the maximum array size for the
//	proofs parameter in a Credential Request. It MUST be 2 or greater."
//
// We accept up to MaxProofsPerRequest proofs and advertised nothing, so a
// conformant wallet — which reads the metadata and finds no batch support — would
// have sent one proof per request forever. A wallet batches keys precisely for
// unlinkability, which is the case this parameter exists to enable.
func TestBatchCredentialIssuanceIsAdvertised(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	doc := credentialIssuerMetadata(t, f)

	batch, ok := doc["batch_credential_issuance"].(map[string]any)
	if !ok {
		t.Fatalf("no batch_credential_issuance in the issuer metadata; this issuer "+
			"accepts %d key proofs and its own metadata says it accepts one: %v",
			oid4vci.MaxProofsPerRequest, doc)
	}
	size, ok := batch["batch_size"].(float64)
	if !ok {
		t.Fatalf("batch_size is missing or not a number: %v", batch)
	}
	if size < 2 {
		t.Errorf("batch_size = %v; §12.2.4 says it MUST be 2 or greater", size)
	}
	// The advertised number must be the enforced one. An issuer that advertises a
	// limit it does not honour sends the wallet into an error it was told would
	// not happen.
	if int(size) != oid4vci.MaxProofsPerRequest {
		t.Errorf("batch_size advertises %v but the endpoint enforces %d",
			size, oid4vci.MaxProofsPerRequest)
	}
}

// The REQUIRED top-level parameters of §12.2.4, checked against the served
// document rather than against the code that builds it.
func TestCredentialIssuerMetadataCarriesTheRequiredParameters(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	doc := credentialIssuerMetadata(t, f)

	// "credential_issuer: REQUIRED... The value MUST be identical to the
	// Credential Issuer's identifier value into which the well-known URI string
	// was inserted to create the URL used to retrieve the metadata."
	//
	// The same mix-up defence as AuthZEN's policy_decision_point and SSF's
	// issuer: a wallet compares this against the identifier it built the URL
	// from and refuses the document when they differ.
	if doc["credential_issuer"] != f.srv.cfg.Issuer {
		t.Errorf("credential_issuer = %v, want %q", doc["credential_issuer"], f.srv.cfg.Issuer)
	}
	for _, k := range []string{"credential_endpoint", "credential_configurations_supported"} {
		if doc[k] == nil {
			t.Errorf("%s is missing; §12.2.4 makes it REQUIRED", k)
		}
	}
	// §7: "A Credential Issuer that requires c_nonce values to be incorporated
	// into proofs in the Credential Request MUST offer a Nonce Endpoint." We do
	// require them, so the endpoint must be both offered and discoverable.
	if doc["nonce_endpoint"] == nil {
		t.Error("nonce_endpoint is missing, and this issuer requires a c_nonce in " +
			"every proof — so a wallet cannot obtain one it is obliged to send")
	}
}

func credentialIssuerMetadata(t *testing.T, f *tokenFixture) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("credential issuer metadata gave %d: %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	return doc
}

// OID4VCI 1.0 §12.2.4, `cryptographic_binding_methods_supported`:
//
//	"It MUST be present when Cryptographic Key Binding is required for a
//	Credential, and omitted otherwise. If absent, Cryptographic Key Binding is
//	not required for this credential."
//
// Found on a second pass over the specification — 509 normative uses across 84
// sections, extracted and checked rather than sampled. The first pass read §4,
// §7, §8 and the top-level parameters of §12.2.4; this requirement is in the
// per-configuration half of the same section.
//
// `Issuer.Issue` refuses a request with no holder key, so binding is required
// unconditionally. The parameter was absent, and absence has a defined meaning
// here: it states that binding is NOT required. The metadata said the opposite
// of what the endpoint enforces.
func TestKeyBindingIsAdvertisedBecauseItIsRequired(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)

	doc := credentialIssuerMetadata(t, f)
	configs, ok := doc["credential_configurations_supported"].(map[string]any)
	if !ok || len(configs) == 0 {
		t.Fatalf("no credential_configurations_supported: %v", doc)
	}

	for id, raw := range configs {
		cfg, _ := raw.(map[string]any)
		methods, present := cfg["cryptographic_binding_methods_supported"]
		if !present {
			t.Errorf("configuration %q does not advertise "+
				"cryptographic_binding_methods_supported. Its absence tells a wallet "+
				"that key binding is not required, and this issuer refuses every "+
				"request that does not carry a holder key", id)
			continue
		}
		list, _ := methods.([]any)
		if len(list) == 0 {
			t.Errorf("configuration %q advertises an empty binding-method list; "+
				"§12.2.4 requires a non-empty array", id)
			continue
		}
		var found bool
		for _, m := range list {
			if m == "jwk" {
				found = true
			}
		}
		if !found {
			// The credential carries `cnf: {"jwk": ...}`, so `jwk` is the
			// representation a wallet must present.
			t.Errorf("configuration %q advertises %v, which does not include the "+
				"representation this issuer actually binds to", id, list)
		}
	}
}
