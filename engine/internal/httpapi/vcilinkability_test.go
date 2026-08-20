package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// RFC 9901 §10.1, "Unlinkability", is the section batch issuance exists to
// serve, and it is the one the OID4VCI review never opened -- that pass was
// reading OID4VCI §8 and §12, where the batch endpoint is defined, not SD-JWT's
// privacy considerations, where the rules about what may go in one are.
//
//	"New Key Binding keys and salts MUST be used for each credential in the batch
//	to ensure that the Verifiers cannot link the credentials using these values.
//	Likewise, claims carrying time information, like iat, exp, and nbf, MUST
//	either be randomized within a time period considered appropriate... or
//	rounded."
//
// The salts were already fresh and the holder keys come from the wallet. The
// time claims were `time.Now().Unix()`, read separately for each credential in
// the loop -- so every credential in a batch carried the same second-precision
// number, and two verifiers comparing two credentials would match on it and
// re-identify the holder. Everything else in the batch was unlinkable and this
// one field gave it away.
func TestABatchOfCredentialsCarriesNoLinkableTimestamp(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	// Three distinct holder keys, as a wallet batching for unlinkability sends.
	var proofs []string
	for i := 0; i < 3; i++ {
		status, nonceBody := f.postJSON(t, "/oid4vci/nonce", "", "")
		if status != http.StatusOK {
			t.Fatalf("nonce endpoint gave %d: %v", status, nonceBody)
		}
		nonce, _ := nonceBody["c_nonce"].(string)
		proofs = append(proofs, mustJSONString(t, newWallet(t).proof(t, f.srv.cfg.Issuer, nonce)))
	}
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + strings.Join(proofs, ",") + `]}}`

	status, resp := f.postJSON(t, "/oid4vci/credential", token, body)
	if status != http.StatusOK {
		t.Fatalf("credential endpoint gave %d: %v", status, resp)
	}
	creds, _ := resp["credentials"].([]any)
	// Asserted before anything below, because every check that follows is a
	// property of a list and would hold vacuously for an empty one.
	if len(creds) != 3 {
		t.Fatalf("got %d credentials for 3 proofs: %v", len(creds), resp["credentials"])
	}

	const day = 86400
	var iats, exps []float64
	for _, c := range creds {
		m, _ := c.(map[string]any)
		raw, _ := m["credential"].(string)
		jwt := strings.Split(raw, "~")[0]
		claims := decodeJWTPayload(t, jwt)

		iat, ok := claims["iat"].(float64)
		if !ok {
			t.Fatalf("no iat in a credential: %v", claims)
		}
		exp, ok := claims["exp"].(float64)
		if !ok {
			t.Fatalf("no exp in a credential: %v", claims)
		}
		iats = append(iats, iat)
		exps = append(exps, exp)

		// The configured lifetime is 30 days, so the rounding period is a day.
		// This is the assertion that fails if the rounding is removed: a raw
		// clock reading is a multiple of 86400 once every 86400 seconds.
		if int64(iat)%day != 0 {
			t.Errorf("iat = %.0f is not rounded to a day boundary (%.0f seconds "+
				"past one). At second precision it identifies the batch, and any "+
				"two verifiers holding two of these credentials can match on it "+
				"and learn they are looking at the same holder",
				iat, iat-float64((int64(iat)/day)*day))
		}
		if int64(exp)%day != 0 {
			t.Errorf("exp = %.0f is not rounded to a day boundary; it is iat plus a "+
				"fixed lifetime, so it carries the same fingerprint a second time", exp)
		}
		// Rounding must never hand out a credential that has already expired.
		if exp <= iat {
			t.Errorf("exp %.0f is not after iat %.0f", exp, iat)
		}
	}

	// The batch must agree with itself. This is a cheap regression guard and not
	// much more: with the rounding above in place it can only fail if a batch
	// straddles midnight, so a test cannot make it fail on demand. The property
	// it stands for -- that every instant within one period maps to one value --
	// is proved directly in internal/sdjwt, where the clock is an argument.
	for i := range iats {
		if iats[i] != iats[0] || exps[i] != exps[0] {
			t.Errorf("credential %d has iat/exp %.0f/%.0f but the first has %.0f/%.0f; "+
				"the batch was stamped from more than one clock reading",
				i, iats[i], exps[i], iats[0], exps[0])
		}
	}
}

// The other half of §10.1's MUST: "New Key Binding keys... for each credential
// in the batch".
//
// The keys come from the wallet, so we are the only party that can enforce it. A
// wallet reusing one key gets two credentials with an identical `cnf` — which
// two verifiers can compare directly, no timing analysis required. Nothing
// stopped this: each proof is validated on its own and the nonces are genuinely
// distinct, so both proofs are individually valid.
func TestTwoProofsWithTheSameHolderKeyAreRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	wa := newWallet(t) // one key, used twice
	var proofs []string
	for i := 0; i < 2; i++ {
		status, nonceBody := f.postJSON(t, "/oid4vci/nonce", "", "")
		if status != http.StatusOK {
			t.Fatalf("nonce endpoint gave %d: %v", status, nonceBody)
		}
		nonce, _ := nonceBody["c_nonce"].(string)
		proofs = append(proofs, mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce)))
	}
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + strings.Join(proofs, ",") + `]}}`

	status, resp := f.postJSON(t, "/oid4vci/credential", token, body)
	if status == http.StatusOK {
		t.Fatalf("two credentials were issued against one holder key; they carry "+
			"the same cnf and any verifier that sees both knows they belong to one "+
			"holder, which is the whole thing batch issuance is for: %v", resp)
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
	if resp["error"] != "invalid_proof" {
		t.Errorf("error = %v, want invalid_proof", resp["error"])
	}
}

// A single-proof request must still work. The duplicate-key check above walks a
// map, and a guard that refuses the ordinary case would be caught here rather
// than by a wallet.
func TestOneProofIsStillIssuedAfterTheDuplicateKeyCheck(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)

	status, nonceBody := f.postJSON(t, "/oid4vci/nonce", "", "")
	if status != http.StatusOK {
		t.Fatalf("nonce endpoint gave %d: %v", status, nonceBody)
	}
	nonce, _ := nonceBody["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + mustJSONString(t, newWallet(t).proof(t, f.srv.cfg.Issuer, nonce)) + `]}}`

	status, resp := f.postJSON(t, "/oid4vci/credential", token, body)
	if status != http.StatusOK {
		t.Fatalf("an ordinary one-proof request was refused with %d: %v", status, resp)
	}
}
