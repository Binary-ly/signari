package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// mintBoundIssuanceToken is mintAccessToken for a wallet that proved a DPoP
// key at the token endpoint.
func (f *tokenFixture) mintBoundIssuanceToken(t *testing.T, jkt string) string {
	t.Helper()
	ctx := context.Background()
	_, hash, err := store.NewPreAuthCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewPreAuthorizedCode(ctx, f.pool, f.orgID, f.userID, f.clientID,
		hash, []string{"IdentityCredential"}, nil, nil, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	stored, err := store.LookupPreAuthorizedCode(ctx, f.pool, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimPreAuthorizedCode(ctx, f.pool, stored.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := f.srv.mintSet(withDPoPThumbprint(ctx, jkt), tx, c, f.orgID, f.userID,
		"", "", []string{}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordPreAuthorizedToken(ctx, tx, stored.ID, resp.jti); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

func (p *proofKey) resourceProof(t *testing.T, uri, token string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, "dpop+jwt").WithHeader("jwk", p.jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"jti": fmt.Sprintf("cb-%d", time.Now().UnixNano()), "htm": http.MethodPost,
		"htu": uri, "iat": time.Now().Unix(), "ath": dpop.AccessTokenHash(token),
	})
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

func (f *tokenFixture) askForCredential(t *testing.T, scheme, token, proof string) (int, string) {
	t.Helper()
	wa := newWallet(t)
	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	body := `{"credential_configuration_id":"IdentityCredential",
	          "proofs":{"jwt":[` + mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce)) + `]}}`
	req := httptest.NewRequest(http.MethodPost, "/oid4vci/credential", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", scheme+" "+token)
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// A DPoP-bound issuance token mints only with a proof from the key it is bound
// to. The endpoint checked that some valid proof came with it, and a stolen
// token minted credentials with the thief's own.
func TestABoundIssuanceTokenMintsOnlyWithItsOwnKey(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	holder, thief := newProofKey(t), newProofKey(t)
	token := f.mintBoundIssuanceToken(t, holder.thumbprint(t))
	uri := tokenTestIssuer + "/oid4vci/credential"

	if st, body := f.askForCredential(t, "DPoP", token, thief.resourceProof(t, uri, token)); st != http.StatusUnauthorized {
		t.Fatalf("a proof from another key minted: %d %.200s", st, body)
	}
	if st, _ := f.askForCredential(t, "DPoP", token, ""); st != http.StatusUnauthorized {
		t.Fatalf("no proof: %d, want 401", st)
	}
	if st, body := f.askForCredential(t, "DPoP", token, holder.resourceProof(t, uri, token)); st != http.StatusOK {
		t.Fatalf("the holder's own key was refused: %d %.200s", st, body)
	}
}

// Userinfo, the other protected resource, holds a bound token to its key the
// same way; it had the comparison and no test of it.
func TestUserinfoHoldsABoundTokenToItsOwnKey(t *testing.T) {
	f := newTokenFixture(t)
	holder, thief := newProofKey(t), newProofKey(t)
	k, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
		Issuer: f.srv.cfg.Issuer, Subject: f.userID, Audience: []string{f.clientID},
		Expiry: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
		JTI: fmt.Sprintf("bound-userinfo-%d", now.UnixNano()), ClientID: f.clientID,
		Scope: "openid", Cnf: &tokens.Confirmation{JKT: holder.thumbprint(t)},
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	uri := tokenTestIssuer + "/oauth2/userinfo"
	ask := func(p *proofKey) int {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", p.resourceProof(t, uri, token))
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := ask(thief); code != http.StatusUnauthorized {
		t.Fatalf("userinfo accepted a bound token with another key's proof: %d", code)
	}
	if code := ask(holder); code != http.StatusOK {
		t.Fatalf("userinfo refused the holder's own key: %d", code)
	}
}

// A deactivated holder's token mints nothing: it carries no session to end and
// no grant to revoke, so deactivation reaches it only here.
func TestADeactivatedHoldersTokenMintsNothing(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if st, body := f.askForCredential(t, "Bearer", token, ""); st != http.StatusUnauthorized {
		t.Fatalf("a deactivated holder's token minted: %d %.200s", st, body)
	}
}
