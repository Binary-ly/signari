package store

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oid4vp"
)

// An OpenID4VP verifier (12.12) is an identity provider of kind oid4vp: the row in
// core.identity_providers that sign-ins are linked to, its settings in core.vp_verifiers,
// and the issuers it believes in core.vp_trusted_issuers.

// VPVerifier is one verifier, ready to ask a wallet and to check what comes back.
type VPVerifier struct {
	ProviderID, OrgID, Slug, DisplayName string
	Policy                               federation.Policy
	Prefix                               oid4vp.Prefix
	WalletURL                            string
	// ResponseMode is direct_post, or direct_post.jwt for an answer encrypted to a
	// key of the request's own.
	ResponseMode string
	VCTValues    []string
	// Subject identifies the person, within the issuer. Email and Name are nil
	// when the verifier does not ask for them.
	Subject, Email, Name oid4vp.Path
	// Key and Chain sign a request under an x509 prefix; nil under redirect_uri.
	Key     crypto.Signer
	Chain   []*x509.Certificate
	Issuers map[string]*jose.JSONWebKeySet
}

// CredentialQueryID names the one credential a verifier asks for, in the query and in
// the vp_token that answers it.
const CredentialQueryID = "credential"

// Ask is what the verifier asks a wallet for: every claim it reads, so each is in the
// credential or the credential is refused.
func (v *VPVerifier) Ask() oid4vp.Ask {
	claims := []oid4vp.Path{v.Subject}
	for _, p := range []oid4vp.Path{v.Email, v.Name} {
		if p != nil && p.String() != v.Subject.String() {
			claims = append(claims, p)
		}
	}
	return oid4vp.Ask{ID: CredentialQueryID, VCTValues: v.VCTValues, Claims: claims}
}

const sealContextVPKey = "vp_verifier_key"

// ErrVPVerifierUnknown is a slug that is not an enabled verifier.
var ErrVPVerifierUnknown = errors.New("no such wallet sign-in")

// LoadVPVerifier reads an enabled verifier by its slug.
func LoadVPVerifier(ctx context.Context, db *pgxpool.Pool, root *keys.RootKey, slug string) (*VPVerifier, error) {
	v := &VPVerifier{}
	var prefix, subject, email, name, chain string
	var sealed []byte
	err := db.QueryRow(ctx, `
		SELECT p.id::text, p.org_id::text, p.slug, p.display_name,
		       p.allow_signup, p.allow_linking, p.require_verified_email, p.trust_email_verification,
		       x.client_id_prefix, x.wallet_url, x.vct_values, x.subject_claim, x.email_claim,
		       x.name_claim, x.signing_key, COALESCE(x.certificate_chain, ''), x.response_mode
		FROM core.identity_providers p
		JOIN core.vp_verifiers x ON x.provider_id = p.id
		WHERE p.slug = $1 AND p.kind = 'oid4vp' AND p.enabled`, slug).Scan(
		&v.ProviderID, &v.OrgID, &v.Slug, &v.DisplayName,
		&v.Policy.AllowSignup, &v.Policy.AllowLinking, &v.Policy.RequireVerifiedEmail,
		&v.Policy.TrustsEmailVerification,
		&prefix, &v.WalletURL, &v.VCTValues, &subject, &email, &name, &sealed, &chain, &v.ResponseMode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVPVerifierUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("loading the wallet sign-in: %w", err)
	}
	if v.Prefix, err = oid4vp.ParsePrefix(prefix); err != nil {
		return nil, err
	}
	if v.Subject, err = oid4vp.ParsePath(subject); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		raw string
		to  *oid4vp.Path
	}{{email, &v.Email}, {name, &v.Name}} {
		if c.raw != "" {
			if *c.to, err = oid4vp.ParsePath(c.raw); err != nil {
				return nil, err
			}
		}
	}
	if len(sealed) > 0 {
		if root == nil {
			return nil, errors.New("opening the wallet sign-in's request key needs the root key")
		}
		plain, err := root.Open(sealed, sealContextVPKey)
		if err != nil {
			return nil, fmt.Errorf("unsealing the wallet sign-in's request key: %w", err)
		}
		if v.Key, _, err = federation.ParseClientKey(plain, []byte(chain)); err != nil {
			return nil, err
		}
		if v.Chain, err = oid4vp.ParseChain(chain); err != nil {
			return nil, err
		}
	}

	rows, err := db.Query(ctx, `SELECT issuer, jwks FROM core.vp_trusted_issuers WHERE provider_id = $1::uuid`,
		v.ProviderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	v.Issuers = map[string]*jose.JSONWebKeySet{}
	for rows.Next() {
		var issuer string
		var raw []byte
		if err := rows.Scan(&issuer, &raw); err != nil {
			return nil, err
		}
		set, err := ParseIssuerKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("the keys held for %s: %w", issuer, err)
		}
		v.Issuers[issuer] = set
	}
	return v, rows.Err()
}

// VPSpec is what an oid4vp provider is made with, beside IdentityProviderSpec's name,
// slug and policy.
type VPSpec struct {
	Prefix, WalletURL string
	// ResponseMode is direct_post, the default, or direct_post.jwt.
	ResponseMode string
	VCTValues    []string
	// Claim paths, as oid4vp.ParsePath reads them.
	SubjectClaim, EmailClaim, NameClaim string
	// KeyPEM signs requests under an x509 prefix, and ChainPEM is its certificate
	// chain, leaf first.
	KeyPEM, ChainPEM string
}

func (s *IdentityProviderSpec) validateVP() error {
	v := s.VP
	if v == nil {
		return s.invalid("a wallet sign-in needs its credential types, the claim that identifies a " +
			"person and how it is known to wallets; `signari idp add -kind oid4vp` takes them")
	}
	switch {
	case s.ClientID != "" || s.ClientSecret != "" || s.Issuer != "":
		return s.invalid("a wallet sign-in has no client id, secret or issuer of its own: it is the verifier")
	case s.TrustEmailVerification && v.EmailClaim == "":
		return s.invalid("an address is believed only from a credential, and this one is asked for none")
	}
	prefix, err := oid4vp.ParsePrefix(v.Prefix)
	if err != nil {
		return s.invalid("%v", err)
	}
	if v.WalletURL == "" {
		v.WalletURL = "openid4vp://"
	}
	switch v.ResponseMode {
	case "":
		v.ResponseMode = oid4vp.ModeDirectPost
	case oid4vp.ModeDirectPost, oid4vp.ModeDirectPostJWT:
	default:
		return s.invalid("the response mode %q: want direct_post or direct_post.jwt", v.ResponseMode)
	}
	if u, err := url.Parse(v.WalletURL); err != nil || u.Scheme == "" || u.Scheme == "http" {
		return s.invalid("the wallet URL %q: want openid4vp:// or a wallet's https link", v.WalletURL)
	}
	for _, p := range []struct{ what, raw string }{{"subject", v.SubjectClaim}, {"email", v.EmailClaim},
		{"name", v.NameClaim}} {
		if p.raw == "" && p.what != "subject" {
			continue
		}
		if _, err := oid4vp.ParsePath(p.raw); err != nil {
			return s.invalid("the %s claim: %v", p.what, err)
		}
	}
	if err := askOf(v).Validate(); err != nil {
		return s.invalid("%v", err)
	}
	switch {
	case prefix.Signed() && (v.KeyPEM == "" || v.ChainPEM == ""):
		return s.invalid("%s signs every request, so it needs the signing key and its certificate chain", prefix)
	case !prefix.Signed() && (v.KeyPEM != "" || v.ChainPEM != ""):
		return s.invalid("redirect_uri cannot sign a request (OID4VP 1.0 §5.9.3), so a key would be unused")
	case prefix.Signed():
		if _, _, err := federation.ParseClientKey([]byte(v.KeyPEM), []byte(v.ChainPEM)); err != nil {
			return s.invalid("the request key: %v", err)
		}
		if _, err := oid4vp.ParseChain(v.ChainPEM); err != nil {
			return s.invalid("the certificate chain: %v", err)
		}
	}
	return nil
}

// askOf is the ask a spec would make, so an impossible one is refused when it is
// stored and not at somebody's first sign-in.
func askOf(s *VPSpec) oid4vp.Ask {
	c := &VPVerifier{VCTValues: s.VCTValues}
	c.Subject, _ = oid4vp.ParsePath(s.SubjectClaim)
	if s.EmailClaim != "" {
		c.Email, _ = oid4vp.ParsePath(s.EmailClaim)
	}
	if s.NameClaim != "" {
		c.Name, _ = oid4vp.ParsePath(s.NameClaim)
	}
	return c.Ask()
}

func addVPVerifier(ctx context.Context, q outpostDB, root *keys.RootKey, orgID string, s IdentityProviderSpec) (string, error) {
	var sealed []byte
	if s.VP.KeyPEM != "" {
		if root == nil {
			return "", errors.New("sealing the request key needs the root key")
		}
		var err error
		if sealed, err = root.Seal([]byte(s.VP.KeyPEM), sealContextVPKey); err != nil {
			return "", fmt.Errorf("sealing the request key: %w", err)
		}
	}
	var id string
	if err := q.QueryRow(ctx, `
		INSERT INTO core.identity_providers
			(org_id, slug, display_name, kind, client_id, scopes, allow_signup, allow_linking,
			 trust_email_verification)
		VALUES ($1::uuid, $2, $3, 'oid4vp', '', '{}', $4, $5, $6)
		RETURNING id::text`, orgID, s.Slug, s.Name, s.AllowSignup, s.AllowLinking,
		s.TrustEmailVerification).Scan(&id); err != nil {
		return "", err
	}
	_, err := q.Exec(ctx, `
		INSERT INTO core.vp_verifiers
			(provider_id, org_id, client_id_prefix, wallet_url, vct_values, subject_claim, email_claim,
			 name_claim, signing_key, certificate_chain, response_mode)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11)`,
		id, orgID, s.VP.Prefix, s.VP.WalletURL, s.VP.VCTValues, canonicalPath(s.VP.SubjectClaim),
		canonicalPath(s.VP.EmailClaim), canonicalPath(s.VP.NameClaim), sealed, s.VP.ChainPEM, s.VP.ResponseMode)
	return id, err
}

// canonicalPath stores a path as the JSON array it means, so a bare name and the array
// holding it are one value.
func canonicalPath(raw string) string {
	if raw == "" {
		return ""
	}
	p, err := oid4vp.ParsePath(raw)
	if err != nil {
		return raw
	}
	return p.String()
}

// ParseIssuerKeys reads the keys an issuer's credentials are checked with: a JWKS of
// public signing keys and nothing else. A private key is refused, since whoever holds
// this file could sign as the issuer, and a MAC key the same, for the same reason.
func ParseIssuerKeys(raw []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the JWKS holds no key")
	}
	for _, k := range set.Keys {
		switch k.Key.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("key %q is not a public signing key", k.KeyID)
		}
		if k.Use != "" && k.Use != "sig" {
			return nil, fmt.Errorf("key %q is for %q, not signing", k.KeyID, k.Use)
		}
	}
	return &set, nil
}

// ErrVPIssuerUnknown is an issuer a wallet sign-in does not believe.
var ErrVPIssuerUnknown = errors.New("this wallet sign-in does not believe that issuer")

// SetVPTrustedIssuer believes issuer, with these keys, for the wallet sign-in slug, or
// replaces the keys held for it. orgID is the organisation it must be in, or "" for
// the command line, which names a slug alone.
func SetVPTrustedIssuer(ctx context.Context, q outpostDB, orgID, slug, issuer string, jwks []byte) error {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" || strings.Contains(issuer, vpSubjectSeparator) {
		return idpInvalid{fmt.Sprintf("the issuer %q: want the exact iss its credentials carry, which has no %q",
			issuer, vpSubjectSeparator)}
	}
	set, err := ParseIssuerKeys(jwks)
	if err != nil {
		return idpInvalid{"the issuer's keys: " + err.Error()}
	}
	canonical, err := json.Marshal(set)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `
		INSERT INTO core.vp_trusted_issuers (provider_id, org_id, issuer, jwks)
		SELECT x.provider_id, x.org_id, $2, $3::jsonb
		FROM core.vp_verifiers x JOIN core.identity_providers p ON p.id = x.provider_id
		WHERE p.slug = $1 AND ($4 = '' OR p.org_id::text = $4)
		ON CONFLICT (provider_id, issuer) DO UPDATE SET jwks = EXCLUDED.jwks`, slug, issuer, canonical, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderUnknown
	}
	return nil
}

// RemoveVPTrustedIssuer stops believing issuer for the wallet sign-in slug.
func RemoveVPTrustedIssuer(ctx context.Context, q outpostDB, orgID, slug, issuer string) error {
	tag, err := q.Exec(ctx, `
		DELETE FROM core.vp_trusted_issuers t USING core.identity_providers p
		WHERE p.id = t.provider_id AND p.slug = $1 AND t.issuer = $2 AND ($3 = '' OR p.org_id::text = $3)`,
		slug, issuer, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVPIssuerUnknown
	}
	return nil
}

// vpSubjectSeparator joins an issuer and the claim that identifies a person within it
// into the subject a sign-in is linked by. A URL cannot hold a bare "|" (RFC 3986), so
// the subject splits one way only.
const vpSubjectSeparator = "|"

// VPSubject is the subject a presentation signs in: the issuer and the claim together,
// since a claim is unique only within the issuer that made it (OID4VP 1.0 §14.4).
func VPSubject(issuer, claim string) string { return issuer + vpSubjectSeparator + claim }

// ErrVPRequestGone is a request that has expired, been answered or never existed.
var ErrVPRequestGone = errors.New("this wallet request has expired or has been answered")

// PendingVPRequest is an unanswered request: its nonce, and under direct_post.jwt the
// key its answer is encrypted to, opened with the root key.
func PendingVPRequest(ctx context.Context, q outpostDB, root *keys.RootKey, providerID, state string) (
	nonce string, responseKey []byte, err error) {
	h := sha256.Sum256([]byte(state))
	var sealed []byte
	err = q.QueryRow(ctx, `
		SELECT nonce, vp_response_key FROM core.federated_logins
		WHERE state_hash = $1 AND provider_id = $2::uuid AND expires_at > now() AND vp_presented IS NULL`,
		h[:], providerID).Scan(&nonce, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrVPRequestGone
	}
	if err != nil || len(sealed) == 0 {
		return nonce, nil, err
	}
	if root == nil {
		return "", nil, errors.New("opening a response key needs the root key")
	}
	responseKey, err = root.Open(sealed, sealContextVPResponseKey)
	return nonce, responseKey, err
}

const sealContextVPResponseKey = "vp_response_key"

// SetVPResponseKey keeps the key a request's answer is encrypted to with the pending
// sign-in, sealed under the root key, so it goes when the sign-in does.
func SetVPResponseKey(ctx context.Context, q outpostDB, root *keys.RootKey, providerID, state string, pkcs8 []byte) error {
	if root == nil {
		return errors.New("sealing a response key needs the root key")
	}
	sealed, err := root.Seal(pkcs8, sealContextVPResponseKey)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(state))
	tag, err := q.Exec(ctx, `UPDATE core.federated_logins SET vp_response_key = $3
		WHERE state_hash = $1 AND provider_id = $2::uuid`, h[:], providerID, sealed)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVPRequestGone
	}
	return nil
}

const vpPresentationContext = "signari oid4vp presentation"

func vpCipher(responseCode string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(responseCode), nil, vpPresentationContext, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// PresentVP records what a wallet's presentation proved, against the request it
// answers, and answers the response code the browser has to bring back for it. What
// was proved is sealed under a key only that code gives, and the code is not stored,
// so the row is no use to anybody who reads it. A request is answered once.
func PresentVP(ctx context.Context, q outpostDB, providerID, state string, proved []byte) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(random)
	aead, err := vpCipher(code)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, proved, []byte(providerID))
	stateHash := sha256.Sum256([]byte(state))
	codeHash := sha256.Sum256([]byte(code))
	tag, err := q.Exec(ctx, `
		UPDATE core.federated_logins SET vp_presented = $3, vp_response_code_hash = $4
		WHERE state_hash = $1 AND provider_id = $2::uuid AND expires_at > now() AND vp_presented IS NULL`,
		stateHash[:], providerID, sealed, codeHash[:])
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrVPRequestGone
	}
	return code, nil
}

// OpenVPPresentation is what a pending sign-in's presentation proved, given the
// response code the browser brought.
func OpenVPPresentation(p *PendingLogin, responseCode string) ([]byte, error) {
	if len(p.VPPresented) == 0 {
		return nil, errors.New("the wallet has not answered this request")
	}
	h := sha256.Sum256([]byte(responseCode))
	if subtle.ConstantTimeCompare(h[:], p.VPResponseCodeHash) != 1 {
		return nil, errors.New("that is not the code the wallet was given")
	}
	aead, err := vpCipher(responseCode)
	if err != nil {
		return nil, err
	}
	if len(p.VPPresented) < aead.NonceSize() {
		return nil, errors.New("the stored presentation is cut short")
	}
	nonce, sealed := p.VPPresented[:aead.NonceSize()], p.VPPresented[aead.NonceSize():]
	return aead.Open(nil, nonce, sealed, []byte(p.ProviderID))
}
