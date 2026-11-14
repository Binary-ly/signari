package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Upstream identity providers (6.07), as `signari idp` configures them: the
// providers people sign in through, and the issuers whose assertions the
// jwt-bearer grant accepts. A provider is addressed by its slug, which is
// unique across the deployment because /login/with/<slug> names no
// organisation.

type identityProviderView struct {
	ID                     string           `json:"id"`
	Slug                   string           `json:"slug"`
	Name                   string           `json:"name"`
	Kind                   string           `json:"kind"`
	Issuer                 string           `json:"issuer"`
	Enabled                bool             `json:"enabled"`
	AllowSignup            bool             `json:"allow_signup"`
	AllowLinking           bool             `json:"allow_linking"`
	AllowAssertions        bool             `json:"allow_assertions"`
	TrustEmailVerification bool             `json:"trust_email_verification"`
	RequireVerifiedEmail   bool             `json:"require_verified_email"`
	MFAAMR                 []string         `json:"mfa_amr"`
	MFAACR                 []string         `json:"mfa_acr"`
	LoginDomains           []string         `json:"login_domains"`
	EndSessionURL          string           `json:"end_session_url"`
	ForwardParameters      []string         `json:"forward_parameters"`
	GroupClaim             string           `json:"group_claim"`
	GroupMap               []map[string]any `json:"group_map"`
	TokenAuthMethod        string           `json:"token_auth_method"`
	HasClientKey           bool             `json:"has_client_key"`
	Linked                 int              `json:"linked"`
	AttributeMap           []map[string]any `json:"attribute_map"`
	StoreTokens            bool             `json:"store_tokens"`
	// A SAML upstream's metadata: where it was read from, and when last.
	MetadataURL    string     `json:"metadata_url"`
	MetadataReadAt *time.Time `json:"metadata_read_at"`
}

// patchIdentityProviderRequest is `idp enable|disable`, `idp assertions`,
// `idp verified-email` and `idp trust-mfa`: what is given changes.
type patchIdentityProviderRequest struct {
	Enabled                *bool     `json:"enabled"`
	AllowAssertions        *bool     `json:"allow_assertions"`
	TrustEmailVerification *bool     `json:"trust_email_verification"`
	RequireVerifiedEmail   *bool     `json:"require_verified_email"`
	MFAAMR                 *[]string `json:"mfa_amr"`
	MFAACR                 *[]string `json:"mfa_acr"`
	LoginDomains           *[]string `json:"login_domains"`
	EndSessionURL          *string   `json:"end_session_url"`
	// ForwardParameters names what a sign-in passes on to the provider: prompt,
	// login_hint or acr_values. Empty tells it nothing.
	ForwardParameters *[]string `json:"forward_parameters"`
	// GroupClaim is the claim the provider's groups arrive in.
	GroupClaim *string `json:"group_claim"`
	// StoreTokens keeps what the provider hands over at a sign-in, sealed. Turned off,
	// everything kept is removed.
	StoreTokens *bool `json:"store_tokens"`
}

// idpGroupMapRequest says one of a provider's groups grants a local one.
type idpGroupMapRequest struct {
	RemoteGroup string `json:"remote_group"`
	Group       string `json:"group"`
}

type idpAttributeMapRequest struct {
	Claim     string `json:"claim"`
	Attribute string `json:"attribute"`
	Overwrite bool   `json:"overwrite"`
	MaxLength int    `json:"max_length"`
}

const idpRefusal = "change how anybody in the organisation may sign in through another provider"

// addIdentityProviderRequest is `idp add` and `idp add-issuer`: a named or
// generic OIDC provider by its client, a SAML upstream by its entity ID, or
// an assertion issuer by its keys.
type addIdentityProviderRequest struct {
	Kind         string `json:"kind"`
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Issuer       string `json:"issuer"`
	JWKSURL      string `json:"jwks_url"`
	// An OAuth 2.0 provider's endpoints, what it is asked for, and the paths
	// into its userinfo answer that hold the person.
	AuthorizeURL          string   `json:"authorize_url"`
	TokenURL              string   `json:"token_url"`
	UserinfoURL           string   `json:"userinfo_url"`
	Scopes                []string `json:"scopes"`
	UserinfoSubject       string   `json:"userinfo_subject"`
	UserinfoEmail         string   `json:"userinfo_email"`
	UserinfoEmailVerified string   `json:"userinfo_email_verified"`
	UserinfoName          string   `json:"userinfo_name"`
	// AllowSignup and AllowLinking default to on, as `idp add` has them, and
	// to off for an assertion issuer, which signs nobody in.
	AllowSignup  *bool `json:"allow_signup"`
	AllowLinking *bool `json:"allow_linking"`
	// TrustEmailVerification defaults to off, and to on for a SAML upstream,
	// whose assertion has no field to say an address is unverified.
	TrustEmailVerification *bool  `json:"trust_email_verification"`
	EntityID               string `json:"entity_id"`
	SSOURL                 string `json:"sso_url"`
	Certificate            string `json:"certificate"`
	NameIDFormat           string `json:"name_id_format"`
	AllowUnsolicited       bool   `json:"allow_unsolicited"`
	ForceAuthn             bool   `json:"force_authn"`
	SkewSeconds            *int   `json:"skew_seconds"`
	// A SAML upstream's metadata, in place of sso_url and certificate: the
	// document itself or where to read it, the certificate it must be signed
	// with, or metadata_unsigned, by name.
	Metadata         string `json:"metadata"`
	MetadataURL      string `json:"metadata_url"`
	MetadataSigner   string `json:"metadata_signer"`
	MetadataUnsigned bool   `json:"metadata_unsigned"`
	// A wallet sign-in's, kind oid4vp: how wallets know this verifier, where the
	// browser is sent, the credential types asked for, the claim paths that
	// identify, address and name the person, and under an x509 prefix the PEM key
	// requests are signed with and its certificate chain, leaf first.
	ClientIDPrefix   string   `json:"client_id_prefix"`
	WalletURL        string   `json:"wallet_url"`
	ResponseMode     string   `json:"response_mode"`
	VCTValues        []string `json:"vct_values"`
	SubjectClaim     string   `json:"subject_claim"`
	EmailClaim       string   `json:"email_claim"`
	NameClaim        string   `json:"name_claim"`
	RequestKey       string   `json:"request_key"`
	CertificateChain string   `json:"certificate_chain"`
}

func providerHTTPClient() *http.Client { return safedial.Client(15 * time.Second) }

// addIdentityProvider registers a provider as `signari idp add` and `idp
// add-issuer` do. The provider is reached first, a generic one discovered and
// an issuer's keys read, through the client the sign-in reaches it with, so
// an issuer that is wrong or internal is refused here rather than at somebody's
// first sign-in. That happens outside the write, so the precondition is
// checked before it and again in the write.
func (s *Server) addIdentityProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addIdentityProviderRequest
	if !decodeStrictUpTo(w, r, &req, maxMetadataRequest) {
		return
	}
	if !slugPattern.MatchString(req.Slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider",
			"detail": "a slug is lowercase letters, digits and inner hyphens, at most 63, since it is the sign-in URL"})
		return
	}
	or := func(p *bool, def bool) bool {
		if p == nil {
			return def
		}
		return *p
	}
	signIn := req.Kind != "assertion"
	spec := store.IdentityProviderSpec{Slug: req.Slug, Name: strings.TrimSpace(req.Name), Kind: req.Kind,
		ClientID: req.ClientID, ClientSecret: req.ClientSecret, Issuer: strings.TrimSpace(req.Issuer),
		JWKSURL: strings.TrimSpace(req.JWKSURL), AllowSignup: or(req.AllowSignup, signIn),
		AllowLinking: or(req.AllowLinking, signIn), TrustEmailVerification: or(req.TrustEmailVerification,
			req.Kind == "saml"), EntityID: req.EntityID, SSOURL: req.SSOURL, CertPEM: req.Certificate,
		NameIDFormat: req.NameIDFormat, AllowUnsolicited: req.AllowUnsolicited, ForceAuthn: req.ForceAuthn,
		SkewSeconds: 30, AuthorizeURL: strings.TrimSpace(req.AuthorizeURL), TokenURL: strings.TrimSpace(req.TokenURL),
		UserinfoURL: strings.TrimSpace(req.UserinfoURL), Scopes: req.Scopes,
		Userinfo: federation.UserinfoClaims{Subject: req.UserinfoSubject, Email: req.UserinfoEmail,
			EmailVerified: req.UserinfoEmailVerified, Name: req.UserinfoName}}
	if req.SkewSeconds != nil {
		spec.SkewSeconds = *req.SkewSeconds
	}
	vp := &store.VPSpec{Prefix: req.ClientIDPrefix, WalletURL: strings.TrimSpace(req.WalletURL),
		ResponseMode: req.ResponseMode, VCTValues: req.VCTValues, SubjectClaim: req.SubjectClaim,
		EmailClaim: req.EmailClaim, NameClaim: req.NameClaim, KeyPEM: req.RequestKey, ChainPEM: req.CertificateChain}
	switch {
	case req.Kind == "oid4vp":
		spec.VP = vp
	case vp.Prefix != "" || vp.WalletURL != "" || vp.ResponseMode != "" || len(vp.VCTValues) > 0 || vp.SubjectClaim != "" ||
		vp.EmailClaim != "" || vp.NameClaim != "" || vp.KeyPEM != "" || vp.ChainPEM != "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider",
			"detail": "client_id_prefix, wallet_url, response_mode, vct_values, the claim paths, request_key and certificate_chain " +
				"are a wallet sign-in's, kind oid4vp"})
		return
	}
	if req.Metadata != "" || req.MetadataURL != "" {
		if req.Kind != "saml" || req.SSOURL != "" || req.Certificate != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
				"detail": "metadata is for a SAML upstream, and says where sign-ins go and which keys are believed, " +
					"so sso_url and certificate would be a second answer"})
			return
		}
		if narrowedTokenRefused(w, r, idpRefusal) {
			return
		}
		entity, origin, ok := s.partnerMetadata(w, r, orgID, samlMetadataRequest{Metadata: req.Metadata,
			MetadataURL: req.MetadataURL, MetadataSigner: req.MetadataSigner, MetadataUnsigned: req.MetadataUnsigned},
			req.EntityID, store.SAMLMetadataOrigin{})
		if !ok {
			return
		}
		if entity.IdP == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
				"detail": "the metadata declares no SAML 2.0 identity provider"})
			return
		}
		spec.ApplyMetadata(entity.EntityID, entity.IdP, origin)
	}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	if err := s.preconditionHoldsNow(ctx, pre); err != nil {
		if !writePreconditionFailure(w, err) {
			s.writeIdPFailure(w, err, orgID)
		}
		return
	}
	if !s.orgExists(w, ctx, orgID) {
		return
	}
	keyCount, err := spec.Resolve(ctx, s.providerClient())
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	var id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if id, err = store.AddIdentityProvider(ctx, tx, s.root, orgID, spec); err != nil {
			return err
		}
		detail := map[string]any{"provider": spec.Slug, "kind": spec.Kind, "allow_signup": spec.AllowSignup,
			"allow_linking": spec.AllowLinking, "trust_email_verification": spec.TrustEmailVerification}
		if spec.Issuer != "" {
			detail["issuer"] = spec.Issuer
		}
		if spec.EntityID != "" {
			detail["entity_id"] = spec.EntityID
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.identity_provider_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	out := map[string]any{"id": id, "slug": spec.Slug, "kind": spec.Kind, "allow_assertions": false,
		"config_version": version}
	switch spec.Kind {
	case "saml":
		out["sign_in_path"] = "/saml/source/" + spec.Slug + "/start"
		out["acs_path"] = "/saml/source/" + spec.Slug + "/acs"
		out["metadata_path"] = "/saml/source/" + spec.Slug + "/metadata"
	case "assertion":
		out["keys"] = keyCount
	case "oid4vp":
		out["sign_in_path"] = "/oid4vp/" + spec.Slug + "/start"
		out["response_path"] = "/oid4vp/" + spec.Slug + "/response"
	default:
		out["sign_in_path"] = "/login/with/" + spec.Slug
		out["callback_path"] = "/login/callback/" + spec.Slug
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listIdentityProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.IdentityProviders(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing identity providers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]identityProviderView, 0, len(got))
	for _, p := range got {
		maps := make([]map[string]any, 0, len(p.AttributeMap))
		for _, m := range p.AttributeMap {
			maps = append(maps, map[string]any{"claim": m.Claim, "attribute": m.Attribute, "overwrite": m.Overwrite,
				"max_length": m.MaxLength})
		}
		groups := make([]map[string]any, 0, len(p.GroupMap))
		for _, m := range p.GroupMap {
			groups = append(groups, map[string]any{"remote_group": m.RemoteGroup, "group": m.Group})
		}
		out = append(out, identityProviderView{ID: p.ID, Slug: p.Slug, Name: p.Name, Kind: p.Kind, Issuer: p.Issuer,
			Enabled: p.Enabled, AllowSignup: p.AllowSignup, AllowLinking: p.AllowLinking,
			AllowAssertions: p.AllowAssertions, TrustEmailVerification: p.TrustEmailVerification,
			RequireVerifiedEmail: p.RequireVerifiedEmail, MFAAMR: p.MFAAMR, MFAACR: p.MFAACR, Linked: p.Linked,
			LoginDomains: p.LoginDomains, EndSessionURL: p.EndSessionURL, TokenAuthMethod: p.TokenAuthMethod,
			HasClientKey: p.HasClientKey, AttributeMap: maps, ForwardParameters: p.ForwardParameters,
			GroupClaim: p.GroupClaim, GroupMap: groups, StoreTokens: p.StoreTokens, MetadataURL: p.MetadataURL,
			MetadataReadAt: p.MetadataReadAt})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "providers": out})
}

func (s *Server) patchIdentityProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	var req patchIdentityProviderRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	change := store.IdentityProviderChange{Enabled: req.Enabled, AllowAssertions: req.AllowAssertions,
		TrustEmailVerification: req.TrustEmailVerification, RequireVerifiedEmail: req.RequireVerifiedEmail,
		StoreTokens: req.StoreTokens}
	if req.MFAAMR != nil {
		l := cleanList(*req.MFAAMR, false)
		change.MFAAMR = &l
	}
	if req.MFAACR != nil {
		l := cleanList(*req.MFAACR, false)
		change.MFAACR = &l
	}
	change.LoginDomains = req.LoginDomains
	change.EndSessionURL = req.EndSessionURL
	change.ForwardParameters = req.ForwardParameters
	change.GroupClaim = req.GroupClaim
	if change.Empty() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change"})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.ChangeIdentityProvider(ctx, tx, orgID, slug, change); err != nil {
			return err
		}
		detail := map[string]any{"provider": slug}
		if req.Enabled != nil {
			detail["enabled"] = *req.Enabled
		}
		if req.AllowAssertions != nil {
			detail["allow_assertions"] = *req.AllowAssertions
		}
		if req.TrustEmailVerification != nil {
			detail["trust_email_verification"] = *req.TrustEmailVerification
		}
		if req.RequireVerifiedEmail != nil {
			detail["require_verified_email"] = *req.RequireVerifiedEmail
		}
		if change.MFAAMR != nil {
			detail["mfa_amr"] = *change.MFAAMR
		}
		if change.MFAACR != nil {
			detail["mfa_acr"] = *change.MFAACR
		}
		if req.ForwardParameters != nil {
			detail["forward_parameters"] = *req.ForwardParameters
		}
		if req.GroupClaim != nil {
			detail["group_claim"] = *req.GroupClaim
		}
		if req.StoreTokens != nil {
			detail["store_tokens"] = *req.StoreTokens
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.identity_provider_updated", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "config_version": version})
}

// idpTokenAuthRequest is `idp auth`. The key is write-only: nothing reads it back.
type idpTokenAuthRequest struct {
	Method            string `json:"method"`
	ClientKey         string `json:"client_key"`
	ClientCertificate string `json:"client_certificate"`
}

// putIdPTokenAuth says how this engine proves itself at the provider's token
// endpoint, as `signari idp auth` does.
func (s *Server) putIdPTokenAuth(w http.ResponseWriter, r *http.Request) {
	var req idpTokenAuthRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.SetIdPTokenAuth(ctx, tx, s.root, orgID, slug, store.IdPTokenAuth{Method: req.Method,
			ClientKey: []byte(req.ClientKey), ClientCertificate: []byte(req.ClientCertificate)}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_token_auth_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"provider": slug, "method": req.Method,
				"client_key_given": req.ClientKey != ""}})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "method": req.Method, "config_version": version})
}

// vpIssuerRequest is an issuer a wallet sign-in believes, with the public keys its
// credentials are signed with, as `signari idp vp-issuer` gives them.
type vpIssuerRequest struct {
	Issuer string          `json:"issuer"`
	JWKS   json.RawMessage `json:"jwks"`
	// KeysFrom is "pinned", the default, with jwks; "metadata", without: the keys the
	// issuer's JWT VC Issuer Metadata publishes, read for each presentation; or "x5c",
	// with roots: the key of the certificate chain each credential carries.
	KeysFrom string `json:"keys_from,omitempty"`
	// Roots are the PEM CA certificates an x5c issuer's chain has to lead to.
	Roots string `json:"roots,omitempty"`
}

func (s *Server) putVPIssuer(w http.ResponseWriter, r *http.Request) {
	var req vpIssuerRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	refuse := func(detail string) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider", "detail": detail})
	}
	jwks := len(req.JWKS) > 0 && string(req.JWKS) != "null"
	switch req.KeysFrom {
	case "", store.VPKeysPinned, store.VPKeysFromMetadata:
		if req.Roots != "" {
			refuse(`roots belong to keys_from "x5c" alone: an issuer is believed one way`)
			return
		}
		if req.KeysFrom == store.VPKeysFromMetadata && jwks {
			refuse("keys_from metadata takes no jwks: the keys are read from the issuer")
			return
		}
	case store.VPKeysFromX5C:
		if jwks {
			refuse("keys_from x5c takes no jwks: the key is the one its certificate chain carries")
			return
		}
	default:
		refuse(`keys_from is "pinned", "metadata" or "x5c"`)
		return
	}
	s.changeVPIssuer(w, r, req, true)
}

func (s *Server) deleteVPIssuer(w http.ResponseWriter, r *http.Request) {
	s.changeVPIssuer(w, r, vpIssuerRequest{Issuer: r.URL.Query().Get("issuer")}, false)
}

// changeVPIssuer believes an issuer for a wallet sign-in, with its keys, or stops
// believing it, as `signari idp vp-issuer` does.
func (s *Server) changeVPIssuer(w http.ResponseWriter, r *http.Request, req vpIssuerRequest, believe bool) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		detail := map[string]any{"provider": slug, "issuer": req.Issuer}
		if believe {
			set := func() error { return store.SetVPTrustedIssuer(ctx, tx, orgID, slug, req.Issuer, req.JWKS) }
			detail["keys_from"] = store.VPKeysPinned
			switch req.KeysFrom {
			case store.VPKeysFromMetadata:
				set = func() error { return store.SetVPTrustedIssuerByMetadata(ctx, tx, orgID, slug, req.Issuer) }
				detail["keys_from"] = store.VPKeysFromMetadata
			case store.VPKeysFromX5C:
				set = func() error { return store.SetVPTrustedIssuerByX5C(ctx, tx, orgID, slug, req.Issuer, req.Roots) }
				detail["keys_from"] = store.VPKeysFromX5C
			}
			if err := set(); err != nil {
				return err
			}
			return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_vp_issuer_set", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: detail})
		}
		if err := store.RemoveVPTrustedIssuer(ctx, tx, orgID, slug, req.Issuer); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_vp_issuer_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "issuer": req.Issuer, "believed": believe,
		"config_version": version})
}

func (s *Server) putIdPAttributeMap(w http.ResponseWriter, r *http.Request) {
	var req idpAttributeMapRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeIdPAttributeMap(w, r, req, true)
}

func (s *Server) deleteIdPAttributeMap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeIdPAttributeMap(w, r, idpAttributeMapRequest{Claim: q.Get("claim"), Attribute: q.Get("attribute")}, false)
}

// changeIdPAttributeMap routes a claim from the provider into a declared
// local attribute, or stops it, as `signari idp attribute-map` does.
func (s *Server) changeIdPAttributeMap(w http.ResponseWriter, r *http.Request, req idpAttributeMapRequest, add bool) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	req.Claim, req.Attribute = strings.TrimSpace(req.Claim), strings.TrimSpace(req.Attribute)
	if req.Claim == "" || req.Attribute == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_mapping",
			"detail": "give claim and attribute"})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		detail := map[string]any{"provider": slug, "claim": req.Claim, "attribute": req.Attribute}
		if add {
			if err := store.SetIdPAttributeMap(ctx, tx, orgID, slug, req.Claim, req.Attribute, req.Overwrite,
				req.MaxLength); err != nil {
				return err
			}
			detail["overwrite"] = req.Overwrite
			return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_attribute_mapped", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: detail})
		}
		if err := store.RemoveIdPAttributeMap(ctx, tx, orgID, slug, req.Claim, req.Attribute); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.idp_attribute_unmapped", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "claim": req.Claim, "attribute": req.Attribute,
		"mapped": add, "config_version": version})
}

func (s *Server) putIdPGroupMap(w http.ResponseWriter, r *http.Request) {
	var req idpGroupMapRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeIdPGroupMap(w, r, req, true)
}

func (s *Server) deleteIdPGroupMap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.changeIdPGroupMap(w, r, idpGroupMapRequest{RemoteGroup: q.Get("remote_group"), Group: q.Get("group")}, false)
}

// changeIdPGroupMap says one of a provider's groups grants a local one, or stops it, as
// `signari idp map-group` does.
func (s *Server) changeIdPGroupMap(w http.ResponseWriter, r *http.Request, req idpGroupMapRequest, add bool) {
	ctx := r.Context()
	orgID, slug := r.PathValue("orgID"), r.PathValue("slug")
	req.RemoteGroup, req.Group = strings.TrimSpace(req.RemoteGroup), strings.TrimSpace(req.Group)
	if req.RemoteGroup == "" || req.Group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_mapping",
			"detail": "give remote_group and group"})
		return
	}
	if narrowedTokenRefused(w, r, idpRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		event := "admin.idp_group_mapped"
		if add {
			if err := store.SetIdPGroupMap(ctx, tx, orgID, slug, req.RemoteGroup, req.Group); err != nil {
				return err
			}
		} else {
			event = "admin.idp_group_unmapped"
			if err := store.RemoveIdPGroupMap(ctx, tx, orgID, slug, req.RemoteGroup, req.Group); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Event{Type: event, AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
			Detail: map[string]any{"provider": slug, "remote_group": req.RemoteGroup, "group": req.Group}})
	})
	if s.writeIdPFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"slug": slug, "remote_group": req.RemoteGroup, "group": req.Group,
		"mapped": add, "config_version": version})
}

// writeIdPFailure answers a refused or failed identity provider write, and
// reports whether it wrote anything.
func (s *Server) writeIdPFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrIdPInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_identity_provider", "detail": err.Error()})
	case errors.Is(err, store.ErrIdPSlugTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, store.ErrProviderUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found"})
	case errors.Is(err, store.ErrIdPMappingUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mapping_not_found"})
	case errors.Is(err, store.ErrVPIssuerUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "issuer_not_found"})
	case errors.Is(err, store.ErrIdPGroupUnknown):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_group", "detail": err.Error()})
	case errors.Is(err, store.ErrIdPGroupImpersonates):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group_impersonates", "detail": err.Error()})
	default:
		s.log.Error("writing an identity provider", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
