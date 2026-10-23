package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
)

// OID4VCI issuance (6.07), as `signari credential` configures it: the
// credentials an organisation issues, the roots an x5c key proof may verify
// to, and the offers that start an issuance for a person.

type credentialConfigurationView struct {
	ID                    string   `json:"id"`
	Format                string   `json:"format"`
	VCT                   string   `json:"vct"`
	Always                []string `json:"always"`
	Selective             []string `json:"selective"`
	LifetimeSeconds       int64    `json:"lifetime_s"`
	DisplayName           string   `json:"display_name"`
	RequireKeyAttestation bool     `json:"require_key_attestation"`
}

// putCredentialConfigurationRequest is `credential define`.
type putCredentialConfigurationRequest struct {
	VCT             string   `json:"vct"`
	Always          []string `json:"always"`
	Selective       []string `json:"selective"`
	LifetimeSeconds int64    `json:"lifetime_s"`
	DisplayName     string   `json:"display_name"`
	// RequireKeyAttestation absent keeps the configuration's setting.
	RequireKeyAttestation *bool `json:"require_key_attestation"`
}

type putProofRootRequest struct {
	Certificate string `json:"certificate"`
}

// credentialOfferRequest is `credential offer`, for the person the path names.
type credentialOfferRequest struct {
	ClientID                 string   `json:"client_id"`
	CredentialConfigurations []string `json:"credential_configurations"`
	// CredentialIssuer defaults to the issuer of the organisation's instance.
	CredentialIssuer string `json:"credential_issuer"`
	TxCode           bool   `json:"tx_code"`
	TxCodeLength     int    `json:"tx_code_length"`
	ExpiresInSeconds int64  `json:"expires_in_s"`
}

const credentialRefusal = "change what the organisation issues as credentials or which key proofs it trusts"

func (s *Server) listCredentialConfigurations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.CredentialConfigurations(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing credential configurations", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]credentialConfigurationView, 0, len(got))
	for _, c := range got {
		out = append(out, credentialConfigurationView{ID: c.ID, Format: c.Format, VCT: c.VCT,
			Always: nonNilStrings(c.AlwaysClaims), Selective: nonNilStrings(c.SelectiveClaims),
			LifetimeSeconds: int64(c.Lifetime.Seconds()), DisplayName: c.DisplayName,
			RequireKeyAttestation: c.RequireKeyAttestation})
	}
	slices.SortFunc(out, func(a, b credentialConfigurationView) int { return strings.Compare(a.ID, b.ID) })
	s.writeList(w, r, map[string]any{"org_id": orgID, "configurations": out})
}

func nonNilStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// putCredentialConfiguration defines or redefines a credential, as `signari
// credential define` does.
func (s *Server) putCredentialConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, configID := r.PathValue("orgID"), r.PathValue("configID")
	var req putCredentialConfigurationRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.LifetimeSeconds < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential",
			"detail": "lifetime_s is zero for no exp claim, or a number of seconds"})
		return
	}
	spec := store.CredentialSpec{ConfigID: configID, VCT: strings.TrimSpace(req.VCT),
		DisplayName: strings.TrimSpace(req.DisplayName), Always: cleanList(req.Always, false),
		Selective: cleanList(req.Selective, false), Lifetime: time.Duration(req.LifetimeSeconds) * time.Second,
		RequireKeyAttestation: req.RequireKeyAttestation}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, credentialRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var required bool
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if required, err = store.DefineCredential(ctx, tx, orgID, spec); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.credential_defined", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"configuration": configID, "vct": spec.VCT,
				"always": spec.Always, "selective": spec.Selective, "lifetime_s": req.LifetimeSeconds,
				"require_key_attestation": required}})
	})
	if s.writeCredentialFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"id": configID, "require_key_attestation": required,
		"config_version": version})
}

type proofRootView struct {
	Name     string     `json:"name"`
	Subject  string     `json:"subject"`
	NotAfter *time.Time `json:"not_after"`
}

func (s *Server) listCredentialProofRoots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.ProofRoots(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing credential proof roots", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]proofRootView, 0, len(got))
	for _, p := range got {
		v := proofRootView{Name: p.Name, Subject: p.Subject}
		if !p.NotAfter.IsZero() {
			t := p.NotAfter.UTC()
			v.NotAfter = &t
		}
		out = append(out, v)
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "roots": out})
}

// putCredentialProofRoot trusts a CA for x5c key proofs, as `signari
// credential trust-root` does. Without one a chain is refused, never accepted
// on its own signature, which a self-signed certificate satisfies.
func (s *Server) putCredentialProofRoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	var req putProofRootRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	der, err := store.ParseProofRootPEM([]byte(req.Certificate))
	var subject string
	var notAfter time.Time
	if err == nil {
		cert, cerr := store.CheckProofRoot(der, time.Now())
		if err = cerr; err == nil {
			subject, notAfter = cert.Subject.String(), cert.NotAfter.UTC()
		}
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_root", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, credentialRefusal) {
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
		if err := store.SetCredentialProofRoot(ctx, tx, orgID, name, der); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.credential_root_trusted", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": name, "subject": subject, "not_after": notAfter}})
	})
	if s.writeCredentialFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "subject": subject, "not_after": notAfter,
		"config_version": version})
}

// deleteCredentialProofRoot withdraws a root, as `signari credential
// untrust-root` does; chains to it are refused from the next request.
func (s *Server) deleteCredentialProofRoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, name := r.PathValue("orgID"), r.PathValue("name")
	if narrowedTokenRefused(w, r, credentialRefusal) {
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
		if err := store.RemoveCredentialProofRoot(ctx, tx, orgID, name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.credential_root_untrusted",
			AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"name": name}})
	})
	if s.writeCredentialFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "removed": true, "config_version": version})
}

// offerCredential mints a Credential Offer for the person, as `signari
// credential offer` does. Whoever holds the offer, and its transaction code
// when it has one, can redeem it into a token for the person, so the route is
// privileged when they are, the client must be one the token may act on, and
// both secrets are answered once and recorded only as hashes.
func (s *Server) offerCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	var req credentialOfferRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	ttl := 5 * time.Minute
	if req.ExpiresInSeconds != 0 {
		ttl = time.Duration(req.ExpiresInSeconds) * time.Second
	}
	length := req.TxCodeLength
	if req.TxCode && length == 0 {
		length = 6
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID != "" {
		if err := requireClient(ctx, clientID); err != nil {
			writeCrossOrg(w, err)
			return
		}
	}
	orgID, ok := s.consentUser(w, r)
	if !ok {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	// Trimmed but not de-duplicated: §4.1.1 requires the ids unique, and a
	// configuration named twice is refused rather than quietly offered once.
	configs := make([]string, 0, len(req.CredentialConfigurations))
	for _, c := range req.CredentialConfigurations {
		if c = strings.TrimSpace(c); c != "" {
			configs = append(configs, c)
		}
	}
	var minted *store.MintedOffer
	var issuer string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		issuer = strings.TrimSpace(req.CredentialIssuer)
		if issuer == "" {
			var err error
			if issuer, err = store.OrgIssuer(ctx, tx, orgID); err != nil {
				return err
			}
		}
		var err error
		if minted, err = store.MintCredentialOffer(ctx, tx, orgID, store.OfferSpec{UserID: userID,
			ClientID: clientID, CredentialIssuer: issuer, ConfigIDs: configs,
			TxCode: req.TxCode, TxLength: length, TTL: ttl}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.credential_offered", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID, Detail: map[string]any{"client_id": clientID,
				"configurations": minted.Offer.ConfigurationIDs, "credential_issuer": issuer,
				"tx_code": req.TxCode, "expires_in_s": int64(ttl.Seconds())}})
	})
	if s.writeCredentialFailure(w, err, orgID) {
		return
	}
	blob, err := json.Marshal(minted.Offer)
	if err != nil {
		s.log.Error("encoding a credential offer", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := map[string]any{"user_id": userID, "offer": minted.Offer,
		// §G.7.1: the wallet is invoked with the offer by value in a query
		// parameter.
		"offer_uri":      oid4vci.CredentialOfferURIScheme + "://?credential_offer=" + url.QueryEscape(string(blob)),
		"expires_at":     time.Now().Add(ttl).UTC(),
		"config_version": version}
	if minted.TxCode != "" {
		// §3.5: the transaction code "MUST be sent via a different channel
		// than the Credential Offer"; it is answered beside the offer only so
		// the caller can send it by one.
		out["tx_code"] = minted.TxCode
	}
	setETag(w, version)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}

// writeCredentialFailure answers a refused or failed credential write, and
// reports whether it wrote anything.
func (s *Server) writeCredentialFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrCredentialInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential", "detail": err.Error()})
	case errors.Is(err, store.ErrOfferClientCannotRedeem):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "client_cannot_redeem", "detail": err.Error() +
			"; register it for " + oid4vci.GrantType})
	case errors.Is(err, store.ErrInvalidProofRoot):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_root", "detail": err.Error()})
	case errors.Is(err, store.ErrProofRootUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "root_not_found"})
	default:
		s.log.Error("writing a credential setting", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
