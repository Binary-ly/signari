package adminapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// SAML service providers (6.07), as `signari saml` registers and configures
// them. A provider is addressed by its id: its entity id is usually a URL.

type samlProviderView struct {
	ID                 string            `json:"id"`
	EntityID           string            `json:"entity_id"`
	Name               string            `json:"name"`
	NameIDFormat       string            `json:"name_id_format"`
	NameIDAttribute    string            `json:"name_id_attribute"`
	SignatureAlg       string            `json:"signature_alg"`
	Enabled            bool              `json:"enabled"`
	SignAssertions     bool              `json:"sign_assertions"`
	SignResponses      bool              `json:"sign_responses"`
	WantSignedRequests bool              `json:"want_signed_requests"`
	Encrypted          bool              `json:"encrypted"`
	HasSigningCert     bool              `json:"has_signing_cert"`
	LifetimeSeconds    int               `json:"lifetime_s"`
	ACSURLs            []string          `json:"acs_urls"`
	SLOURLs            []string          `json:"slo_urls"`
	Attributes         map[string]string `json:"attribute_release"`
	GroupRelease       any               `json:"group_release"`
	IdPInitiated       bool              `json:"idp_initiated"`
	DefaultRelayState  string            `json:"default_relay_state"`
	// MetadataURL is where it was read from, and MetadataReadAt when last:
	// empty and null for a provider typed in by hand.
	MetadataURL    string     `json:"metadata_url"`
	MetadataReadAt *time.Time `json:"metadata_read_at"`
	// WSFedSAMLVersion is the SAML its WS-Federation token is in.
	WSFedSAMLVersion string `json:"wsfed_saml_version"`
	// OrgEndpoint is a provider that answers at its organisation's endpoints.
	OrgEndpoint bool `json:"org_endpoint"`
}

type addSAMLProviderRequest struct {
	EntityID           string `json:"entity_id"`
	Name               string `json:"name"`
	ACSURL             string `json:"acs_url"`
	NameIDFormat       string `json:"name_id_format"`
	SLOURL             string `json:"slo_url"`
	SLOBinding         string `json:"slo_binding"`
	SigningCert        string `json:"signing_cert"`
	EncryptionCert     string `json:"encryption_cert"`
	KeyTransport       string `json:"key_transport"`
	WantSignedRequests bool   `json:"want_signed_requests"`
	// The provider's metadata, in place of acs_url, slo_url and the certificates:
	// the document itself or where to read it, the certificate it must be signed
	// with, or metadata_unsigned, by name.
	Metadata         string `json:"metadata"`
	MetadataURL      string `json:"metadata_url"`
	MetadataSigner   string `json:"metadata_signer"`
	MetadataUnsigned bool   `json:"metadata_unsigned"`
	// MetadataEncrypt encrypts assertions to the key the metadata offers.
	MetadataEncrypt bool `json:"metadata_encrypt"`
}

// patchSAMLProviderRequest is `saml signing`: what is not given is left as
// it is.
type patchSAMLProviderRequest struct {
	SignAssertions  *bool  `json:"sign_assertions"`
	SignResponses   *bool  `json:"sign_responses"`
	LifetimeSeconds int    `json:"lifetime_s"`
	SignatureAlg    string `json:"signature_alg"`
	// NameIDAttribute is where the NameID comes from: a declared attribute no
	// person can edit, or username. Empty returns it to the format alone.
	NameIDAttribute *string `json:"name_id_attribute"`
	// IdPInitiated lets a sign-in to this provider start from the portal, and
	// DefaultRelayState is what goes with that response.
	IdPInitiated      *bool   `json:"idp_initiated"`
	DefaultRelayState *string `json:"default_relay_state"`
	// SOAPLogoutURL is where it is told of a logout with no browser, empty for
	// nowhere, as `signari saml soap-logout` sets it.
	SOAPLogoutURL *string `json:"soap_logout_url"`
	// WSFedSAMLVersion is the SAML its WS-Federation token is in, as
	// `signari saml wsfed-token` sets it.
	WSFedSAMLVersion *string `json:"wsfed_saml_version"`
	// OrgEndpoint moves it to its organisation's endpoints or back, as
	// `signari saml org-endpoint` does.
	OrgEndpoint *bool `json:"org_endpoint"`
}

type samlAttributeRequest struct {
	SAMLAttribute string `json:"saml_attribute"`
	Attribute     string `json:"attribute"`
}

type samlGroupReleaseRequest struct {
	AttributeName string   `json:"attribute_name"`
	Only          []string `json:"only"`
}

const samlRefusal = "change what the organisation asserts to another system about its people"

func (s *Server) listSAMLProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.SAMLProviders(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing SAML providers", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]samlProviderView, 0, len(got))
	for _, p := range got {
		v := samlProviderView{ID: p.ID, EntityID: p.EntityID, Name: p.Name, NameIDFormat: p.NameIDFormat,
			NameIDAttribute: p.NameIDAttribute,
			SignatureAlg:    p.SignatureAlg, Enabled: p.Enabled, SignAssertions: p.SignAssertions,
			SignResponses: p.SignResponses, WantSignedRequests: p.WantSignedRequests, Encrypted: p.Encrypted,
			HasSigningCert: p.HasSigningCert, LifetimeSeconds: p.LifetimeSeconds, ACSURLs: p.ACSURLs,
			SLOURLs: p.SLOURLs, Attributes: p.Attributes, IdPInitiated: p.IdPInitiated,
			DefaultRelayState: p.DefaultRelayState, MetadataURL: p.MetadataURL, MetadataReadAt: p.MetadataReadAt,
			WSFedSAMLVersion: p.WSFedSAMLVersion, OrgEndpoint: p.OrgEndpoint}
		if v.Attributes == nil {
			v.Attributes = map[string]string{}
		}
		if p.ReleasesGroups {
			v.GroupRelease = map[string]any{"attribute_name": p.GroupAttribute, "only": p.OnlyGroups}
		}
		out = append(out, v)
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "providers": out})
}

func (s *Server) addSAMLProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addSAMLProviderRequest
	if !decodeStrictUpTo(w, r, &req, maxMetadataRequest) {
		return
	}
	spec := store.SAMLProviderSpec{EntityID: strings.TrimSpace(req.EntityID), Name: strings.TrimSpace(req.Name),
		ACSURL: strings.TrimSpace(req.ACSURL), NameIDFormat: req.NameIDFormat, SLOURL: strings.TrimSpace(req.SLOURL),
		SLOBinding: req.SLOBinding, SigningCertPEM: req.SigningCert, EncryptionCertPEM: req.EncryptionCert,
		KeyTransport: req.KeyTransport, WantSignedRequests: req.WantSignedRequests}
	if req.Metadata != "" || req.MetadataURL != "" {
		if spec.ACSURL != "" || spec.SLOURL != "" || spec.SigningCertPEM != "" || spec.EncryptionCertPEM != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
				"detail": "the metadata says where assertions go and which keys are believed; acs_url, slo_url and " +
					"the certificates would be a second answer"})
			return
		}
		if narrowedTokenRefused(w, r, samlRefusal) {
			return
		}
		entity, origin, ok := s.partnerMetadata(w, r, orgID, samlMetadataRequest{Metadata: req.Metadata,
			MetadataURL: req.MetadataURL, MetadataSigner: req.MetadataSigner, MetadataUnsigned: req.MetadataUnsigned},
			spec.EntityID, store.SAMLMetadataOrigin{})
		if !ok {
			return
		}
		if entity.SP == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
				"detail": "the metadata declares no SAML 2.0 service provider"})
			return
		}
		if req.MetadataEncrypt && entity.SP.EncryptionCertPEM == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_metadata",
				"detail": "metadata_encrypt was given and the metadata offers no key for encryption"})
			return
		}
		spec.ApplyMetadata(entity.EntityID, entity.SP, req.MetadataEncrypt, origin)
	}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_saml_provider", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, samlRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id string
	var onOrg bool
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if id, err = store.AddSAMLProvider(ctx, tx, orgID, spec); err != nil {
			return err
		}
		if onOrg, err = store.SAMLOnOrgEndpoint(ctx, tx, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_provider_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"provider": id, "entity_id": spec.EntityID, "acs_url": spec.ACSURL,
				"name_id_format": spec.NameIDFormat, "encrypted": spec.EncryptionCertPEM != ""}})
	})
	if s.writeSAMLFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	// The provider imports the certificate from /saml/metadata.
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "entity_id": spec.EntityID,
		"name_id_format": spec.NameIDFormat, "org_endpoint": onOrg, "config_version": version})
}

// patchSAMLProvider chooses what is signed, with which algorithm, and how
// long an assertion lives, as `signari saml signing` does.
func (s *Server) patchSAMLProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, providerID := r.PathValue("orgID"), r.PathValue("providerID")
	var req patchSAMLProviderRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	if req.SignAssertions == nil && req.SignResponses == nil && req.LifetimeSeconds == 0 && req.SignatureAlg == "" &&
		req.NameIDAttribute == nil && req.IdPInitiated == nil && req.DefaultRelayState == nil && req.SOAPLogoutURL == nil &&
		req.WSFedSAMLVersion == nil && req.OrgEndpoint == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing_to_change"})
		return
	}
	if narrowedTokenRefused(w, r, samlRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var signA, signR bool
	var alg string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		if signA, signR, alg, err = store.SetSAMLSigning(ctx, tx, orgID, providerID, store.SAMLSigningChange{
			Assertions: req.SignAssertions, Responses: req.SignResponses, LifetimeSeconds: req.LifetimeSeconds,
			SignatureAlg: req.SignatureAlg}); err != nil {
			return err
		}
		detail := map[string]any{"provider": providerID, "sign_assertions": signA,
			"sign_responses": signR, "signature_alg": alg, "lifetime_s": req.LifetimeSeconds}
		if req.NameIDAttribute != nil {
			if err := store.SetSAMLNameIDAttribute(ctx, tx, orgID, providerID, *req.NameIDAttribute); err != nil {
				return err
			}
			detail["name_id_attribute"] = *req.NameIDAttribute
		}
		if req.IdPInitiated != nil || req.DefaultRelayState != nil {
			if err := store.SetSAMLIdPInitiated(ctx, tx, orgID, providerID, req.IdPInitiated, req.DefaultRelayState); err != nil {
				return err
			}
			if req.IdPInitiated != nil {
				detail["idp_initiated"] = *req.IdPInitiated
			}
			if req.DefaultRelayState != nil {
				detail["default_relay_state"] = *req.DefaultRelayState
			}
		}
		if req.SOAPLogoutURL != nil {
			if err := store.SetSAMLSOAPLogout(ctx, tx, orgID, providerID, *req.SOAPLogoutURL); err != nil {
				return err
			}
			detail["soap_logout_url"] = *req.SOAPLogoutURL
		}
		if req.WSFedSAMLVersion != nil {
			if err := store.SetSAMLWSFedVersion(ctx, tx, orgID, providerID, *req.WSFedSAMLVersion); err != nil {
				return err
			}
			detail["wsfed_saml_version"] = *req.WSFedSAMLVersion
		}
		if req.OrgEndpoint != nil {
			if err := store.SetSAMLOrgEndpoint(ctx, tx, orgID, providerID, *req.OrgEndpoint); err != nil {
				return err
			}
			detail["org_endpoint"] = *req.OrgEndpoint
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_signing_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: detail})
	})
	if s.writeSAMLFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out := map[string]any{"id": providerID, "sign_assertions": signA, "sign_responses": signR, "signature_alg": alg,
		"config_version": version}
	if req.SignatureAlg != "" {
		// The provider checks signatures against its copy of the metadata,
		// which it must fetch again before its next sign-in.
		out["metadata_changed"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSAMLAttributeRelease(w http.ResponseWriter, r *http.Request) {
	var req samlAttributeRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeSAMLRelease(w, r, "attribute", &req, nil)
}

func (s *Server) deleteSAMLAttributeRelease(w http.ResponseWriter, r *http.Request) {
	req := samlAttributeRequest{SAMLAttribute: r.URL.Query().Get("saml_attribute")}
	if req.SAMLAttribute == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "saml_attribute_required"})
		return
	}
	s.changeSAMLRelease(w, r, "attribute-remove", &req, nil)
}

func (s *Server) putSAMLGroupRelease(w http.ResponseWriter, r *http.Request) {
	var req samlGroupReleaseRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.changeSAMLRelease(w, r, "groups", nil, &req)
}

func (s *Server) deleteSAMLGroupRelease(w http.ResponseWriter, r *http.Request) {
	s.changeSAMLRelease(w, r, "groups-remove", nil, nil)
}

// changeSAMLRelease sets or stops what a provider is told: a local attribute
// under a SAML attribute name, as `signari saml attribute-release` does, or
// group membership, as `signari saml group-release` does.
func (s *Server) changeSAMLRelease(w http.ResponseWriter, r *http.Request, what string, attr *samlAttributeRequest,
	groups *samlGroupReleaseRequest) {
	ctx := r.Context()
	orgID, providerID := r.PathValue("orgID"), r.PathValue("providerID")
	if narrowedTokenRefused(w, r, samlRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	out := map[string]any{"id": providerID}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		switch what {
		case "attribute":
			if err := store.SetSAMLAttributeRelease(ctx, tx, orgID, providerID, attr.SAMLAttribute,
				attr.Attribute); err != nil {
				return err
			}
			out["saml_attribute"], out["attribute"] = attr.SAMLAttribute, attr.Attribute
			return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_attribute_released", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"provider": providerID, "saml_attribute": attr.SAMLAttribute,
					"attribute": attr.Attribute}})
		case "attribute-remove":
			if err := store.RemoveSAMLAttributeRelease(ctx, tx, orgID, providerID, attr.SAMLAttribute); err != nil {
				return err
			}
			out["saml_attribute"], out["removed"] = attr.SAMLAttribute, true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_attribute_withdrawn",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
				Detail: map[string]any{"provider": providerID, "saml_attribute": attr.SAMLAttribute}})
		case "groups":
			only := cleanList(groups.Only, false)
			if err := store.SetSAMLGroupRelease(ctx, tx, orgID, providerID, groups.AttributeName, only); err != nil {
				return err
			}
			name := strings.TrimSpace(groups.AttributeName)
			if name == "" {
				name = "groups"
			}
			out["attribute_name"], out["only"] = name, only
			return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_group_release_set", AdminTokenID: TokenIDFrom(ctx),
				OrgID: orgID, Detail: map[string]any{"provider": providerID, "attribute_name": name, "only": only}})
		default:
			if err := store.StopSAMLGroupRelease(ctx, tx, orgID, providerID); err != nil {
				return err
			}
			out["removed"] = true
			return audit.Write(ctx, tx, audit.Event{Type: "admin.saml_group_release_removed",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, Detail: map[string]any{"provider": providerID}})
		}
	})
	if s.writeSAMLFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

// writeSAMLFailure answers a refused or failed SAML write, and reports
// whether it wrote anything.
func (s *Server) writeSAMLFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrSAMLInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_saml_provider", "detail": err.Error()})
	case errors.Is(err, store.ErrSAMLEntityTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, store.ErrSAMLProviderUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider_not_found"})
	case errors.Is(err, store.ErrSAMLReleaseUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "release_not_found"})
	default:
		s.log.Error("writing a SAML provider", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
