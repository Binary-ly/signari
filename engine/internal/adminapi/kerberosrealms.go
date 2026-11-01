package adminapi

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// An organisation's own Kerberos realms, as `signari kerberos add-realm` keeps them
// (8.10). A keytab comes in once and never goes out.

const kerberosRealmRefusal = "change an organisation's Kerberos realms"

func (s *Server) listKerberosRealms(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("orgID")
	list, err := store.KerberosRealms(r.Context(), s.db, orgID)
	if err != nil {
		s.log.Error("listing Kerberos realms", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"realms": list})
}

type addKerberosRealmRequest struct {
	Realm            string `json:"realm"`
	Host             string `json:"host"`
	ServicePrincipal string `json:"service_principal"`
	// Keytab is the file, base64.
	Keytab     string `json:"keytab"`
	StripRealm bool   `json:"strip_realm"`
	// TrustedRealms are the other realms whose people may sign in here.
	TrustedRealms []string `json:"trusted_realms,omitempty"`
	// CreateAccounts makes an account for a good ticket with none.
	CreateAccounts bool `json:"create_accounts,omitempty"`
}

func (s *Server) addKerberosRealm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addKerberosRealmRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	keytab, err := base64.StdEncoding.DecodeString(req.Keytab)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_kerberos_realm",
			"detail": "the keytab is the file, in base64"})
		return
	}
	if narrowedTokenRefused(w, r, kerberosRealmRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var realm store.KerberosRealm
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var err error
		realm, err = store.AddKerberosRealm(ctx, tx, s.root, orgID, store.KerberosRealmSpec{Realm: req.Realm, Host: req.Host,
			ServicePrincipal: req.ServicePrincipal, Keytab: keytab, StripRealm: req.StripRealm,
			TrustedRealms: req.TrustedRealms, CreateAccounts: req.CreateAccounts})
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.kerberos_realm_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"realm": realm.Realm, "host": realm.Host}})
	})
	if s.writeKerberosRealmFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": realm.ID, "realm": realm.Realm, "host": realm.Host,
		"service_principal": realm.ServicePrincipal, "strip_realm": realm.StripRealm,
		"trusted_realms": realm.TrustedRealms, "create_accounts": realm.CreateAccounts, "created_at": realm.CreatedAt,
		"config_version": version})
}

func (s *Server) removeKerberosRealm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID, realm := r.PathValue("orgID"), r.PathValue("realm")
	if narrowedTokenRefused(w, r, kerberosRealmRefusal) {
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
		if _, err := store.RemoveKerberosRealm(ctx, tx, orgID, realm); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.kerberos_realm_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"realm": realm}})
	})
	if s.writeKerberosRealmFailure(w, err, orgID) {
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"removed": realm, "config_version": version})
}

func (s *Server) writeKerberosRealmFailure(w http.ResponseWriter, err error, orgID string) bool {
	switch {
	case err == nil:
		return false
	case writePreconditionFailure(w, err):
	case writeOrgRefusal(w, err):
	case errors.Is(err, store.ErrKerberosRealm):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_kerberos_realm", "detail": err.Error()})
	case errors.Is(err, store.ErrKerberosRealmTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
	case errors.Is(err, store.ErrKerberosRealmUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
	default:
		s.log.Error("writing a Kerberos realm", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
	return true
}
