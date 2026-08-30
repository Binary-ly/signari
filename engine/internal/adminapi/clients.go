package adminapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
)

// Client administration.
//
// One rule governs both endpoints here: THE SECRET IS RETURNED EXACTLY ONCE.
// Only a hash is stored, so there is no second chance to read it -- the same
// property as recovery codes, and for the same reason. A console that can show
// an operator a client secret again can show it to whoever reads the database.

type createClientRequest struct {
	ClientID     string   `json:"client_id"`
	DisplayName  string   `json:"display_name"`
	OrgID        string   `json:"org_id"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirect_uris"`
	// Secret may be supplied to import an application's EXISTING credential, so
	// migrating it needs no change on their side. Left empty, one is generated.
	Secret string `json:"secret"`
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" || req.OrgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "detail": "client_id and org_id are required",
		})
		return
	}
	if err := clients.ValidateClientID(req.ClientID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "detail": err.Error(),
		})
		return
	}
	// The organisation boundary, at the point the org is chosen.
	if err := requireOrg(r.Context(), req.OrgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.ClientID
	}
	if len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "redirect_uri_required",
			"detail": "a client with no registered redirect_uri can never complete a " +
				"flow, so registering one now beats discovering it during an integration",
		})
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_redirect_uri", "detail": err.Error(),
			})
			return
		}
	}

	// A public client authenticates with PKCE, not a secret. Issuing one would be
	// a secret embedded in a distributable binary, which is a secret in name only.
	var plaintext, hash string
	if !req.Public {
		plaintext = req.Secret
		if plaintext == "" {
			b := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, b); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
				return
			}
			plaintext = base64.RawURLEncoding.EncodeToString(b)
		}
		h, ok := clients.HashSecret(plaintext)
		var err error
		if !ok {
			h, err = s.hasher.Hash(ctx, plaintext)
		}
		if err != nil {
			s.log.Error("hashing client secret", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		hash = h
	}

	kind := "confidential"
	if req.Public {
		kind = "public"
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, enabled, grant_types, scopes,
			                          require_pkce)
			VALUES ($1, $2::uuid, $3, $4, $5, true,
			        ARRAY['authorization_code','refresh_token'],
			        ARRAY['openid','profile','email'], $6)`,
			req.ClientID, req.OrgID, req.DisplayName, kind, hash, req.Public); err != nil {
			return err
		}
		for _, u := range req.RedirectURIs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
				req.ClientID, u); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.client_created", AdminTokenID: TokenIDFrom(ctx), OrgID: req.OrgID, ClientID: req.ClientID,
			Detail: map[string]any{"type": kind, "imported_secret": req.Secret != ""},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case err != nil && strings.Contains(err.Error(), "clients_pkey"):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "already_exists", "detail": "a client with that id already exists",
		})
		return
	case err != nil:
		s.log.Error("creating client", "client_id", req.ClientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)

	s.log.Info("client created", "client_id", req.ClientID, "type", kind, "config_version", version)

	resp := map[string]any{"client_id": req.ClientID, "type": kind, "config_version": version}
	if plaintext != "" {
		resp["client_secret"] = plaintext
		// Said in the response, because an operator who does not copy it now has
		// to rotate it, and nothing else will tell them that.
		resp["notice"] = "This secret is shown once and is not recoverable. Copy it now."
	}
	writeJSON(w, http.StatusCreated, resp)
}

// rotateClientSecret issues a new secret and invalidates the old one.
//
// IMMEDIATELY, with no grace period. Rotation is what you do when a secret has
// leaked, and an overlap window during which the leaked value still works is
// precisely the thing you were trying to end. A planned rotation with no
// downtime is done by registering a second client and migrating traffic.
func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	plaintext := base64.RawURLEncoding.EncodeToString(b)
	hash, ok := clients.HashSecret(plaintext)
	var err error
	if !ok {
		hash, err = s.hasher.Hash(ctx, plaintext)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}

	var orgID, kind string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text, client_type FROM core.clients WHERE client_id = $1`,
			clientID).Scan(&orgID, &kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		// Checked against the row we are about to modify, inside the same
		// transaction that will modify it.
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}
		if kind != "confidential" {
			// A public client has no secret to rotate, and pretending otherwise
			// would hand an operator a value that authenticates nothing.
			return fmt.Errorf("client %s is public and has no secret", clientID)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE core.clients SET client_secret_hash = $2, updated_at = now() WHERE client_id = $1`,
			clientID, hash); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.client_secret_rotated", AdminTokenID: TokenIDFrom(ctx), OrgID: orgID, ClientID: clientID,
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case err != nil && strings.Contains(err.Error(), "is public"):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "public_client", "detail": err.Error(),
		})
		return
	case err != nil:
		s.log.Error("rotating client secret", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)

	s.log.Warn("client secret rotated; the previous secret stopped working immediately",
		"client_id", clientID, "config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"client_id": clientID, "client_secret": plaintext, "config_version": version,
		"notice": "The previous secret stopped working immediately. This one is shown once.",
	})
}

// validateRedirectURI enforces what the authorization endpoint will later demand.
//
// Checked at REGISTRATION rather than only at use, because a redirect that can
// never match is a client that appears configured and fails at the worst moment
// -- during someone else's integration, with an error that names the request
// rather than the registration.
// validateRedirectURI delegates to the one shared validator.
//
// It used to have its own copy, which was good but not identical to the CLI's
// or to dynamic registration's -- and dynamic registration, being open to
// anybody, had none at all.
func validateRedirectURI(raw string) error {
	return clients.ValidateRedirectURI(raw)
}

// deleteClient removes a client and everything issued to it.
//
// # Why this needed to exist
//
// There was no way to remove a client over any HTTP surface. Every competitor
// has one, and the absence had a second cost here: the Terraform provider's
// destroy could only DISABLE a client and warn that the row remained, so
// `terraform destroy` left state behind that Terraform believed it had removed.
//
// # Real deletion, and why that is safe here
//
// ADR-005 refuses soft deletes: a `deleted_at` column means every hot-path query
// must remember `AND deleted_at IS NULL`, and forgetting once authenticates
// against a client somebody deleted. Every foreign key pointing at core.clients
// is ON DELETE CASCADE -- nineteen of them, covering codes, tokens, refresh
// families, consents, pushed requests, device authorisations, UMA tickets and
// SSF streams -- so the row and everything issued under it go together.
//
// core.audit_events carries client_id WITHOUT a foreign key, deliberately, so
// the trail describing a client outlives the client. Deleting one does not erase
// the record that it existed or what was done with it.
func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}

	var sessions, tokens int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.clients WHERE client_id = $1`, clientID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}

		// Counted before the cascade, for the audit record. "How much was revoked"
		// is asked afterwards, and the rows are gone by then.
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM core.access_tokens WHERE client_id = $1`,
			clientID).Scan(&tokens); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM core.session_clients WHERE client_id = $1`,
			clientID).Scan(&sessions); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM core.clients WHERE client_id = $1`, clientID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.client_deleted", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID,
			Detail: map[string]any{
				"tokens_revoked":   tokens,
				"sessions_touched": sessions,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case err != nil:
		s.log.Error("deleting a client", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{
		"client_id":      clientID,
		"tokens_revoked": tokens,
		"config_version": version,
	})
}
