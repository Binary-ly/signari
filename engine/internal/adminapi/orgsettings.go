package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/store"
)

// An organisation's sign-in and session policy (6.07): what the `signari
// instance` commands for one organisation set, read and changed together. Each
// field present in a PATCH goes through the setter its command uses, with the
// same bounds, and is recorded with the same event, so the trail reads alike
// whichever way it was changed.

type orgSettingsView struct {
	OrgID                 string `json:"org_id"`
	MaxConcurrentSessions int    `json:"max_concurrent_sessions"`
	SessionLimitBehaviour string `json:"session_limit_behaviour"`
	PasswordOnlyBinds     string `json:"password_only_binds"`
	RememberDeviceDays    int    `json:"remember_device_days"`
	NewDeviceNotice       bool   `json:"new_device_notice"`
	ReauthWindowS         int    `json:"reauth_window_s"`
	SessionLifetimeS      int    `json:"session_lifetime_s"`
	// SessionIdleS is 0 when an unused session is not ended early.
	SessionIdleS       int    `json:"session_idle_s"`
	OfflineLifetimeS   int    `json:"offline_lifetime_s"`
	PersistentSessions bool   `json:"persistent_sessions"`
	SMSNumbers         string `json:"sms_numbers"`
	TOTPAlgorithm      string `json:"totp_algorithm"`
	TOTPDigits         int    `json:"totp_digits"`
	TOTPPeriodS        int    `json:"totp_period_s"`
	LoginFreeAttempts  int    `json:"login_free_attempts"`
	LoginMaxDelayS     int    `json:"login_max_delay_s"`
}

func viewOrgSettings(orgID string, s store.OrgSettings) orgSettingsView {
	sms := "stored"
	if s.SMSNumbersHashed {
		sms = "hashed"
	}
	return orgSettingsView{OrgID: orgID, MaxConcurrentSessions: s.MaxConcurrentSessions,
		SessionLimitBehaviour: s.SessionLimitBehaviour, PasswordOnlyBinds: s.PasswordOnlyBinds,
		RememberDeviceDays: s.RememberDeviceDays, NewDeviceNotice: s.NewDeviceNotice,
		ReauthWindowS:    seconds(s.ReauthWindow),
		SessionLifetimeS: seconds(s.Sessions.Lifetime), SessionIdleS: seconds(s.Sessions.Idle),
		OfflineLifetimeS: seconds(s.Sessions.Offline), PersistentSessions: s.Sessions.Persistent,
		SMSNumbers: sms, TOTPAlgorithm: s.TOTP.Algorithm, TOTPDigits: s.TOTP.Digits,
		TOTPPeriodS: seconds(s.TOTP.Period), LoginFreeAttempts: s.LoginFreeAttempts,
		LoginMaxDelayS: seconds(s.LoginMaxDelay)}
}

func seconds(d time.Duration) int { return int(d / time.Second) }

func secondsOf(n int) time.Duration { return time.Duration(n) * time.Second }

// patchOrgSettingsRequest changes the settings present and leaves the rest.
type patchOrgSettingsRequest struct {
	MaxConcurrentSessions *int    `json:"max_concurrent_sessions"`
	SessionLimitBehaviour *string `json:"session_limit_behaviour"`
	PasswordOnlyBinds     *string `json:"password_only_binds"`
	RememberDeviceDays    *int    `json:"remember_device_days"`
	NewDeviceNotice       *bool   `json:"new_device_notice"`
	ReauthWindowS         *int    `json:"reauth_window_s"`
	SessionLifetimeS      *int    `json:"session_lifetime_s"`
	SessionIdleS          *int    `json:"session_idle_s"`
	OfflineLifetimeS      *int    `json:"offline_lifetime_s"`
	PersistentSessions    *bool   `json:"persistent_sessions"`
	SMSNumbers            *string `json:"sms_numbers"`
	TOTPAlgorithm         *string `json:"totp_algorithm"`
	TOTPDigits            *int    `json:"totp_digits"`
	TOTPPeriodS           *int    `json:"totp_period_s"`
	LoginFreeAttempts     *int    `json:"login_free_attempts"`
	LoginMaxDelayS        *int    `json:"login_max_delay_s"`
}

// errInvalidSetting carries a setter's own refusal to the caller as a 400.
type errInvalidSetting struct{ err error }

func (e errInvalidSetting) Error() string { return e.err.Error() }

// settingRefusals are the setters' refusals of a value out of bounds.
var settingRefusals = []error{store.ErrSessionLimit, store.ErrPasswordBinds, store.ErrRememberDeviceDays,
	store.ErrReauthWindow, store.ErrSessionLifetime, store.ErrOfflineLifetime, store.ErrLoginThrottle}

func invalidSetting(err error) error {
	for _, r := range settingRefusals {
		if errors.Is(err, r) {
			return errInvalidSetting{err}
		}
	}
	return err
}

func (s *Server) getOrgSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.OrgSettingsOf(ctx, s.db, orgID)
	switch {
	case errors.Is(err, store.ErrOrganizationNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization_not_found"})
		return
	case err != nil:
		s.log.Error("reading an organisation's settings", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, viewOrgSettings(orgID, got))
}

func (s *Server) patchOrgSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req patchOrgSettingsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var after store.OrgSettings
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := s.applyOrgSettings(ctx, tx, orgID, req); err != nil {
			return invalidSetting(err)
		}
		var err error
		after, err = store.OrgSettingsOf(ctx, tx, orgID)
		return err
	})
	var invalid errInvalidSetting
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_setting", "detail": invalid.Error()})
		return
	case err != nil:
		s.log.Error("changing an organisation's settings", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, struct {
		orgSettingsView
		ConfigVersion int64 `json:"config_version"`
	}{viewOrgSettings(orgID, after), version})
}

// applyOrgSettings makes each change the request asks for, as its command
// does, and records each.
func (s *Server) applyOrgSettings(ctx context.Context, tx pgx.Tx, orgID string, req patchOrgSettingsRequest) error {
	cur, err := store.OrgSettingsOf(ctx, tx, orgID)
	if err != nil {
		return err
	}
	// Each event's type is written where it is built, so the registry's guard
	// can read it.
	record := func(e audit.Event) error {
		e.AdminTokenID, e.OrgID = TokenIDFrom(ctx), orgID
		e.Detail["via"] = "admin_api"
		return audit.Write(ctx, tx, e)
	}

	if req.MaxConcurrentSessions != nil || req.SessionLimitBehaviour != nil {
		max, behaviour := pick(req.MaxConcurrentSessions, cur.MaxConcurrentSessions),
			pick(req.SessionLimitBehaviour, cur.SessionLimitBehaviour)
		wasMax, was, err := store.SetSessionLimit(ctx, tx, orgID, max, behaviour)
		if err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.session_limit_set", Detail: map[string]any{"max_from": wasMax,
			"max_to": max, "behaviour_from": was, "behaviour_to": behaviour}}); err != nil {
			return err
		}
	}
	if req.PasswordOnlyBinds != nil {
		was, err := store.SetPasswordBinds(ctx, tx, orgID, *req.PasswordOnlyBinds)
		if err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.password_only_binds_set",
			Detail: map[string]any{"from": was, "to": *req.PasswordOnlyBinds}}); err != nil {
			return err
		}
	}
	if req.RememberDeviceDays != nil {
		was, err := store.SetRememberDeviceDays(ctx, tx, orgID, *req.RememberDeviceDays)
		if err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.remember_device_set",
			Detail: map[string]any{"from_days": was, "to_days": *req.RememberDeviceDays}}); err != nil {
			return err
		}
	}
	if req.NewDeviceNotice != nil {
		was, err := store.SetNewDeviceNotice(ctx, tx, orgID, *req.NewDeviceNotice)
		if err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.new_device_notice_set",
			Detail: map[string]any{"from": was, "to": *req.NewDeviceNotice}}); err != nil {
			return err
		}
	}
	if req.ReauthWindowS != nil {
		was, err := store.SetReauthWindow(ctx, tx, orgID, secondsOf(*req.ReauthWindowS))
		if err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.reauth_window_set",
			Detail: map[string]any{"from_s": seconds(was), "to_s": *req.ReauthWindowS}}); err != nil {
			return err
		}
	}
	if req.SessionLifetimeS != nil || req.SessionIdleS != nil || req.OfflineLifetimeS != nil || req.PersistentSessions != nil {
		// All four together, as `instance session-lifetime` sets them.
		lifetime := secondsOf(pick(req.SessionLifetimeS, seconds(cur.Sessions.Lifetime)))
		idle := secondsOf(pick(req.SessionIdleS, seconds(cur.Sessions.Idle)))
		offline := secondsOf(pick(req.OfflineLifetimeS, seconds(cur.Sessions.Offline)))
		stay := pick(req.PersistentSessions, cur.Sessions.Persistent)
		was, sooner, ended, err := store.SetSessionLifetimes(ctx, tx, orgID, lifetime, idle)
		if err != nil {
			return err
		}
		_, grantsSooner, err := store.SetOfflineLifetime(ctx, tx, orgID, offline)
		if err != nil {
			return err
		}
		if _, err := store.SetPersistentSessions(ctx, tx, orgID, stay); err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.session_lifetime_set", Detail: map[string]any{
			"lifetime_from_s": seconds(was.Lifetime), "lifetime_to_s": seconds(lifetime),
			"idle_from_s": seconds(was.Idle), "idle_to_s": seconds(idle),
			"offline_from_s": seconds(was.Offline), "offline_to_s": seconds(offline),
			"persistent_from": was.Persistent, "persistent_to": stay,
			"sessions_sooner": sooner, "sessions_ended": ended, "offline_grants_sooner": grantsSooner,
		}}); err != nil {
			return err
		}
	}
	if req.SMSNumbers != nil {
		mode := *req.SMSNumbers
		if mode != "stored" && mode != "hashed" {
			return errInvalidSetting{errors.New("sms_numbers is stored or hashed")}
		}
		if err := store.SetSMSNumbers(ctx, tx, orgID, mode == "hashed"); err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.sms_numbers_set",
			Detail: map[string]any{"sms_numbers": mode}}); err != nil {
			return err
		}
	}
	if req.TOTPAlgorithm != nil || req.TOTPDigits != nil || req.TOTPPeriodS != nil {
		p := mfa.Params{Algorithm: mfa.Algorithm(pick(req.TOTPAlgorithm, cur.TOTP.Algorithm)),
			Digits: pick(req.TOTPDigits, cur.TOTP.Digits),
			Period: secondsOf(pick(req.TOTPPeriodS, seconds(cur.TOTP.Period)))}
		if err := p.Check(); err != nil {
			return errInvalidSetting{err}
		}
		if err := store.SetTOTPPolicy(ctx, tx, orgID, store.TOTPPolicy{Algorithm: string(p.Algorithm),
			Digits: p.Digits, Period: p.Period}); err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.totp_policy_set", Detail: map[string]any{
			"algorithm": string(p.Algorithm), "digits": p.Digits, "period_s": seconds(p.Period)}}); err != nil {
			return err
		}
	}
	if req.LoginFreeAttempts != nil || req.LoginMaxDelayS != nil {
		free, delay := pick(req.LoginFreeAttempts, cur.LoginFreeAttempts), pick(req.LoginMaxDelayS, seconds(cur.LoginMaxDelay))
		// Zero is the setter's "leave as it is", which a caller naming it did
		// not mean: both are bounded above it.
		if free == 0 || delay == 0 {
			return store.ErrLoginThrottle
		}
		if err := store.SetLoginThrottle(ctx, tx, orgID, free, secondsOf(delay)); err != nil {
			return err
		}
		if err := record(audit.Event{Type: "org.login_throttle_set",
			Detail: map[string]any{"free_attempts": free, "max_delay_s": delay}}); err != nil {
			return err
		}
	}
	return nil
}

// pick is the value asked for, or what is there.
func pick[T any](asked *T, current T) T {
	if asked != nil {
		return *asked
	}
	return current
}
