package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// OrgSettings is an organisation's sign-in and session policy: each field one
// an `instance` command sets, read together for the Admin API (6.07).
type OrgSettings struct {
	MaxConcurrentSessions int
	SessionLimitBehaviour string
	PasswordOnlyBinds     string
	RememberDeviceDays    int
	NewDeviceNotice       bool
	ReauthWindow          time.Duration
	Sessions              SessionLifetimes
	SMSNumbersHashed      bool
	TOTP                  TOTPPolicy
	LoginFreeAttempts     int
	LoginMaxDelay         time.Duration
}

// OrgSettingsOf reads an organisation's settings in one statement.
func OrgSettingsOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (OrgSettings, error) {
	var s OrgSettings
	var reauth, lifetime, offline, period, maxDelay int
	var idle *int
	var sms string
	err := q.QueryRow(ctx, `
		SELECT max_concurrent_sessions, session_limit_behaviour, password_only_binds,
		       remember_device_days, new_device_notice, reauth_window_s,
		       session_lifetime_s, session_idle_s, offline_lifetime_s, persistent_sessions,
		       sms_numbers, totp_algorithm, totp_digits, totp_period_s,
		       login_free_attempts, login_max_delay_s
		  FROM core.organizations WHERE id = $1::uuid`, orgID).
		Scan(&s.MaxConcurrentSessions, &s.SessionLimitBehaviour, &s.PasswordOnlyBinds,
			&s.RememberDeviceDays, &s.NewDeviceNotice, &reauth,
			&lifetime, &idle, &offline, &s.Sessions.Persistent,
			&sms, &s.TOTP.Algorithm, &s.TOTP.Digits, &period,
			&s.LoginFreeAttempts, &maxDelay)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrgSettings{}, ErrOrganizationNotFound
	}
	if err != nil {
		return OrgSettings{}, fmt.Errorf("reading the organisation's settings: %w", err)
	}
	s.ReauthWindow = time.Duration(reauth) * time.Second
	s.Sessions.Lifetime = time.Duration(lifetime) * time.Second
	s.Sessions.Offline = time.Duration(offline) * time.Second
	if idle != nil {
		s.Sessions.Idle = time.Duration(*idle) * time.Second
	}
	s.SMSNumbersHashed = sms == "hashed"
	s.TOTP.Period = time.Duration(period) * time.Second
	s.LoginMaxDelay = time.Duration(maxDelay) * time.Second
	return s, nil
}

// The ways a sign-in past the session limit is answered.
const (
	SessionLimitDeny        = "deny"
	SessionLimitEvictOldest = "evict_oldest"
)

// ErrSessionLimit is a limit below zero or a behaviour that is neither.
var ErrSessionLimit = errors.New("the session limit is 0 (none) or more, and a sign-in past it is " +
	SessionLimitDeny + " or " + SessionLimitEvictOldest)

// SetSessionLimit bounds how many sessions one person may hold at once, 0 for
// none, and says what a sign-in past it does; it returns the limit and
// behaviour it replaced.
func SetSessionLimit(ctx context.Context, tx pgx.Tx, orgID string, max int, behaviour string) (int, string, error) {
	if max < 0 || (behaviour != SessionLimitDeny && behaviour != SessionLimitEvictOldest) {
		return 0, "", ErrSessionLimit
	}
	var wasMax int
	var was string
	err := tx.QueryRow(ctx, `SELECT max_concurrent_sessions, session_limit_behaviour
		FROM core.organizations WHERE id = $1::uuid FOR UPDATE`, orgID).Scan(&wasMax, &was)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", ErrOrganizationNotFound
	}
	if err != nil {
		return 0, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations
		SET max_concurrent_sessions = $2, session_limit_behaviour = $3 WHERE id = $1::uuid`,
		orgID, max, behaviour); err != nil {
		return 0, "", err
	}
	return wasMax, was, nil
}

// ErrPasswordBinds is a password-binds policy that is neither.
var ErrPasswordBinds = fmt.Errorf("password binds are %s or %s", PasswordBindsAllow, PasswordBindsRefuseWhenMFA)

// SetPasswordBinds decides whether the protocols that carry only a password
// may sign in somebody the sign-in flow would ask for a second factor (0128),
// and returns the policy it replaced.
func SetPasswordBinds(ctx context.Context, tx pgx.Tx, orgID, policy string) (string, error) {
	if policy != PasswordBindsAllow && policy != PasswordBindsRefuseWhenMFA {
		return "", ErrPasswordBinds
	}
	var was string
	err := tx.QueryRow(ctx, `SELECT password_only_binds FROM core.organizations
		WHERE id = $1::uuid FOR UPDATE`, orgID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrOrganizationNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET password_only_binds = $2
		WHERE id = $1::uuid`, orgID, policy); err != nil {
		return "", err
	}
	return was, nil
}

// SetNewDeviceNotice turns on or off the mail a sign-in from a new device
// sends its person (0187), and returns what it replaced.
func SetNewDeviceNotice(ctx context.Context, tx pgx.Tx, orgID string, on bool) (bool, error) {
	var was bool
	err := tx.QueryRow(ctx, `SELECT new_device_notice FROM core.organizations
		WHERE id = $1::uuid FOR UPDATE`, orgID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrOrganizationNotFound
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.organizations SET new_device_notice = $2
		WHERE id = $1::uuid`, orgID, on); err != nil {
		return false, err
	}
	return was, nil
}
