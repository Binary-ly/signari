package main

import (
	"fmt"
	"strconv"
	"time"

	"signari.dev/engine/internal/store"
)

// retentionFromEnv reads how long the janitor keeps rows nothing reads any
// more (3.17): SIGNARI_RETENTION_* as Go durations, each at least an hour so a
// typo cannot empty a table at the next pass, and the password history depth
// from SIGNARI_PASSWORD_HISTORY, the depth the reuse check reads.
func retentionFromEnv(getenv func(string) string) (store.Retention, error) {
	r := store.DefaultRetention()
	for _, s := range []struct {
		name string
		into *time.Duration
	}{
		{"SIGNARI_RETENTION_SESSIONS", &r.Sessions},
		{"SIGNARI_RETENTION_REFRESH_FAMILIES", &r.Families},
		{"SIGNARI_RETENTION_DELIVERED", &r.Delivered},
		{"SIGNARI_RETENTION_RECEIVED_EVENTS", &r.Received},
		{"SIGNARI_RETENTION_SIGNIN_LOCATIONS", &r.Locations},
		{"SIGNARI_RETENTION_CREDENTIAL_NONCES", &r.Nonces},
	} {
		v := getenv(s.name)
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Hour {
			return r, fmt.Errorf("%s=%q: want a duration of at least 1h, such as 720h", s.name, v)
		}
		*s.into = d
	}
	if v := getenv("SIGNARI_PASSWORD_HISTORY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			r.PasswordHistory = n
		}
	}
	return r, nil
}
