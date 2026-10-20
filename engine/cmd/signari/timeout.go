package main

import (
	"context"
	"time"
)

// defaultCommandTimeout bounds a command that edits configuration. Such a
// command touches a handful of rows, so a minute is generous, and a command
// stuck behind a lock should fail rather than hang a deploy script.
var defaultCommandTimeout = 60 * time.Second

// unboundedCommands run with no deadline unless -timeout gives one, because
// their work grows with the data. Every command used to share the 60-second
// deadline above, which cancelled an audit export of a large trail, a
// migration building an index on a large table and a migration waiting its
// turn behind another, partway through. Each entry says what grows.
var unboundedCommands = map[string]string{
	"serve":             "runs until it is stopped",
	"migrate bootstrap": "waits for another migrate to finish; its statements are bounded by -lock-timeout and -statement-timeout",
	"migrate up":        "builds indexes on tables of any size and waits for another migrate to finish",
	"migrate all":       "both of the above",
	"export audit":      "verifies and writes the whole audit trail",
	"audit checkpoint":  "verifies the whole audit trail before declaring the restart point",
	"import authentik":  "imports every user in the export file",
	"import keycloak":   "imports every user in the export file",
	"dir sync":          "reads every person in the directory",
	"scim sync":         "pushes every person to the downstream application, one request each",
	"kerberos sync":     "reads every principal in the realm",
	"keys rewrap-root":  "reseals every sealed value in the database",
	"janitor once":      "sweeps every expired row",
}

// commandTimeout is how long cmd may run: what -timeout said when it was given
// (0 for no limit), otherwise the command's own default.
func commandTimeout(cmd string, given time.Duration, wasGiven bool) time.Duration {
	if wasGiven {
		return given
	}
	if _, ok := unboundedCommands[cmd]; ok {
		return 0
	}
	if cmd == "proxy check" {
		// It probes an application from outside, retrying through redirects
		// and slow upstreams, and has always been allowed five minutes.
		return 5 * time.Minute
	}
	return defaultCommandTimeout
}

// commandContext is the context a command runs under: cancelled after d, or
// never when d is 0.
func commandContext(d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), d)
}
