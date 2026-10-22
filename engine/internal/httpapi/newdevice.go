package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Telling a person their account was signed in to from a new device (5.21).
//
// A device here is a browser on a system, "Firefox on Windows", read from the
// User-Agent and nothing finer: the version is left out, or every browser
// update would be a new device, and an address is left out, or every train
// journey would. The sign-in is new when none of the person's sessions of the
// last 90 days was the same, counted before this one is written. A person's
// first sign-in in that time is not news, having nothing to differ from, and
// neither is one on a device they told the second-factor page to remember.
// It is a notice, not a gate: what the person does with it is theirs.

// newDeviceWindow is how far back a device counts as known.
const newDeviceWindow = 90 * 24 * time.Hour

// deviceFamily names the browser and system a User-Agent describes, or ""
// when it names neither. Order matters: Edge and Opera say Chrome, Chrome says
// Safari, and iOS says Mac OS X.
func deviceFamily(ua string) string {
	if ua == "" {
		return ""
	}
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgiOS/") || strings.Contains(ua, "EdgA/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/") || strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/") || strings.Contains(ua, "Chromium/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	system := ""
	switch {
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod"):
		system = "iOS"
	case strings.Contains(ua, "Android"):
		system = "Android"
	case strings.Contains(ua, "CrOS"):
		system = "ChromeOS"
	case strings.Contains(ua, "Windows"):
		system = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		system = "macOS"
	case strings.Contains(ua, "Linux"):
		system = "Linux"
	}
	switch {
	case browser == "" && system == "":
		return ""
	case browser == "":
		return "a browser on " + system
	case system == "":
		return browser
	}
	return browser + " on " + system
}

// newDeviceSignIn reports the device this sign-in came from, and whether it is
// one to tell the person about, read in the sign-in's transaction before its
// session is written.
func (s *Server) newDeviceSignIn(ctx context.Context, r *http.Request, tx pgx.Tx, userID, orgID string) (string, bool) {
	family := deviceFamily(r.UserAgent())
	if family == "" {
		return "", false
	}
	var on bool
	if err := tx.QueryRow(ctx, `SELECT new_device_notice FROM core.organizations WHERE id = $1::uuid`,
		orgID).Scan(&on); err != nil || !on {
		return family, false
	}
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT user_agent FROM core.sessions
		 WHERE user_id = $1::uuid AND created_at > now() - make_interval(secs => $2)
		   -- Sessions from before user agents were kept (2.28) say nothing.
		   AND user_agent IS NOT NULL AND user_agent <> ''
		 LIMIT 500`, userID, int(newDeviceWindow.Seconds()))
	if err != nil {
		s.log.Error("reading the devices a person has signed in from", "err", err)
		return family, false
	}
	seen, known := 0, false
	for rows.Next() {
		var ua string
		if rows.Scan(&ua) == nil {
			seen++
			known = known || deviceFamily(ua) == family
		}
	}
	rows.Close()
	if seen == 0 || known {
		return family, false
	}
	return family, !s.deviceRemembered(ctx, r, tx, orgID, userID)
}
