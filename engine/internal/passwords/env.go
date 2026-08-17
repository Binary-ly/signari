package passwords

import (
	"os"
	"strconv"
	"time"
)

// PolicyFromEnv builds the password rules from the environment.
//
// It lives here rather than in any one caller because sign-up, recovery, the
// admin API and the CLI must all get the SAME policy. Reading the environment in
// four places is how one of them ends up with a different floor -- and the
// weakest of the four is the one that matters.
//
// Breach checking is OFF unless configured. A control that silently starts
// making outbound requests because a binary was upgraded is a surprise in a
// regulated environment, and the offline list exists precisely so that
// deployments which cannot call out still get the check.
func PolicyFromEnv() Policy {
	p := DefaultPolicy()
	if v := os.Getenv("SIGNARI_PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.MinLength = n
		}
	}
	if v := os.Getenv("SIGNARI_PASSWORD_HISTORY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			p.HistoryDepth = n
		}
	}
	online := os.Getenv("SIGNARI_PASSWORD_BREACH_CHECK") == "1"
	local := os.Getenv("SIGNARI_PASSWORD_BREACH_LIST")
	if online || local != "" {
		p.Breach = &BreachChecker{Online: online, LocalFile: local}
		p.BreachRequired = os.Getenv("SIGNARI_PASSWORD_BREACH_REQUIRED") == "1"
		if v := os.Getenv("SIGNARI_PASSWORD_BREACH_RECHECK_DAYS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				p.RecheckEvery = time.Duration(n) * 24 * time.Hour
			}
		}
	}
	return p
}
