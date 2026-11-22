package sms

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Policy bounds what text messages may cost.
//
// SMS is the one factor where an attacker can spend the operator's money. A
// number on a premium or high-cost range, enrolled from a signup form or
// challenged over and over, earns whoever leases that range a share of every
// message. That is SMS pumping, also called toll fraud, and the defences are a
// list of countries the deployment actually serves and a daily ceiling that
// turns a runaway bill into a refused message and an audit event.
type Policy struct {
	// prefixes are E.164 prefixes such as "+1" or "+44". Empty allows any.
	prefixes []string
	// NumberDaily is how many messages one number may be sent in a day.
	NumberDaily int
	// OrgDaily is how many messages one organisation may send in a day.
	OrgDaily int
}

const (
	defaultNumberDaily = 10
	defaultOrgDaily    = 1000
)

var prefixShape = regexp.MustCompile(`^\+[1-9][0-9]{0,6}$`)

// PolicyFromEnv reads SIGNARI_SMS_ALLOWED_PREFIXES,
// SIGNARI_SMS_NUMBER_DAILY_LIMIT and SIGNARI_SMS_ORG_DAILY_LIMIT. A malformed
// value is an error, not a default: a deployment that asked for a country list
// and silently got none would believe it was protected.
func PolicyFromEnv(getenv func(string) string) (Policy, error) {
	p := Policy{NumberDaily: defaultNumberDaily, OrgDaily: defaultOrgDaily}
	for _, raw := range strings.Split(getenv("SIGNARI_SMS_ALLOWED_PREFIXES"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !prefixShape.MatchString(raw) {
			return Policy{}, fmt.Errorf("SIGNARI_SMS_ALLOWED_PREFIXES: %q is not an E.164 "+
				"prefix such as +1 or +44", raw)
		}
		p.prefixes = append(p.prefixes, raw)
	}
	for _, v := range []struct {
		name string
		into *int
	}{
		{"SIGNARI_SMS_NUMBER_DAILY_LIMIT", &p.NumberDaily},
		{"SIGNARI_SMS_ORG_DAILY_LIMIT", &p.OrgDaily},
	} {
		raw := strings.TrimSpace(getenv(v.name))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return Policy{}, fmt.Errorf("%s must be a whole number of messages, at least 1 (got %q)",
				v.name, raw)
		}
		*v.into = n
	}
	return p, nil
}

// Restricted reports whether a country list is set.
func (p Policy) Restricted() bool { return len(p.prefixes) > 0 }

// Permits reports whether a normalised number is on the list. With no list,
// every number is permitted.
func (p Policy) Permits(number string) bool {
	if len(p.prefixes) == 0 {
		return true
	}
	for _, pre := range p.prefixes {
		if strings.HasPrefix(number, pre) {
			return true
		}
	}
	return false
}

// Limits returns the daily ceilings, with the defaults for a zero Policy.
func (p Policy) Limits() (number, org int) {
	number, org = p.NumberDaily, p.OrgDaily
	if number < 1 {
		number = defaultNumberDaily
	}
	if org < 1 {
		org = defaultOrgDaily
	}
	return number, org
}
