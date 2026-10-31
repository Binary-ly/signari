package policy

import (
	"strings"
	"testing"
)

const conditionPolicy = `
version: 1
policies:
  - name: office-hours
    when: {client: ledger}
    require:
      time: {days: [mon, tue, wed, thu, fri], from: "09:00", to: "17:00", zone: Europe/London}
  - name: only-here
    when: {client: payroll}
    require:
      from_countries: [GB, IE]
  - name: not-there
    when: {client: wiki}
    require:
      not_from_countries: [KP]
  - name: keeps-its-record
    when: {client: mail}
    require:
      max_recent_failures: 5
tests:
  - name: a weekday morning in London
    given: {client: ledger, at: "2026-11-02T10:00:00Z"}
    expect: allow
  - name: the same hour on a Sunday
    given: {client: ledger, at: "2026-11-01T10:00:00Z"}
    expect: deny
  - name: after hours
    given: {client: ledger, at: "2026-11-02T18:00:00Z"}
    expect: deny
  - name: 09:30 in London in summer is 08:30 by the clock in UTC
    given: {client: ledger, at: "2026-07-06T08:30:00Z"}
    expect: allow
  - name: from a listed country
    given: {client: payroll, country: IE}
    expect: allow
  - name: from another
    given: {client: payroll, country: FR}
    expect: deny
  - name: from nowhere anything can place
    given: {client: payroll}
    expect: deny
  - name: from a refused country
    given: {client: wiki, country: KP}
    expect: deny
  - name: from anywhere else
    given: {client: wiki, country: FR}
    expect: allow
  - name: from somewhere nothing can place, which is no evidence against it
    given: {client: wiki}
    expect: allow
  - name: an address with a few failures
    given: {client: mail, recent_failures: 5}
    expect: allow
  - name: an address with more
    given: {client: mail, recent_failures: 6}
    expect: deny
`

// Each condition in the file's own tests, with no clock, database or GeoIP behind them,
// which is how a rule gets to deploy (11.09). Where somebody is cannot be known at a refresh,
// and on a grant nobody watched it is refused as every other where-from condition is, while
// the hours are the server's and hold for all of them.
func TestConditionsOnTimePlaceAndRecord(t *testing.T) {
	f, err := Parse([]byte(conditionPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !f.UsesCountries() || !f.UsesRecentFailures() {
		t.Error("the file does not say what it reads")
	}
	for _, c := range []struct {
		name string
		req  Request
		want bool
	}{
		{"a refresh, from a place that is not listed", Request{Client: "payroll", Refresh: true}, true},
		{"a grant nobody watched, for a listed place", Request{Client: "payroll", Unobserved: true}, false},
		{"a grant nobody watched, by its record", Request{Client: "mail", Unobserved: true}, false},
		{"a refresh after hours", Request{Client: "ledger", Refresh: true, At: "2026-11-02T18:00:00Z"}, false},
		{"a refresh in hours", Request{Client: "ledger", Refresh: true, At: "2026-11-02T10:00:00Z"}, true},
		{"a moment that does not parse", Request{Client: "ledger", At: "tuesday"}, false},
	} {
		if d := f.Evaluate(c.req); d.Allowed != c.want {
			t.Errorf("%s: allowed %v, want %v", c.name, d.Allowed, c.want)
		}
	}
}

// What could never match, or says nothing, does not load.
func TestConditionsThatCouldNeverMatchAreRefused(t *testing.T) {
	head := "version: 1\npolicies:\n  - name: r\n    require:\n      "
	tail := "\ntests:\n  - {name: t, given: {client: x}, expect: allow}\n"
	for _, c := range []struct{ name, condition, want string }{
		{"a lower-case code", "from_countries: [gb]", "ISO 3166"},
		{"a country's name", "not_from_countries: [Britain]", "ISO 3166"},
		{"hours in no zone", `time: {from: "09:00", to: "17:00"}`, "zone"},
		{"a zone that is not one", `time: {from: "09:00", to: "17:00", zone: Mars/Base}`, "IANA"},
		{"a day that is not one", "time: {days: [someday]}", "day"},
		{"a window of nothing", "time: {}", "restricts nothing"},
		{"a negative record", "max_recent_failures: -1", "max_recent_failures"},
	} {
		if _, err := Parse([]byte(head + c.condition + tail)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.want)
		}
	}
}
