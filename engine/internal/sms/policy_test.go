package sms

import (
	"strings"
	"testing"
)

func TestTheSMSPolicyIsReadStrictly(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	p, err := PolicyFromEnv(env(nil))
	if err != nil || p.Restricted() || !p.Permits("+88212345678") {
		t.Fatalf("with nothing set every country should pass: %v %+v", err, p)
	}
	if n, o := p.Limits(); n != defaultNumberDaily || o != defaultOrgDaily {
		t.Fatalf("defaults are %d and %d", n, o)
	}

	p, err = PolicyFromEnv(env(map[string]string{"SIGNARI_SMS_ALLOWED_PREFIXES": "+1, +44"}))
	if err != nil {
		t.Fatal(err)
	}
	for number, want := range map[string]bool{
		"+14155550100": true, "+447700900123": true, "+88212345678": false, "+4915112345678": false,
	} {
		if p.Permits(number) != want {
			t.Errorf("Permits(%s) = %v, want %v", number, !want, want)
		}
	}

	for _, c := range []struct{ key, value, want string }{
		{"SIGNARI_SMS_ALLOWED_PREFIXES", "44", "not an E.164 prefix"},
		{"SIGNARI_SMS_ALLOWED_PREFIXES", "+0", "not an E.164 prefix"},
		{"SIGNARI_SMS_NUMBER_DAILY_LIMIT", "0", "at least 1"},
		{"SIGNARI_SMS_ORG_DAILY_LIMIT", "lots", "whole number"},
	} {
		if _, err := PolicyFromEnv(env(map[string]string{c.key: c.value})); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s=%q gave %v, want an error containing %q", c.key, c.value, err, c.want)
		}
	}
}
