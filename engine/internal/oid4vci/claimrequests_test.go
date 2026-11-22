package oid4vci

import (
	"encoding/json"
	"strings"
	"testing"

	"signari.dev/engine/internal/rar"
)

func asked(t *testing.T, raw string) []rar.ClaimDescription {
	t.Helper()
	var out []rar.ClaimDescription
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// What a wallet takes no credential without is what it marked mandatory, named as
// this format names its claims; a claim it may go without and the configuration does
// not carry is let go.
func TestTheMandatoryClaimsAreTheOnesTheWalletWillNotGoWithout(t *testing.T) {
	sd := Configuration{ID: "staff", Format: FormatSDJWTVC, AlwaysClaims: []string{"email"},
		SelectiveClaims: []string{"preferred_username"}}
	got, err := sd.MandatoryClaims(asked(t, `[{"path":["email"],"mandatory":true},{"path":["preferred_username"]},
		{"path":["nickname"]},{"path":["email"],"mandatory":false,"display":[{"name":"x"}]}]`))
	if err == nil {
		t.Fatalf("one claim described twice was taken: %v", got)
	}
	got, err = sd.MandatoryClaims(asked(t, `[{"path":["email"],"mandatory":true},{"path":["preferred_username"]},
		{"path":["nickname"]}]`))
	if err != nil || strings.Join(got, ",") != "email" {
		t.Errorf("answered %v, %v", got, err)
	}
	if got, err := sd.MandatoryClaims(nil); got != nil || err != nil {
		t.Errorf("no claims asked answered %v, %v", got, err)
	}

	jwt := Configuration{ID: "staff-jwt", Format: FormatJWTVC, AlwaysClaims: []string{"email"}}
	if got, err := jwt.MandatoryClaims(asked(t, `[{"path":["credentialSubject","email"],"mandatory":true}]`)); err != nil ||
		strings.Join(got, ",") != "email" {
		t.Errorf("a JWT VC's claim under credentialSubject answered %v, %v", got, err)
	}
	if _, err := jwt.MandatoryClaims(asked(t, `[{"path":["email"],"mandatory":true}]`)); err == nil {
		t.Error("a JWT VC's claim named as an SD-JWT VC's was taken as mandatory and carried")
	}
}

// Appendix B.3 aborts on what contradicts itself, and Appendix C says what a path is.
func TestAClaimsDescriptionThatContradictsItselfIsRefused(t *testing.T) {
	cfg := Configuration{ID: "staff", Format: FormatSDJWTVC, AlwaysClaims: []string{"email", "address", "degrees"}}
	for name, c := range map[string]struct{ raw, says string }{
		"an empty list":                 {`[]`, "non-empty"},
		"an empty path":                 {`[{"path":[]}]`, "non-empty"},
		"a negative index":              {`[{"path":["degrees",-1]}]`, "non-negative"},
		"a fraction":                    {`[{"path":["degrees",1.5]}]`, "non-negative"},
		"an object in the path":         {`[{"path":["degrees",{"a":1}]}]`, "not a key"},
		"one claim twice":               {`[{"path":["email"]},{"path":["email"],"mandatory":true}]`, "twice"},
		"an array whole and by index":   {`[{"path":["degrees",null]},{"path":["degrees",0]}]`, "whole and by an index"},
		"an array and an object at one": {`[{"path":["address",0]},{"path":["address","street"]}]`, "array and an object"},
		"a mandatory claim not carried": {`[{"path":["birthdate"],"mandatory":true}]`, "carries no such claim"},
	} {
		if _, err := cfg.MandatoryClaims(asked(t, c.raw)); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s answered %v, want it to say %q", name, err, c.says)
		}
	}
	// Two elements of one array, and two keys of one object, are two claims.
	if _, err := cfg.MandatoryClaims(asked(t, `[{"path":["degrees",0]},{"path":["degrees",1]},
		{"path":["address","street"]},{"path":["address","city"]}]`)); err != nil {
		t.Errorf("distinct claims were refused: %v", err)
	}
}
