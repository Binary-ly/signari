package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RFC 7644 §3.4.2.2, of the filter grammar: "the `compValue` (comparison value)
// rule is built on JSON Data Interchange format ABNF rules as specified in
// [RFC7159]".
//
// A JSON string, not a Go one. This was built with fmt.Sprintf("%q"), which
// agrees with JSON on the cases that matter for injection -- a quote becomes \"
// and a backslash \\ either way, so a crafted userName could never break out of
// the literal -- and disagrees on control characters, where Go emits escapes
// JSON does not define (\a, \v, \x01 against , , ).
//
// The result was a filter the target is right to reject, on a path whose whole
// job is recovering from a 409 so an existing remote account gets recorded. A
// failure there leaves an account we provisioned but did not record -- which is
// exactly the account deprovisioning will later fail to find.
func TestTheUserNameFilterIsAValidJSONString(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("filter")
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],` +
			`"totalResults":0,"Resources":[]}`))
	}))
	defer srv.Close()

	c := NewClient(Target{BaseURL: srv.URL, Token: "t"}, srv.Client())

	for _, name := range []string{
		"alice@example.com",
		`quote"name`,
		`back\slash`,
		"bell\aname",   // 0x07 — Go writes \a, for which JSON has no escape
		"vtab\vname",   // 0x0B — likewise \v
		"ctrl\x01name", // Go writes \x01; JSON requires 
		"tab\tname",    // both write \t, so this must keep working
		"nl\nname",
	} {
		if _, err := c.FindByUserName(context.Background(), name); err != nil {
			t.Fatalf("%q: %v", name, err)
		}

		const prefix = "userName eq "
		if !strings.HasPrefix(got, prefix) {
			t.Fatalf("filter = %q, want it to start with %q", got, prefix)
		}
		literal := strings.TrimPrefix(got, prefix)

		// The comparison value must parse as a JSON string...
		var back string
		if err := json.Unmarshal([]byte(literal), &back); err != nil {
			t.Errorf("for userName %q the comparison value %s is not a valid "+
				"JSON string: %v\nRFC 7644 §3.4.2.2 builds compValue on the "+
				"JSON grammar, so a target is right to reject this filter.",
				name, literal, err)
			continue
		}
		// ...and mean exactly what we asked for.
		if back != name {
			t.Errorf("the comparison value round-tripped to %q, want %q", back, name)
		}
	}
}

// Not an injection, and worth pinning so nobody "fixes" it by adding escaping on
// top of the encoder.
//
// A userName cannot terminate the literal and append filter syntax of its own,
// because the encoder escapes the quote. This test states that property
// directly rather than leaving it as a claim in a comment.
func TestAUserNameCannotEscapeTheFilterLiteral(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("filter")
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
	}))
	defer srv.Close()

	c := NewClient(Target{BaseURL: srv.URL, Token: "t"}, srv.Client())

	// A name that would, unescaped, close the string and add a second clause
	// matching everybody.
	hostile := `x" or userName pr or userName eq "y`
	if _, err := c.FindByUserName(context.Background(), hostile); err != nil {
		t.Fatal(err)
	}

	var back string
	literal := strings.TrimPrefix(got, "userName eq ")
	if err := json.Unmarshal([]byte(literal), &back); err != nil {
		t.Fatalf("the filter is not a JSON string: %v", err)
	}
	if back != hostile {
		t.Fatalf("the hostile name was altered to %q; it must survive intact "+
			"inside the literal rather than being stripped", back)
	}
	// The whole hostile string is the comparison value and nothing else.
	//
	// Asserted as an exact encoding rather than by counting ` eq ` occurrences:
	// the hostile name legitimately CONTAINS that substring, escaped inside the
	// literal, so counting it in the raw filter fails on correct output. That
	// was this test's first version, and it was the test that was wrong.
	want, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	if got != "userName eq "+string(want) {
		t.Errorf("filter = %s\nwant     = userName eq %s", got, want)
	}
}
