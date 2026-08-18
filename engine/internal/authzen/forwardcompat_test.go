package authzen

import (
	"strings"
	"testing"
)

// AuthZEN §10.1.1, verbatim:
//
//	"To ensure forward compatibility, receivers MUST ignore unknown fields
//	present in request or response bodies."
//
// And §4 says future revisions of the API "MAY augment this API... Augmentation
// MAY include additional API methods or additional parameters to existing API
// methods."
//
// So the specification both permits new parameters and requires receivers to
// tolerate them. A PDP that refuses an unfamiliar field rejects every PEP that
// speaks a later revision — the request is not merely denied, it is a 400, so
// the caller cannot even tell whether they would have been allowed.
func TestUnknownFieldsAreIgnoredNotRefused(t *testing.T) {
	body := []byte(`{
		"subject":  {"type":"user","id":"alice"},
		"action":   {"name":"read"},
		"resource": {"type":"document","id":"42"},
		"a_field_from_authzen_1_1": {"nested": true},
		"another_extension": "whatever"
	}`)

	var req Request
	if err := Decode(body, &req); err != nil {
		t.Fatalf("a request carrying fields from a later revision was refused: %v\n"+
			"§10.1.1 makes ignoring them a MUST", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("the known fields did not survive the unknown ones: %v", err)
	}
	if req.Subject.ID != "alice" || req.Action.Name != "read" || req.Resource.Type != "document" {
		t.Fatalf("request decoded wrongly: %+v", req)
	}
}

// The reason the strictness was there in the first place, and why removing it
// costs nothing.
//
// The old decoder refused unknown fields so that a caller sending `subjects`
// instead of `subject` was told, rather than receiving "a confident denial about
// a subject we never saw". That instinct is right and the mechanism was wrong:
// with the field ignored, `subject` is simply absent, and Validate answers with
// the error §10.1.1 actually requires —
//
//	"If a required attribute in the information model is omitted, the server
//	MUST return a 'Bad Request' error"
//
// — which names the missing attribute rather than the misspelled one, and is the
// more useful of the two messages.
func TestAMisspelledRequiredFieldIsStillReported(t *testing.T) {
	body := []byte(`{
		"subjects": {"type":"user","id":"alice"},
		"action":   {"name":"read"},
		"resource": {"type":"document","id":"42"}
	}`)

	var req Request
	if err := Decode(body, &req); err != nil {
		t.Fatalf("decode should now tolerate the unknown field: %v", err)
	}
	err := req.Validate()
	if err == nil {
		t.Fatal("a request with no subject was accepted; the typo became silence")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("the error does not name what is missing: %v", err)
	}
}

// Forward compatibility must not extend to the top-level shape. §10.1.1: "The
// top-level element of all request and response bodies MUST be a JSON object."
func TestATopLevelNonObjectIsRefused(t *testing.T) {
	for _, body := range []string{`[]`, `"a string"`, `42`, `null`, `true`} {
		var req Request
		if err := Decode([]byte(body), &req); err == nil {
			// `null` decodes into a zero Request without error in Go, so the
			// backstop is Validate. Either refusal is acceptable; silence is not.
			if verr := req.Validate(); verr == nil {
				t.Errorf("top-level %s was accepted as an evaluation request", body)
			}
		}
	}
}

// Unknown fields nested INSIDE a known object must be tolerated too — that is
// where an extension to an existing entity would land.
func TestUnknownFieldsInsideEntitiesAreIgnored(t *testing.T) {
	body := []byte(`{
		"subject":  {"type":"user","id":"alice","future_attr":1},
		"action":   {"name":"read","future_attr":[1,2]},
		"resource": {"type":"document","id":"42","future_attr":{"a":"b"}},
		"context":  {"time":"now","future_attr":true}
	}`)

	var req Request
	if err := Decode(body, &req); err != nil {
		t.Fatalf("extensions inside entities were refused: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// The fail-closed invariant, swept over hostile bodies.
//
// A PDP has exactly one catastrophic failure: answering `true` when it should
// not. Every other outcome — a 400, a 500, a denial — is safe. So rather than
// enumerate what each malformed body should return, this asserts the single
// property that must hold for all of them: **nothing that fails to decode or
// validate may produce a request a caller could act on as an allow.**
//
// Decode-and-validate is the gate the handler runs before it ever consults
// policy, so a body that gets past both is one where the decision is genuinely
// the policy's to make; a body that does not must never reach that point.
func TestNoMalformedBodyEverProducesAValidRequest(t *testing.T) {
	hostile := []string{
		``,
		`{`,
		`[]`,
		`null`,
		`"string"`,
		`42`,
		`true`,
		`{"subject":null,"action":null,"resource":null}`,
		`{"subject":{},"action":{},"resource":{}}`,
		`{"subject":{"type":"user"},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		`{"subject":{"id":"alice"},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		`{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"}}`,
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"read"}}`,
		`{"subject":{"type":"user","id":"alice"},"action":{"name":""},"resource":{"type":"doc","id":"1"}}`,
		// Type confusion: entities as scalars rather than objects.
		`{"subject":"alice","action":"read","resource":"doc"}`,
		`{"subject":["alice"],"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		// Duplicate keys. RFC 8259 leaves the result implementation-defined, so
		// whichever wins, a request missing a required attribute must still fail.
		`{"subject":{"type":"user","id":"alice"},"subject":{},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
	}

	for _, body := range hostile {
		var req Request
		derr := Decode([]byte(body), &req)
		if derr != nil {
			continue // refused at the door, which is the safe outcome
		}
		if verr := req.Validate(); verr == nil {
			t.Errorf("this body decoded AND validated, so it would reach policy "+
				"evaluation as though it were a well-formed question:\n  %s\n"+
				"  parsed as %+v", body, req)
		}
	}
}

// And the converse, so the sweep above cannot pass because everything fails: a
// well-formed request must get through both stages.
func TestAWellFormedRequestPassesBothStages(t *testing.T) {
	body := []byte(`{"subject":{"type":"user","id":"alice"},
	                 "action":{"name":"read"},
	                 "resource":{"type":"document","id":"42"}}`)
	var req Request
	if err := Decode(body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("a well-formed request was rejected, so the sweep above proves "+
			"nothing: %v", err)
	}
}

// Duplicate members, at every depth, with the reason spelled out.
//
// Go merges a repeated object into what it already decoded, so the FIRST
// occurrence's populated fields survive — while a proxy, WAF or audit shipper
// taking the last occurrence sees something else. The decision and the record of
// the decision would then describe different requests.
func TestDuplicateMembersAreRefusedAtEveryDepth(t *testing.T) {
	cases := map[string]string{
		"top level": `{"subject":{"type":"user","id":"alice"},"subject":{},
		               "action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		"inside an entity": `{"subject":{"type":"user","id":"alice","id":"mallory"},
		                      "action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		"inside context": `{"subject":{"type":"user","id":"alice"},
		                    "action":{"name":"read"},"resource":{"type":"doc","id":"1"},
		                    "context":{"ip":"10.0.0.1","ip":"203.0.113.9"}}`,
		"inside an array element": `{"subject":{"type":"user","id":"alice"},
		                            "action":{"name":"read"},
		                            "resource":{"type":"doc","id":"1",
		                              "properties":{"tags":[{"a":1,"a":2}]}}}`,
	}
	for name, body := range cases {
		var req Request
		if err := Decode([]byte(body), &req); err == nil {
			t.Errorf("%s: a body naming a member twice was accepted, and decoded "+
				"as %+v — a reader taking the other occurrence would see something "+
				"different", name, req)
		} else if !strings.Contains(err.Error(), "more than once") {
			t.Errorf("%s: refused for the wrong reason: %v", name, err)
		}
	}
}

// Repeating a key in DIFFERENT objects is not a duplicate. Without this the
// check above would refuse almost every real request, since `type` and `id`
// appear in subject and resource alike.
func TestTheSameKeyInDifferentObjectsIsFine(t *testing.T) {
	body := []byte(`{"subject":{"type":"user","id":"alice"},
	                 "action":{"name":"read"},
	                 "resource":{"type":"document","id":"42"},
	                 "context":{"type":"anything"}}`)
	var req Request
	if err := Decode(body, &req); err != nil {
		t.Fatalf("a normal request was refused as duplicated: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
