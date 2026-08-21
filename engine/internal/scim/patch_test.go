package scim

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The dialects two real upstreams actually emit. Every case here is a shape
// seen in the wild, not one invented from the RFC's examples.
func TestApplyUserPatchDialects(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantActive *bool
		wantName   string
		wantEmail  string
		wantErr    string
	}{
		{
			name:       "the tidy form",
			body:       `{"Operations":[{"op":"replace","path":"active","value":false}]}`,
			wantActive: boolPtr(false),
		},
		{
			name:       "Entra: no path, object value",
			body:       `{"Operations":[{"op":"replace","value":{"active":false}}]}`,
			wantActive: boolPtr(false),
		},
		{
			name:       "Entra: capitalised op",
			body:       `{"Operations":[{"op":"Replace","path":"active","value":false}]}`,
			wantActive: boolPtr(false),
		},
		{
			// The one that matters. A non-empty string reads as true in most
			// languages, so this deactivation becomes an activation and the
			// person who left keeps their account.
			name:       "Entra: active sent as the STRING False",
			body:       `{"Operations":[{"op":"replace","path":"active","value":"False"}]}`,
			wantActive: boolPtr(false),
		},
		{
			name:       "Entra: fully qualified path",
			body:       `{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:active","value":true}]}`,
			wantActive: boolPtr(true),
		},
		{
			name:     "display name",
			body:     `{"Operations":[{"op":"replace","path":"displayName","value":"Alice Anderson"}]}`,
			wantName: "Alice Anderson",
		},
		{
			name:      "emails as an array of objects",
			body:      `{"Operations":[{"op":"replace","path":"emails","value":[{"value":"a@x.test","type":"home"},{"value":"b@x.test","primary":true}]}]}`,
			wantEmail: "b@x.test",
		},
		{
			name: "two operations at once",
			body: `{"Operations":[
				{"op":"replace","path":"active","value":false},
				{"op":"replace","path":"displayName","value":"Gone"}]}`,
			wantActive: boolPtr(false),
			wantName:   "Gone",
		},
		{
			name:    "an unreadable boolean is refused, never guessed",
			body:    `{"Operations":[{"op":"replace","path":"active","value":"maybe"}]}`,
			wantErr: "neither true nor false",
		},
		{
			name:    "an unknown op is an error, not a silent success",
			body:    `{"Operations":[{"op":"frobnicate","path":"active","value":false}]}`,
			wantErr: "unknown op",
		},
		{
			name:    "no operations",
			body:    `{"Operations":[]}`,
			wantErr: "no operations",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req PatchRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("test body is not JSON: %v", err)
			}
			got, err := ApplyUserPatch(req)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("accepted a patch that should be refused: %+v", got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("wrong error: %v (want %q)", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a valid patch: %v", err)
			}
			if tc.wantActive != nil {
				if got.Active == nil {
					t.Fatal("active was not read at all")
				}
				if *got.Active != *tc.wantActive {
					t.Fatalf("active = %v, want %v -- this is the bug that keeps a "+
						"departed employee signed in", *got.Active, *tc.wantActive)
				}
			}
			if tc.wantName != "" {
				if got.DisplayName == nil || *got.DisplayName != tc.wantName {
					t.Fatalf("display name = %v, want %q", got.DisplayName, tc.wantName)
				}
			}
			if tc.wantEmail != "" {
				if got.Email == nil || *got.Email != tc.wantEmail {
					t.Fatalf("email = %v, want %q", got.Email, tc.wantEmail)
				}
			}
		})
	}
}

// TestUnmentionedAttributesStayUnmentioned is why the fields are pointers.
func TestUnmentionedAttributesStayUnmentioned(t *testing.T) {
	var req PatchRequest
	_ = json.Unmarshal([]byte(
		`{"Operations":[{"op":"replace","path":"displayName","value":"Just a name"}]}`), &req)
	got, err := ApplyUserPatch(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Active != nil {
		t.Fatal("a patch that never mentioned active would have changed it")
	}
	if got.Email != nil {
		t.Fatal("a patch that never mentioned email would have cleared it")
	}
}

func TestAFilteredEmailPathIsApplied(t *testing.T) {
	var req PatchRequest
	_ = json.Unmarshal([]byte(
		`{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"w@x.test"}]}`), &req)
	got, err := ApplyUserPatch(req)
	if err != nil {
		t.Fatalf("a filtered email path was refused: %v", err)
	}
	if got.Email == nil || *got.Email != "w@x.test" {
		t.Fatalf("Email = %v; the change was not applied", got.Email)
	}
	if len(got.Unsupported) != 0 {
		t.Errorf("still recorded as unsupported: %v", got.Unsupported)
	}
}

// `primary eq true` selects the address we store just as `type eq "work"` does,
// and so does the conjunction of the two. The filter is evaluated against the
// record we would store rather than pattern-matched, which is why combinations
// work without being enumerated.
func TestTheFilterIsEvaluatedNotPatternMatched(t *testing.T) {
	for _, path := range []string{
		`emails[primary eq true].value`,
		`emails[type eq "work" and primary eq true].value`,
		`emails[type eq "WORK"].value`,
		`emails[type sw "wor"].value`,
		`emails[primary pr].value`,
	} {
		var req PatchRequest
		body := `{"Operations":[{"op":"replace","path":` + mustJSON(t, path) +
			`,"value":"w@x.test"}]}`
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatal(err)
		}
		got, err := ApplyUserPatch(req)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if got.Email == nil {
			t.Errorf("%s: not applied", path)
		}
	}
}

// A filter selecting an address we do not keep is REFUSED, not recorded.
//
// Applying it would overwrite the primary with a home address; recording it
// would drop a change the upstream believes it made. Refusing is the only one of
// the three that gets retried.
func TestAFilterSelectingAnAddressWeDoNotStoreIsRefused(t *testing.T) {
	var req PatchRequest
	_ = json.Unmarshal([]byte(
		`{"Operations":[{"op":"replace","path":"emails[type eq \"home\"].value","value":"h@x.test"}]}`), &req)
	if _, err := ApplyUserPatch(req); err == nil {
		t.Fatal("a home address was accepted; it would have overwritten the primary")
	}
}

// A path for an attribute this server does not store at all stays reported
// rather than refused: the same operation may have changed something we DID
// apply, and failing the request would block the sync over an unused attribute.
func TestAnAttributeWeDoNotStoreIsStillReported(t *testing.T) {
	var req PatchRequest
	_ = json.Unmarshal([]byte(
		`{"Operations":[{"op":"replace","path":"phoneNumbers[type eq \"work\"].value","value":"+1"}]}`), &req)
	got, err := ApplyUserPatch(req)
	if err != nil {
		t.Fatalf("refused an attribute we simply do not keep: %v", err)
	}
	if len(got.Unsupported) == 0 {
		t.Fatal("dropped without a word")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestAddAndReplaceAgreeOnSingleValuedAttributes(t *testing.T) {
	for _, op := range []string{"add", "replace"} {
		var req PatchRequest
		if err := json.Unmarshal([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations":[{"op":"`+op+`","path":"displayName","value":"Alicia"}]}`), &req); err != nil {
			t.Fatal(err)
		}
		got, err := ApplyUserPatch(req)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if got.DisplayName == nil || *got.DisplayName != "Alicia" {
			t.Errorf("%s produced DisplayName=%v, want the value replaced", op, got.DisplayName)
		}
	}
}

// The premise the unification rests on, checked directly.
//
// Every field `applyAssign` can set must be single-valued. A slice or map here
// means a multi-valued attribute exists, and `add` and `replace` must then stop
// being the same branch — §3.5.2.1 makes `add` append where `replace` replaces
// the whole attribute.
func TestUserPatchHoldsNoMultiValuedAttribute(t *testing.T) {
	ty := reflect.TypeOf(UserPatch{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.Name == "Unsupported" {
			// Diagnostics, not a patchable attribute.
			continue
		}
		k := f.Type.Kind()
		if k == reflect.Ptr {
			k = f.Type.Elem().Kind()
		}
		if k == reflect.Slice || k == reflect.Map {
			t.Errorf("UserPatch.%s is multi-valued (%s). ApplyUserPatch sends `add` "+
				"and `replace` down the same branch because no multi-valued "+
				"attribute is stored; with one, RFC 7644 §3.5.2.1 requires `add` to "+
				"APPEND while §3.5.2.3 has `replace` replace the whole attribute. "+
				"Adding this field means splitting that branch, or a client adding "+
				"one value will delete the others", f.Name, f.Type)
		}
	}
}
