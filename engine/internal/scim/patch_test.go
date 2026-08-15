package scim

import (
	"encoding/json"
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

// TestFilteredPathIsReportedNotDropped keeps a path we cannot honour visible.
func TestFilteredPathIsReportedNotDropped(t *testing.T) {
	var req PatchRequest
	_ = json.Unmarshal([]byte(
		`{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"w@x.test"}]}`), &req)
	got, err := ApplyUserPatch(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Unsupported) == 0 {
		t.Fatal("a path we do not act on was dropped without a word")
	}
}

func boolPtr(b bool) *bool { return &b }
