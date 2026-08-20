package httpapi

import (
	"net/http"
	"testing"

	"signari.dev/engine/internal/authzen"
)

func TestASearchTokenCannotBeReusedWithADifferentRequest(t *testing.T) {
	base := authzen.SearchRequest{
		Subject:  &authzen.Subject{Type: "user", ID: "alice"},
		Action:   &authzen.Action{Name: "can_read"},
		Resource: &authzen.Resource{Type: "document"},
		Page:     &authzen.PageRequest{Limit: 1},
	}

	// A token as the first page would have issued it.
	page := pageResponse(base, []authzen.Item{{Type: "document", ID: "doc-1"}}, true, "doc-1")
	if page.NextToken == "" {
		t.Fatal("no next_token was issued for a page with more results")
	}

	// The same request, continuing: accepted, and the cursor comes back.
	cont := base
	cont.Page = &authzen.PageRequest{Limit: 1, Token: page.NextToken}
	_, cursor, err := pageOf(cont)
	if err != nil {
		t.Fatalf("a legitimate continuation was refused: %v", err)
	}
	if cursor != "doc-1" {
		t.Errorf("cursor = %q, want doc-1", cursor)
	}

	// Every entity §8.2 names, changed one at a time.
	for _, tc := range []struct {
		name   string
		mutate func(*authzen.SearchRequest)
	}{
		{"subject id", func(r *authzen.SearchRequest) {
			r.Subject = &authzen.Subject{Type: "user", ID: "mallory"}
		}},
		{"subject type", func(r *authzen.SearchRequest) {
			r.Subject = &authzen.Subject{Type: "service", ID: "alice"}
		}},
		{"action", func(r *authzen.SearchRequest) {
			r.Action = &authzen.Action{Name: "can_delete"}
		}},
		{"resource type", func(r *authzen.SearchRequest) {
			r.Resource = &authzen.Resource{Type: "secret"}
		}},
		{"context", func(r *authzen.SearchRequest) {
			r.Context = map[string]any{"ip": "203.0.113.9"}
		}},
		{"limit", func(r *authzen.SearchRequest) {
			r.Page = &authzen.PageRequest{Limit: 50, Token: page.NextToken}
		}},
	} {
		t.Run(tc.name+" changed", func(t *testing.T) {
			bad := base
			bad.Page = &authzen.PageRequest{Limit: 1, Token: page.NextToken}
			tc.mutate(&bad)
			if bad.Page.Token == "" {
				bad.Page.Token = page.NextToken
			}
			if _, _, err := pageOf(bad); err == nil {
				t.Errorf("a token issued for a different %s was accepted; §8.2 "+
					"requires every entity and pagination parameter to be identical "+
					"to the request that produced it", tc.name)
			}
		})
	}
}

// §8.2.2: "If there are no more results after this page, its value MUST be an
// empty string."
//
// `next_token` carried `omitempty`, so a final page omitted the field. A PEP
// following the specification tests `next_token === ""` to learn it is done, and
// an absent field is a different value in every language a client is written in.
func TestNextTokenIsAnEmptyStringWhenExhausted(t *testing.T) {
	f := newTokenFixture(t)
	token := newPDPCaller(t, f)
	seedSearchModel(t, f)

	code, body := postAuthz(t, f, token, "/access/v1/search/resource",
		`{"subject":{"type":"user","id":"nobody-at-all"},
		  "action":{"name":"can_read"},
		  "resource":{"type":"document"}}`)
	if code != http.StatusOK {
		t.Fatalf("search gave %d: %v", code, body)
	}
	page, ok := body["page"].(map[string]any)
	if !ok {
		t.Fatalf("no page object: %v", body)
	}
	v, present := page["next_token"]
	if !present {
		t.Fatal("next_token is absent from the final page. §8.2.2 makes it " +
			"REQUIRED and says its value MUST be an empty string when there are " +
			"no more results — absent and empty are not the same to a client")
	}
	if s, _ := v.(string); s != "" {
		t.Errorf("next_token = %q on an exhausted result set, want \"\"", s)
	}
}

func seedSearchModel(t *testing.T, f *tokenFixture) {
	t.Helper()
	model := `{"types":{"document":{"relations":{"reader":null},
	           "permissions":{"can_read":["reader"]}}}}`
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO core.authorization_models (org_id, source, compiled)
		VALUES ($1::uuid, '# search test', $2::jsonb)
		ON CONFLICT (org_id) DO UPDATE SET compiled = $2::jsonb`,
		f.orgID, model); err != nil {
		t.Fatal(err)
	}
}
