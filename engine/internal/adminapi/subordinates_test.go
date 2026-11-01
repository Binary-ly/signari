package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// driftJWK is a public key, for statements about somebody.
const driftJWK = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
	`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"sub-1","use":"sig"}`

// No authority_hints is a Trust Anchor, as the list being empty and not absent says too.
func TestAnInstanceBecomesATrustAnchorThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	id := newDriftInstance(t, s)
	t.Cleanup(func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, id)
	})
	path := "/admin/instances/" + id + "/federation"
	if rec := call(t, s, http.MethodPut, path, testToken, map[string]any{"authority_hints": []string{}}); rec.Code != http.StatusOK {
		t.Fatalf("enabling with no superiors answered %d %s", rec.Code, rec.Body.String())
	}
	rec := call(t, s, http.MethodGet, path, testToken, nil)
	if !strings.Contains(rec.Body.String(), `"enabled":true`) || !strings.Contains(rec.Body.String(), `"authority_hints":[]`) {
		t.Errorf("the instance reads %s", rec.Body.String())
	}
}

// Who an instance speaks for in a federation, through the routes a console will use (12.11).
func TestASubordinateIsManagedThroughTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	base := "/admin/instances/" + newDriftFederatedInstance(t, s) + "/federation/subordinates"
	const leaf = "https://leaf.example.test"
	keys := json.RawMessage(`{"keys":[` + driftJWK + `]}`)

	for name, body := range map[string]map[string]any{
		"no entity id":     {"jwks": keys},
		"an http entity":   {"entity_id": "http://leaf.example.test", "jwks": keys},
		"no keys":          {"entity_id": leaf, "jwks": json.RawMessage(`{"keys":[]}`)},
		"not a key set":    {"entity_id": leaf, "jwks": json.RawMessage(`{"keys":"none"}`)},
		"a negative depth": {"entity_id": leaf, "jwks": keys, "max_path_length": -1},
		"a private key": {"entity_id": leaf, "jwks": json.RawMessage(`{"keys":[{"kty":"EC","crv":"P-256",` +
			`"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",` +
			`"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}]}`)},
		"a policy no resolver could apply": {"entity_id": leaf, "jwks": keys,
			"metadata_policy": json.RawMessage(`{"openid_relying_party":{"client_name":{"value":"a","one_of":["b"]}}}`)},
	} {
		if rec := call(t, s, http.MethodPut, base, testToken, body); rec.Code != http.StatusBadRequest ||
			!strings.Contains(rec.Body.String(), "invalid_subordinate") {
			t.Errorf("%s answered %d %s", name, rec.Code, rec.Body.String())
		}
	}

	body := map[string]any{"entity_id": leaf, "jwks": keys, "max_path_length": 1, "intermediate": true,
		"metadata_policy": json.RawMessage(`{"openid_relying_party":{"contacts":{"add":["fed@example.test"]}}}`)}
	if rec := call(t, s, http.MethodPut, base, testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("speaking for an entity answered %d %s", rec.Code, rec.Body.String())
	}
	listed := call(t, s, http.MethodGet, base, testToken, nil).Body.String()
	for _, want := range []string{leaf, `"kid":"sub-1"`, `"max_path_length":1`, `"intermediate":true`, "fed@example.test"} {
		if !strings.Contains(listed, want) {
			t.Errorf("the list reads %s, without %s", listed, want)
		}
	}
	// Replaced whole: what a statement says is what was last decided.
	delete(body, "metadata_policy")
	if rec := call(t, s, http.MethodPut, base, testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("replacing answered %d %s", rec.Code, rec.Body.String())
	}
	if listed := call(t, s, http.MethodGet, base, testToken, nil).Body.String(); strings.Contains(listed, "fed@example.test") {
		t.Errorf("a policy left out of a replacement stayed: %s", listed)
	}

	gone := base + "?entity_id=" + url.QueryEscape(leaf)
	if rec := call(t, s, http.MethodDelete, base, testToken, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("removing nobody answered %d", rec.Code)
	}
	if rec := call(t, s, http.MethodDelete, gone, testToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("removing answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, s, http.MethodDelete, gone, testToken, nil); rec.Code != http.StatusNotFound {
		t.Errorf("removing twice answered %d", rec.Code)
	}
}
