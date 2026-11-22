package uma

import (
	"net/http"
	"strings"
	"testing"
)

// §3.1's own example, with the type this server needs, reads as written; a member it
// does not know is ignored, and the scopes come back trimmed.
func TestAResourceDescriptionIsReadAsRegistered(t *testing.T) {
	d, perr := ParseResourceDescription([]byte(`{"resource_scopes":[" view ","http://photoz.example.com/dev/scopes/print"],
		"description":"Collection of digital photographs","icon_uri":"http://www.example.com/icons/flower.png",
		"name":"Photo Album","type":"photoalbum","x-extension":true}`))
	if perr != nil {
		t.Fatal(perr)
	}
	if strings.Join(d.ResourceScopes, ",") != "view,http://photoz.example.com/dev/scopes/print" || d.Type != "photoalbum" ||
		d.Name != "Photo Album" || d.IconURI != "http://www.example.com/icons/flower.png" {
		t.Errorf("read as %+v", d)
	}
}

// What §3.2 answers 400 (specs/uma-fedauthz.txt:263), each saying which rule it broke.
func TestAResourceDescriptionThatCannotBeProtectedIsRefused(t *testing.T) {
	for _, c := range []struct{ name, body, says string }{
		{"not JSON", `scopes=view`, "not a resource description"},
		{"no scopes", `{"type":"photoalbum"}`, "resource_scopes is required"},
		{"empty scopes", `{"type":"photoalbum","resource_scopes":[]}`, "resource_scopes is required"},
		{"no type", `{"resource_scopes":["view"]}`, "type is required"},
		{"a blank scope", `{"type":"photoalbum","resource_scopes":["view"," "]}`, "1 to 256"},
		{"a scope twice", `{"type":"photoalbum","resource_scopes":["view","view"]}`, "named twice"},
		{"a parameter twice", `{"type":"photoalbum","type":"invoice","resource_scopes":["view"]}`, "type"},
		{"an icon that is not a URL", `{"type":"photoalbum","resource_scopes":["view"],"icon_uri":"flower.png"}`, "icon_uri"},
		{"an icon by javascript", `{"type":"photoalbum","resource_scopes":["view"],"icon_uri":"javascript:alert(1)"}`, "icon_uri"},
	} {
		_, perr := ParseResourceDescription([]byte(c.body))
		if perr == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if perr.Code != "invalid_request" || perr.Status != http.StatusBadRequest || !strings.Contains(perr.Description, c.says) {
			t.Errorf("%s: refused as %s %d %q, want invalid_request 400 saying %q", c.name, perr.Code, perr.Status,
				perr.Description, c.says)
		}
	}
}
