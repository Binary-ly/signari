package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// rptFor walks a resource through a ticket to an RPT.
func (f *cibaFixture) rptFor(t *testing.T, id string, extra url.Values) map[string]any {
	t.Helper()
	code, body := f.permission(t, f.clientID, f.secret,
		`{"resource_type":"document","resource_id":"`+id+`","resource_scopes":["read"]}`)
	if code != http.StatusCreated {
		t.Fatalf("permission: %d %v", code, body)
	}
	ticket, _ := body["ticket"].(string)
	code, out := f.exchange(t, f.clientID, ticket, extra)
	if code != http.StatusOK {
		t.Fatalf("the RPT was refused: %d %v", code, out)
	}
	return out
}

func grantDocument(t *testing.T, f *cibaFixture, id string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.relations (org_id, subject_type, subject_id, relation, object_type, object_id)
		VALUES ($1::uuid, 'client', $2, 'viewer', 'document', $3)`, f.orgID, f.clientID, id); err != nil {
		t.Fatal(err)
	}
}

// §3.3.5.1: the permissions of the RPT presented are added to the one issued, and
// `upgraded` says so. The old one SHOULD be revoked and here it is: presented again,
// it carries nothing.
func TestAnRPTIsUpgradedWithWhatItHeld(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")
	grantDocument(t, f, "43")

	first := f.rptFor(t, "42", nil)
	raw := first["access_token"].(string)
	second := f.rptFor(t, "43", url.Values{"rpt": {raw}})
	if second["upgraded"] != true {
		t.Fatalf("no upgrade: %v", second)
	}
	scope, _ := second["scope"].(string)
	if !strings.Contains(scope, "document:42#read") || !strings.Contains(scope, "document:43#read") {
		t.Errorf("the upgraded RPT holds %q", scope)
	}

	again := f.rptFor(t, "43", url.Values{"rpt": {raw}})
	if again["upgraded"] != nil {
		t.Errorf("a revoked RPT was upgraded: %v", again)
	}
	if scope, _ := again["scope"].(string); strings.Contains(scope, "document:42#read") {
		t.Errorf("a revoked RPT's permission came through: %q", scope)
	}
}

// §3.3.1: an RPT presented "MAY be expired". So the token has no authority left, and
// what it says is only worth anything because each permission is decided again. A
// permission taken away while the token was out must not come back through one.
func TestAnUpgradeDecidesEverythingAgain(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")
	grantDocument(t, f, "43")

	key, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	expired := func(scope string) string {
		t.Helper()
		now := time.Now()
		c, err := f.srv.lookupClient(context.Background(), f.clientID)
		if err != nil {
			t.Fatal(err)
		}
		jti, _ := newSID()
		signed, err := issueAccessToken(context.Background(), f.srv.db, c, tokens.NewSigner(key), tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.clientID, Audience: []string{f.clientID},
			Expiry: now.Add(-time.Hour).Unix(), IssuedAt: now.Add(-2 * time.Hour).Unix(), JTI: jti,
			ClientID: f.clientID, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	out := f.rptFor(t, "43", url.Values{"rpt": {expired("document:42#read")}})
	if out["upgraded"] != true {
		t.Fatalf("an expired RPT whose permission still stands was not upgraded: %v", out)
	}

	// Somebody's permission is taken away, and the expired RPT still says it.
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.relations
		WHERE org_id = $1::uuid AND object_id = '42'`, f.orgID); err != nil {
		t.Fatal(err)
	}
	out = f.rptFor(t, "43", url.Values{"rpt": {expired("document:42#read document:43#read")}})
	if out["upgraded"] != nil {
		t.Errorf("a token that outlived a permission was upgraded: %v", out)
	}
	if scope, _ := out["scope"].(string); strings.Contains(scope, "document:42") {
		t.Errorf("a permission taken away came back through an old token: %q", scope)
	}
}

// A token presented here is the client's word. Each of these is a real token, and
// none is this client's RPT for this party at this resource server: the answer is a
// new RPT saying nothing about the old one, not a refusal.
func TestWhatIsNotThisRPTIsNotUpgraded(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")
	grantDocument(t, f, "43")
	key, err := f.srv.cfg.Keys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	minted := func(subject, client string, aud []string, scope string, bound string) string {
		t.Helper()
		now := time.Now()
		jti, _ := newSID()
		claims := tokens.AccessTokenClaims{Issuer: f.srv.cfg.Issuer, Subject: subject, Audience: aud,
			Expiry: now.Add(time.Hour).Unix(), IssuedAt: now.Unix(), JTI: jti, ClientID: client, Scope: scope}
		if bound != "" {
			claims.Cnf = bindingFor(bound, "")
		}
		signed, err := issueAccessToken(context.Background(), f.srv.db, c, tokens.NewSigner(key), claims)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	for name, raw := range map[string]string{
		"nothing like a token":      "x",
		"another client's":          minted(f.clientID, f.otherClient, []string{f.clientID}, "document:42#read", ""),
		"another resource server's": minted(f.clientID, f.clientID, []string{"elsewhere"}, "document:42#read", ""),
		"another party's":           minted(f.otherUserID, f.clientID, []string{f.clientID}, "document:42#read", ""),
		"an ordinary access token":  minted(f.clientID, f.clientID, []string{f.clientID}, "openid profile", ""),
		"bound to a key not shown":  minted(f.clientID, f.clientID, []string{f.clientID}, "document:42#read", "somekey"),
	} {
		out := f.rptFor(t, "43", url.Values{"rpt": {raw}})
		if out["upgraded"] != nil {
			t.Errorf("%s was upgraded: %v", name, out)
		}
		if scope, _ := out["scope"].(string); scope != "document:43#read" {
			t.Errorf("%s: the RPT holds %q", name, scope)
		}
	}
}

// §5.3 leaves this to a profile, and RFC 9449 is one: a proof at the token endpoint
// binds an RPT as it binds any other token, or a client asking for a bound token gets
// a bearer one and a resource server enforcing DPoP refuses it.
func TestAnRPTIsBoundToTheProofItWasAskedWith(t *testing.T) {
	f := newCIBAFixture(t)
	f.allowClientOn(t, "document", "42", "viewer")
	code, body := f.permission(t, f.clientID, f.secret, onePermission)
	if code != http.StatusCreated {
		t.Fatalf("permission: %d %v", code, body)
	}
	form := url.Values{"grant_type": {uma.GrantType}, "ticket": {body["ticket"].(string)}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	c, err := f.srv.lookupClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.srv.handleUMAGrant(rec, req.WithContext(withDPoPThumbprint(req.Context(), "thumb")), c)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	if out["token_type"] != "DPoP" {
		t.Errorf("token_type %v", out["token_type"])
	}
	cnf, _ := claimsOfJWT(t, out["access_token"].(string))["cnf"].(map[string]any)
	if cnf["jkt"] != "thumb" {
		t.Errorf("the RPT is not bound: %v", cnf)
	}
}

func TestAPermissionScopeReadsBack(t *testing.T) {
	for scope, want := range map[string][3]string{
		"document:42#read": {"document", "42", "read"},
		"doc:a:b#c#read":   {"doc", "a:b#c", "read"},
		"openid":           {},
		"document:42#":     {},
		"document#read":    {},
		":42#read":         {},
	} {
		typ, id, s, ok := uma.ParseScope(scope)
		if ok != (want != [3]string{}) || [3]string{typ, id, s} != want {
			t.Errorf("%q read as %q %q %q %v", scope, typ, id, s, ok)
		}
	}
}
