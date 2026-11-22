package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// accessTokenClaims reads an access token's claims as a resource server does.
func accessTokenClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", raw)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A resource server that wants more than a password can only ask if the token says
// what it got. A token with no session behind it says nothing, not something assumed.
func TestAnAccessTokenSaysHowThePersonSignedIn(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	mint := func(sid string) map[string]any {
		t.Helper()
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		c, err := f.srv.lookupClient(ctx, f.clientID)
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, f.userID, sid, "", []string{"profile"}, nil, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		return accessTokenClaims(t, resp.AccessToken)
	}

	signedIn := time.Now().Add(-time.Hour).Truncate(time.Second)
	sid := "sid-assurance-" + signedIn.Format("150405.000")
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, $2, $3::uuid, $4::uuid, '2', ARRAY['pwd','otp','mfa'], $5, now() + interval '1 hour')`,
		sid, store.HashToken(sid), f.orgID, f.userID, signedIn); err != nil {
		t.Fatal(err)
	}
	claims := mint(sid)
	if claims["acr"] != "2" {
		t.Errorf("acr reads %v", claims["acr"])
	}
	if at, _ := claims["auth_time"].(float64); int64(at) != signedIn.Unix() {
		t.Errorf("auth_time reads %v, want %d", claims["auth_time"], signedIn.Unix())
	}

	claims = mint("")
	if _, ok := claims["acr"]; ok {
		t.Errorf("a token with no session says acr %v", claims["acr"])
	}
	if _, ok := claims["auth_time"]; ok {
		t.Errorf("a token with no session says auth_time %v", claims["auth_time"])
	}
}
