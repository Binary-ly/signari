package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// Every source and transform, through each place a claim goes (10.04): the ID token, the
// access token and userinfo.
func TestAClaimIsMadeFromMoreThanAnAttribute(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetRootKey(root)
	n := time.Now().UnixNano()
	group := fmt.Sprintf("Staff-%d", n)
	var groupID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'Staff') RETURNING id::text`, f.orgID, group).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, groupID, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	// A second group the person is in and the client was not told it may hear of.
	var hiddenID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1::uuid, $2, 'Hidden') RETURNING id::text`, f.orgID, group+"-hidden").Scan(&hiddenID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.groups WHERE id = $1::uuid`, hiddenID)
	})
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, hiddenID, f.userID, f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.client_group_release (client_id, org_id, only_groups)
		VALUES ($1, $2::uuid, $3)`, f.clientID, f.orgID, []string{group}); err != nil {
		t.Fatalf("releasing the group: %v", err)
	}
	var email string
	if err := f.pool.QueryRow(ctx, `UPDATE core.users SET display_name = 'Ada Lovelace' WHERE id = $1::uuid
		RETURNING email`, f.userID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantRelation(ctx, f.pool, f.orgID, store.Relation{SubjectType: "user", SubjectID: f.userID,
		Relation: "editor", ObjectType: store.ApplicationObject, ObjectID: f.clientID}, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.relations WHERE org_id = $1::uuid AND object_id = $2`, f.orgID, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.claim_mappers WHERE client_id = $1`, f.clientID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.groups WHERE id = $1::uuid`, groupID)
	})

	destinations := []string{"id_token", "access_token", "userinfo"}
	mapper := func(m store.ClaimMapper) error {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, d := range destinations {
			m.Destination, m.ClientID = d, f.clientID
			if _, _, err := store.SetClaimMapper(ctx, tx, f.orgID, m); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	domain := strings.SplitN(email, "@", 2)[1]
	for _, m := range []store.ClaimMapper{
		{Source: "constant", SourceValue: "acme", ClaimName: "tenant"},
		{Source: "constant", SourceValue: "ACME", ClaimName: "lowered", Transform: "lower"},
		{Source: "groups", ClaimName: "teams", Transform: "prefix", TransformArg: "team:"},
		{Source: "relation", ClaimName: "app_roles", Transform: "prefix", TransformArg: "role:"},
		{Source: "user_field", SourceValue: "display_name", ClaimName: "shown"},
		{Source: "user_field", SourceValue: "email", ClaimName: "mail_domain", Transform: "extract",
			TransformArg: `@(.+)$`},
		{Source: "user_field", SourceValue: "email", ClaimName: "never", Transform: "extract",
			TransformArg: `^nothing-matches-this$`},
		{Source: "user_field", SourceValue: "surname", ClaimName: "unset"},
	} {
		if err := mapper(m); err != nil {
			t.Fatalf("%s: %v", m.ClaimName, err)
		}
	}
	want := map[string]any{"tenant": "acme", "lowered": "acme", "teams": []any{"team:" + group},
		"app_roles": []any{"role:editor"}, "shown": "Ada Lovelace", "mail_domain": domain}

	verifier := strings.Repeat("a", 48)
	status, body := f.post(t, f.redeem(f.issueCodeWithScopes(t, verifier, []string{"openid"}), verifier))
	if status != http.StatusOK {
		t.Fatalf("redeeming a code: %d %v", status, body)
	}
	claimsIn := func(raw string) map[string]any {
		t.Helper()
		b, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	access := body["access_token"].(string)
	r := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
	r.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	var userinfo map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &userinfo); err != nil {
		t.Fatal(err)
	}
	for where, claims := range map[string]map[string]any{"ID token": claimsIn(body["id_token"].(string)),
		"access token": claimsIn(access), "userinfo": userinfo} {
		for name, value := range want {
			if !reflect.DeepEqual(claims[name], value) {
				t.Errorf("%s says %s is %v, want %v", where, name, claims[name], value)
			}
		}
		for _, name := range []string{"never", "unset"} {
			if got, said := claims[name]; said {
				t.Errorf("%s says %s is %v; a value that is not there is not released", where, name, got)
			}
		}
	}

	// What could never produce a value does not get stored.
	for _, c := range []struct {
		name string
		m    store.ClaimMapper
	}{
		{"an unknown source", store.ClaimMapper{Source: "environment"}},
		{"a constant of nothing", store.ClaimMapper{Source: "constant"}},
		{"a field off the list", store.ClaimMapper{Source: "user_field", SourceValue: "password"}},
		{"a value for groups", store.ClaimMapper{Source: "groups", SourceValue: "x"}},
		{"an attribute on a constant", store.ClaimMapper{Source: "constant", SourceValue: "x", Attribute: "a"}},
		{"a pattern that is not one", store.ClaimMapper{Source: "groups", Transform: "extract", TransformArg: "("}},
		{"a backreference, which RE2 has not", store.ClaimMapper{Source: "groups", Transform: "extract", TransformArg: `(a)\1`}},
		{"a transform that is not one", store.ClaimMapper{Source: "groups", Transform: "shell"}},
		{"a prefix of nothing", store.ClaimMapper{Source: "groups", Transform: "prefix"}},
	} {
		c.m.ClaimName = "refused"
		if err := mapper(c.m); !errors.Is(err, store.ErrMapperSource) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := mapper(store.ClaimMapper{Source: "constant", SourceValue: "x", ClaimName: "sub"}); !errors.Is(err, store.ErrMapperProtocolClaim) {
		t.Errorf("a constant in sub: %v", err)
	}

	// Two sources writing one claim to one place is one mapper, replaced.
	if err := mapper(store.ClaimMapper{Source: "constant", SourceValue: "other", ClaimName: "tenant"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.claim_mappers WHERE client_id = $1 AND claim_name = 'tenant'
		AND destination = 'id_token'`, f.clientID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d mappers write one claim to one place", count)
	}
}
