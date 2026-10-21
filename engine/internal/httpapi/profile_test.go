package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// /account/profile and sign-up hold an organisation's attributes to what their
// declarations say (5.05): readable shown, writable edited, required required,
// personal sealed.

// declareAttributes declares the test's attributes for orgID, each name
// suffixed so parallel tests cannot share one.
func declareAttributes(t *testing.T, pool *pgxpool.Pool, orgID, tag string, decl ...store.Attribute) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range decl {
		a.Name += tag
		if _, err := store.DeclareAttribute(ctx, tx, orgID, a); err != nil {
			t.Fatal(err)
		}
		name := a.Name
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM core.user_attribute_schema
				WHERE org_id = $1::uuid AND name = $2`, orgID, name)
		})
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func heldAttributes(t *testing.T, pool *pgxpool.Pool, userID, orgID string, root *keys.RootKey) map[string]string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	vals, err := store.UserAttributes(ctx, tx, userID, orgID, root)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range vals {
		out[v.Name] = v.Value
	}
	return out
}

func TestAPersonSeesAndSetsOnlyWhatTheirProfileAllows(t *testing.T) {
	f, cookie := enrolFixture(t)
	clearSignInBucket(t, f.pool)
	ctx := context.Background()
	tag := fmt.Sprintf("_%d", time.Now().UnixNano()%1_000_000_000)
	declareAttributes(t, f.pool, f.orgID, tag,
		store.Attribute{Name: "department", ValueType: "string", UserReadable: true, UserWritable: true, Required: true},
		store.Attribute{Name: "employee_no", ValueType: "string", UserReadable: true},
		store.Attribute{Name: "nickname", ValueType: "string", Personal: true, UserReadable: true, UserWritable: true},
		store.Attribute{Name: "clearance", ValueType: "string"},
	)
	dept, emp, nick, clear := "department"+tag, "employee_no"+tag, "nickname"+tag, "clearance"+tag
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hidden := "cosmic-clearance" + tag
	for name, v := range map[string]string{dept: "Ops", emp: "E-1001", clear: hidden} {
		if err := store.SetUserAttribute(ctx, tx, f.userID, f.orgID, name, v, f.srv.cfg.Root); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	page := accountGET(f, cookie, "/account/profile").Body.String()
	switch {
	case !strings.Contains(page, `name="attr.`+dept+`"`) || !strings.Contains(page, `value="Ops"`):
		t.Fatalf("the writable attribute is not editable: %s", truncate(page, 400))
	case strings.Contains(page, `name="attr.`+emp+`"`) || !strings.Contains(page, "E-1001"):
		t.Fatal("the read-only attribute is not shown as read-only")
	case strings.Contains(page, clear) || strings.Contains(page, hidden):
		t.Fatal("an attribute its subject may not read is on the page")
	}

	post := func(form url.Values) string {
		t.Helper()
		return f.formPost(t, cookie, "/account/profile", "/account/profile", form).Body.String()
	}
	post(url.Values{"attr." + dept: {"Platform"}, "attr." + nick: {"Ace"}})
	held := heldAttributes(t, f.pool, f.userID, f.orgID, f.srv.cfg.Root)
	if held[dept] != "Platform" || held[nick] != "Ace" {
		t.Fatalf("after saving: %v", held)
	}
	var sealed bool
	if err := f.pool.QueryRow(ctx, `SELECT a.value IS NULL AND a.value_sealed IS NOT NULL
		FROM core.user_attributes a JOIN core.user_attribute_schema s ON s.id = a.attribute_id
		WHERE a.user_id = $1::uuid AND s.name = $2`, f.userID, nick).Scan(&sealed); err != nil || !sealed {
		t.Errorf("a personal attribute set from the profile is not sealed (%v)", err)
	}

	// Not the person's to set: refused, and nothing moves.
	if rec := f.formPost(t, cookie, "/account/profile", "/account/profile",
		url.Values{"attr." + emp: {"E-9999"}, "attr." + dept: {"Sales"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("setting an administrator's attribute: %d, want 400", rec.Code)
	}
	if held := heldAttributes(t, f.pool, f.userID, f.orgID, f.srv.cfg.Root); held[emp] != "E-1001" || held[dept] != "Platform" {
		t.Errorf("a refused save changed something: %v", held)
	}

	// Required cannot be emptied; optional can.
	if body := post(url.Values{"attr." + dept: {""}}); !strings.Contains(body, `role="alert">this attribute is required`) {
		t.Errorf("emptying a required attribute was not refused: %s", truncate(body, 300))
	}
	post(url.Values{"attr." + nick: {""}})
	if held := heldAttributes(t, f.pool, f.userID, f.orgID, f.srv.cfg.Root); held[dept] != "Platform" || held[nick] != "" {
		t.Errorf("after emptying: %v", held)
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE subject_id = $1::uuid
		AND event_type = 'user.attributes_updated' AND NOT detail::text LIKE '%Platform%'`, f.userID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 2 {
		t.Errorf("%d profile changes audited without their values, want 2", audited)
	}
}

func TestSignUpAsksForTheAttributesAPersonSets(t *testing.T) {
	f := newTokenFixture(t)
	enableSelfSignup(t, f)
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Root = root
	tag := fmt.Sprintf("_%d", time.Now().UnixNano()%1_000_000_000)
	declareAttributes(t, f.pool, f.orgID, tag,
		store.Attribute{Name: "team", ValueType: "string", UserReadable: true, UserWritable: true, Required: true},
		store.Attribute{Name: "badge", ValueType: "string", UserReadable: true},
	)
	team := "team" + tag
	get := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/signup", nil))
	if form := get.Body.String(); !strings.Contains(form, `name="attr.`+team+`"`) || strings.Contains(form, "badge"+tag) {
		t.Fatalf("the sign-up form does not ask for exactly the writable attribute: %s", truncate(form, 400))
	}

	email := fmt.Sprintf("attrs-%d@example.test", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE email = $1`, email) })
	refused := postSignup(t, f, url.Values{"email": {email}, "password": {verifyTestPassword}})
	if accountExists(t, f, email) || !strings.Contains(refused.Body.String(), `role="alert">this attribute is required`) {
		t.Fatalf("a sign-up without a required attribute: account %v, %s", accountExists(t, f, email),
			truncate(refused.Body.String(), 300))
	}
	postSignup(t, f, url.Values{"email": {email}, "password": {verifyTestPassword}, "attr." + team: {"Blue"}})
	var userID string
	if err := f.pool.QueryRow(context.Background(), `SELECT id::text FROM core.users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("the sign-up with the attribute made no account: %v", err)
	}
	if held := heldAttributes(t, f.pool, userID, f.orgID, root); held[team] != "Blue" {
		t.Errorf("the attribute given at sign-up: %v", held)
	}
}
