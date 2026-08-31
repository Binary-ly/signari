package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Changing a user's email address must clear its verified mark.
//
// # The attack this closes
//
// `email_verified_at` is what makes this server emit `email_verified: true` in
// an ID token and from /userinfo. Relying parties key accounts on a verified
// address precisely because an unverified one proves nothing -- so a server that
// keeps the mark while the address underneath it changes is signing a statement
// that somebody owns an address nobody checked.
//
// Concretely: a holder of `users:write` sets a victim's address to one they
// control, the mark survives, and the next sign-in at any relying party that
// matches on verified email merges the victim's account onto the attacker's.
// The scope is meant to administer users, not to mint verified ownership of
// arbitrary addresses, and the difference between those two is this one UPDATE.
//
// It is worth being precise about why this is not paranoia: the takeover
// happens at a DIFFERENT system, using a claim this one signed, so nothing in
// this server's own logs looks wrong afterwards. The ID token was valid. The
// address really was in the database. Only the assertion of verification was
// false, and it was false because an UPDATE forgot one column.
func TestChangingAUsersEmailClearsTheVerifiedMark(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)

	// Start verified, which is the state the bug needs in order to matter.
	if _, err := s.db.Exec(ctx,
		`UPDATE core.users SET email_verified_at = now() WHERE id = $1::uuid`,
		userID); err != nil {
		t.Fatal(err)
	}
	if !emailVerified(t, s, userID) {
		t.Fatal("the fixture is not verified, so this test proves nothing")
	}

	fresh := fmt.Sprintf("moved-%d@example.test", time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+userID,
		fmt.Sprintf(`{"email":%q}`, fresh), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch gave %d: %s", rec.Code, rec.Body.String())
	}

	if emailVerified(t, s, userID) {
		t.Fatal("the address changed and email_verified_at survived. This " +
			"server will now assert email_verified:true for an address nobody " +
			"verified, which is account takeover at every relying party that " +
			"matches on verified email.")
	}

	var got string
	if err := s.db.QueryRow(ctx,
		`SELECT email FROM core.users WHERE id = $1::uuid`, userID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != fresh {
		t.Errorf("email = %q, want %q", got, fresh)
	}
}

// The audit trail records THAT the mark was cleared, not the address.
//
// Both halves matter. An investigation needs to know the account stopped
// asserting a verified address and when; it must not learn the address itself,
// because writing personal data into the append-only table is what the audit
// package's first rule exists to prevent and what makes a lawful erasure
// request unanswerable.
func TestTheAuditTrailRecordsTheClearedMarkWithoutTheAddress(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)

	fresh := fmt.Sprintf("audited-%d@example.test", time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+userID,
		fmt.Sprintf(`{"email":%q}`, fresh), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch gave %d: %s", rec.Code, rec.Body.String())
	}

	var detail string
	if err := s.db.QueryRow(ctx, `
		SELECT detail::text FROM core.audit_events
		WHERE subject_id = $1::uuid AND event_type = 'admin.user_updated'
		ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&detail); err != nil {
		t.Fatalf("no admin.user_updated event was written: %v", err)
	}
	// Space-tolerant: jsonb round-trips with a space after the colon, so
	// matching the compact form asserts the storage format rather than the
	// content.
	compact := strings.ReplaceAll(detail, ": ", ":")
	if !strings.Contains(compact, `"email_verified_cleared":true`) {
		t.Errorf("the audit detail does not record that the verified mark was "+
			"cleared: %s", detail)
	}
	if strings.Contains(detail, fresh) {
		t.Errorf("the audit detail contains the new address. Personal data must "+
			"not enter the append-only table -- it outlives the account and "+
			"cannot be erased on request. detail = %s", detail)
	}
}

// A taken address is a 409, not a 500.
//
// The uniqueness index doing its job is not a server fault, and reporting it as
// one sends an operator to investigate an incident that is really a typo.
func TestPatchingAUserToATakenEmailConflicts(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	first := newDriftUser(t, s)
	second := newDriftUser(t, s)

	var taken string
	if err := s.db.QueryRow(ctx,
		`SELECT email FROM core.users WHERE id = $1::uuid`, first).Scan(&taken); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+second,
		fmt.Sprintf(`{"email":%q}`, taken), ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("patch to a taken address gave %d, want 409: %s",
			rec.Code, rec.Body.String())
	}
}

// Clearing a field means NULL, not an empty string.
//
// The uniqueness indexes are partial -- `WHERE email IS NOT NULL` -- so two
// users each holding "" would collide on an index whose whole purpose is to let
// them both hold nothing. Each fixture is given a username first, because
// `CHECK (username IS NOT NULL OR email IS NOT NULL)` means an account must
// keep one of the two.
func TestClearingAnIdentityFieldStoresNullNotEmpty(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	a := newDriftUser(t, s)
	b := newDriftUser(t, s)

	for i, id := range []string{a, b} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+id,
			fmt.Sprintf(`{"username":"kept-%d-%d","email":""}`, time.Now().UnixNano(), i), ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("clearing the address gave %d: %s", rec.Code, rec.Body.String())
		}
	}

	var nulls int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM core.users WHERE id = ANY($1::uuid[]) AND email IS NULL`,
		[]string{a, b}).Scan(&nulls); err != nil {
		t.Fatal(err)
	}
	if nulls != 2 {
		t.Fatalf("%d of 2 cleared addresses are NULL. An empty string would "+
			"make the second clear collide on users_org_email_key.", nulls)
	}
}

// Clearing the LAST identifier is refused, and the refusal explains itself.
//
// This was found by the test above rather than by reading: the fixture user has
// only an email, clearing it hit `users_has_an_identifier`, and the handler
// reported "server_error" for a request the database had correctly refused. An
// operator would have opened an incident about a working constraint.
//
// The 400 matters more than it looks. The account it prevents is not corrupt --
// every column is valid -- it is simply unreachable: nobody can sign in to it
// and no administrator can search for it, because both of the things you search
// by are gone. It can only be addressed by its uuid, which nobody has written
// down.
func TestClearingTheLastIdentifierIsRefusedWithAReason(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s) // email only, no username

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+userID,
		`{"email":""}`, ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("gave %d, want 400: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "no_identifier_left" {
		t.Errorf("error = %q, want no_identifier_left (got detail %q)",
			body.Error, body.Detail)
	}
}

// The display fields round-trip and carry no authentication meaning.
func TestPatchingDisplayFieldsUpdatesThem(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+userID,
		`{"display_name":"Ada L","given_name":"Ada","surname":"Lovelace"}`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch gave %d: %s", rec.Code, rec.Body.String())
	}

	var display, given, surname string
	if err := s.db.QueryRow(ctx, `
		SELECT COALESCE(display_name,''), COALESCE(given_name,''), COALESCE(surname,'')
		FROM core.users WHERE id = $1::uuid`, userID).Scan(&display, &given, &surname); err != nil {
		t.Fatal(err)
	}
	if display != "Ada L" || given != "Ada" || surname != "Lovelace" {
		t.Errorf("got (%q, %q, %q)", display, given, surname)
	}
}

// A malformed address is refused before the transaction opens.
func TestPatchingAUserWithAMalformedEmailIsRejected(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodPatch, "/admin/users/"+userID,
		`{"email":"not-an-address"}`, ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("gave %d, want 400: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "invalid_email" {
		t.Errorf("error = %q, want invalid_email", body.Error)
	}
}

func emailVerified(t *testing.T, s *Server, userID string) bool {
	t.Helper()
	var verified bool
	if err := s.db.QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	return verified
}
