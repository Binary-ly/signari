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

// Removing a second factor must end the person's live sessions.
//
// # The case that decides it
//
// A phone is stolen and the support desk resets the authenticator on it. If the
// thief has already signed in, deleting the enrolment they are no longer using
// does nothing whatever about the session they ARE using -- and the desk has
// just told the caller their account is secured.
//
// The assurance argument points the same way: those sessions carry an `acr`
// asserting multi-factor authentication, and the factor behind that assertion no
// longer exists.
func TestRemovingAFactorEndsTheUsersSessions(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUserWithTOTP(t, s)
	sid := newDriftSession(t, s, userID)

	// A client with a back-channel logout URI, so there is a notice to queue.
	// Without it this passes against a plain DELETE.
	clientID := newPreconditionClient(t, s)
	if _, err := s.db.Exec(ctx,
		`UPDATE core.clients SET backchannel_logout_uri = $2 WHERE client_id = $1`,
		clientID, "https://app.example.test/backchannel"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx,
		`INSERT INTO core.session_clients (sid, client_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`, sid, clientID); err != nil {
		t.Fatal(err)
	}
	if liveSessionCount(t, s, userID) != 1 {
		t.Fatal("the fixture session is not live, so this proves nothing")
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete,
		"/admin/users/"+userID+"/factors/totp", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("removing the factor gave %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Removed       int `json:"removed"`
		SessionsEnded int `json:"sessions_ended"`
		NoticesQueued int `json:"notices_queued"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Removed != 1 {
		t.Errorf("removed = %d, want 1", body.Removed)
	}
	if body.SessionsEnded != 1 {
		t.Fatalf("sessions_ended = %d, want 1. The factor is gone and whoever "+
			"was holding the device is still signed in.", body.SessionsEnded)
	}
	if body.NoticesQueued != 1 {
		t.Errorf("notices_queued = %d, want 1", body.NoticesQueued)
	}
	if liveSessionCount(t, s, userID) != 0 {
		t.Error("a session survived the factor reset")
	}
}

// One passkey may be removed without touching the others.
func TestRemovingOnePasskeyLeavesTheRest(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	doomed := newDriftPasskey(t, s, userID)
	kept := newDriftPasskey(t, s, userID)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete,
		"/admin/users/"+userID+"/factors/webauthn/"+doomed, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d: %s", rec.Code, rec.Body.String())
	}

	var remaining int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid`,
		userID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("%d credentials remain, want 1", remaining)
	}
	var survivor string
	if err := s.db.QueryRow(ctx,
		`SELECT id::text FROM core.webauthn_credentials WHERE user_id = $1::uuid`,
		userID).Scan(&survivor); err != nil {
		t.Fatal(err)
	}
	if survivor != kept {
		t.Errorf("the wrong credential survived: %s", survivor)
	}
}

// A credential id belonging to somebody else must not be deletable.
//
// The delete carries `WHERE user_id = $1 AND id = $2`. Dropping the first
// predicate would still pass every single-user test in this file while letting a
// caller destroy any credential in the deployment by id -- the tenancy boundary
// undone by an omitted clause, which is the failure this repository keeps
// finding and keeps writing tests against.
func TestAFactorBelongingToAnotherUserIsNotRemovable(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	victim := newDriftUser(t, s)
	victimKey := newDriftPasskey(t, s, victim)
	other := newDriftUser(t, s)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete,
		"/admin/users/"+other+"/factors/webauthn/"+victimKey, "", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deleting another user's credential gave %d, want 404: %s",
			rec.Code, rec.Body.String())
	}

	var alive int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM core.webauthn_credentials WHERE id = $1::uuid`,
		victimKey).Scan(&alive); err != nil {
		t.Fatal(err)
	}
	if alive != 1 {
		t.Fatal("the victim's credential was deleted through another user's " +
			"path. The user_id predicate is missing from the DELETE.")
	}
}

// The listing must not disclose credential material.
//
// A read scope must not be a slower route to the power a write scope has. The
// way that rule normally breaks is somebody selecting `*` because it was
// convenient, so this asserts against the response body rather than against the
// query text.
func TestTheFactorListingReturnsNoSecretMaterial(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUserWithTOTP(t, s)
	newDriftPasskey(t, s, userID)

	// A distinctive address and number, so their appearance in the body is
	// unmistakable rather than a coincidence.
	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO core.sms_otp_credentials (user_id, org_id, number, verified_at)
		VALUES ($1::uuid, $2::uuid, $3, now())`,
		userID, orgID, "+15550001111"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet,
		"/admin/users/"+userID+"/factors", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for _, forbidden := range []string{
		"not-a-real-secret", // the TOTP secret the fixture stores
		"not-a-real-key",    // the passkey's public key
		"+15550001111",      // the number behind the SMS factor
		"secret_enc", "code_hash", "public_key", "credential_id",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the factor listing discloses %q: %s", forbidden, body)
		}
	}

	// It still has to be useful, or the test above is satisfied by an empty
	// response.
	var parsed struct {
		Factors []struct {
			Type      string `json:"type"`
			Confirmed bool   `json:"confirmed"`
		} `json:"factors"`
		HasSecondFactor bool `json:"has_second_factor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Factors) != 3 {
		t.Fatalf("listed %d factors, want 3 (totp, webauthn, sms_otp): %s",
			len(parsed.Factors), body)
	}
	if !parsed.HasSecondFactor {
		t.Error("has_second_factor is false for a user holding three")
	}
}

// Recovery codes are counted, never listed.
func TestRecoveryCodesAreCountedNotListed(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	userID := newDriftUser(t, s)
	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	// `code_hash` is globally UNIQUE, so one hash cannot stand in for three --
	// which is itself worth knowing: no two accounts anywhere can hold the same
	// recovery code.
	for i := 0; i < 3; i++ {
		if _, err := s.db.Exec(ctx, `
			INSERT INTO core.recovery_codes (user_id, org_id, code_hash)
			VALUES ($1::uuid, $2::uuid, $3)`,
			userID, orgID,
			fmt.Sprintf("hash-of-a-recovery-code-%d-%d", time.Now().UnixNano(), i)); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, adminReq(t, http.MethodGet,
		"/admin/users/"+userID+"/factors", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("gave %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hash-of-a-recovery-code-") {
		t.Error("the listing contains recovery code material")
	}

	var parsed struct {
		Unused int `json:"recovery_codes_unused"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Unused != 3 {
		t.Errorf("recovery_codes_unused = %d, want 3", parsed.Unused)
	}
}

// An unknown factor kind is a 400, and never reaches SQL.
//
// The kind selects a TABLE NAME, which cannot be a bind parameter. The lookup is
// a fixed map for exactly that reason, and this asserts the closed set holds.
func TestAnUnknownFactorKindIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	userID := newDriftUser(t, s)

	// No spaces: httptest.NewRequest panics on a target it cannot parse, which
	// would abort the run rather than exercise the handler. The injection shape
	// is what matters and it survives the constraint.
	for _, kind := range []string{"clients", "users", "totp;DROP-TABLE-core.users", "unknown"} {
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, adminReq(t, http.MethodDelete,
			"/admin/users/"+userID+"/factors/"+kind, "", ""))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("factor kind %q gave %d, want 400 or 404: %s",
				kind, rec.Code, rec.Body.String())
		}
	}

	// The table the most hostile of those names is still there.
	var n int
	if err := s.db.QueryRow(context.Background(),
		`SELECT count(*) FROM core.users WHERE id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("core.users no longer holds the fixture user")
	}
}
