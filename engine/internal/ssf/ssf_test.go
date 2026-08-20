package ssf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fakeSigner records what it was asked to sign, so the wire shape can be
// asserted without a key.
type fakeSigner struct {
	claims any
	typ    string
}

func (f *fakeSigner) SignJSON(claims any, typ string) (string, error) {
	f.claims, f.typ = claims, typ
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return "hdr." + base64.RawURLEncoding.EncodeToString(b) + ".sig", nil
}

func decode(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sampleEvent() Event {
	return Event{
		Type: EventSessionRevoked,
		Subject: Subject{
			Format: "iss_sub", Issuer: "https://auth.example.com", Sub: "user-123",
		},
		EventTime:        time.Unix(1700000000, 0),
		ReasonAdmin:      "Administrator revoked the session.",
		ReasonUser:       "You were signed out by an administrator.",
		InitiatingEntity: "admin",
	}
}

func TestMintShape(t *testing.T) {
	f := &fakeSigner{}
	tok, err := Mint(f, "https://auth.example.com", "receiver-app", "jti-1",
		sampleEvent(), time.Unix(1700000005, 0))
	if err != nil {
		t.Fatal(err)
	}
	if f.typ != TypSET {
		t.Errorf("typ = %q, want %q -- a SET must not be confusable with an ID token",
			f.typ, TypSET)
	}

	m := decode(t, tok)
	if m["iss"] != "https://auth.example.com" {
		t.Errorf("iss = %v", m["iss"])
	}
	if m["jti"] != "jti-1" {
		t.Errorf("jti = %v", m["jti"])
	}
	aud, _ := m["aud"].([]any)
	if len(aud) != 1 || aud[0] != "receiver-app" {
		t.Errorf("aud = %v, want exactly the receiver", m["aud"])
	}

	events, ok := m["events"].(map[string]any)
	if !ok || len(events) != 1 {
		t.Fatalf("events = %v", m["events"])
	}
	payload, ok := events[EventSessionRevoked].(map[string]any)
	if !ok {
		t.Fatalf("the event is not keyed by its type URI: %v", events)
	}

	// event_timestamp in SECONDS. Milliseconds here is a common silent
	// interoperability bug -- the receiver reads a date forty thousand years out.
	if ts, _ := payload["event_timestamp"].(float64); int64(ts) != 1700000000 {
		t.Errorf("event_timestamp = %v, want 1700000000 (seconds)", payload["event_timestamp"])
	}
	// And it is the time the thing HAPPENED, not when the token was minted.
	if iat, _ := m["iat"].(float64); int64(iat) != 1700000005 {
		t.Errorf("iat = %v, want the mint time", m["iat"])
	}

	subj, _ := payload["subject"].(map[string]any)
	if subj["sub"] != "user-123" || subj["format"] != "iss_sub" {
		t.Errorf("subject = %v", subj)
	}
}

// TestAudienceIsRequired.
//
// A SET with no audience is a token one receiver can forward to another --
// which is how one relying party ends another's sessions.
func TestAudienceIsRequired(t *testing.T) {
	if _, err := Mint(&fakeSigner{}, "https://auth.example.com", "", "jti",
		sampleEvent(), time.Now()); err == nil {
		t.Fatal("minted a security event token with no audience")
	}
}

func TestSubjectIsRequired(t *testing.T) {
	e := sampleEvent()
	e.Subject.Sub = ""
	if _, err := Mint(&fakeSigner{}, "https://auth.example.com", "rp", "jti",
		e, time.Now()); err == nil {
		t.Fatal("minted an event with no subject")
	}
}

// TestNoEmailInTheSubject. A receiver matching on email is vulnerable to the
// same account confusion the federation code refuses; the subject we issued is
// the only identifier both sides agree on.
func TestNoEmailInTheSubject(t *testing.T) {
	tok, err := Mint(&fakeSigner{}, "https://auth.example.com", "rp", "jti",
		sampleEvent(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tok, "@") {
		t.Error("the token appears to contain an email address")
	}
	m := decode(t, tok)
	events := m["events"].(map[string]any)
	payload := events[EventSessionRevoked].(map[string]any)
	subj := payload["subject"].(map[string]any)
	for k := range subj {
		if k == "email" {
			t.Error("the subject carries an email address")
		}
	}
}

// TestSubscriptionIsAnAllowList.
//
// An empty subscription means NOTHING, not everything. A receiver that
// registered without naming event types has not asked to be told about
// credential changes, and sending them anyway discloses more than it was given.
func TestSubscriptionIsAnAllowList(t *testing.T) {
	if Wants(nil, EventSessionRevoked) {
		t.Error("an empty subscription was treated as subscribing to everything")
	}
	if Wants([]string{}, EventCredentialChange) {
		t.Error("same, for an empty slice")
	}
	if !Wants([]string{EventSessionRevoked}, EventSessionRevoked) {
		t.Error("an explicit subscription was not honoured")
	}
	if Wants([]string{EventSessionRevoked}, EventCredentialChange) {
		t.Error("subscribing to one event type delivered another")
	}
}

// TestSupportedEventsAreOnlyWhatWeSend.
//
// A receiver subscribing to an event we never emit waits forever for a signal
// that will not come, and would rather have known at subscription time.
func TestSupportedEventsAreOnlyWhatWeSend(t *testing.T) {
	supported := SupportedEvents()
	if len(supported) == 0 {
		t.Fatal("nothing is advertised")
	}
	for _, e := range supported {
		if e != EventSessionRevoked && e != EventCredentialChange {
			t.Errorf("%q is advertised but this engine does not emit it", e)
		}
	}
	// The two defined but unemitted types must NOT be advertised.
	for _, e := range supported {
		if e == EventAssuranceChange || e == EventTokenClaimsChange {
			t.Errorf("%q is advertised and never sent", e)
		}
	}
}

func TestReasonsAreSeparate(t *testing.T) {
	tok, _ := Mint(&fakeSigner{}, "https://auth.example.com", "rp", "jti",
		sampleEvent(), time.Now())
	m := decode(t, tok)
	payload := m["events"].(map[string]any)[EventSessionRevoked].(map[string]any)

	admin, _ := payload["reason_admin"].(map[string]any)
	user, _ := payload["reason_user"].(map[string]any)
	if admin["en"] == user["en"] {
		t.Error("the administrator and user reasons are identical; they are separate " +
			"fields because the useful phrasing differs and the admin one may name " +
			"internal detail")
	}
}

// SSF 1.0 §3.1: "claim named sub_id MUST be used to describe the primary subject
// of the event", and §3.1.1: "MUST include the top-level sub_id claim even for
// these existing event types" — CAEP and RISC, which is everything we emit.
//
// Found on the second pass over this specification. The first pass covered
// §4.1.x SET validation and §7.1 transmitter metadata; it never opened §3, which
// is the part that decides WHO an event is about.
//
// The subject travelled inside the event object as `subject`, the pre-1.0 CAEP
// shape. A conformant 1.0 receiver reads the top level, finds nothing, and cannot
// tell who the event concerns. The first pass sharpened this without noticing:
// it added spec_version "1_0" to our metadata, so we advertised Final while
// emitting draft-shaped subjects.
func TestMintEmitsTheTopLevelSubID(t *testing.T) {
	raw, err := Mint(&fakeSigner{}, "https://idp.example", "https://rp.example",
		"jti-1", Event{
			Type:      EventSessionRevoked,
			Subject:   Subject{Format: "iss_sub", Issuer: "https://idp.example", Sub: "user-1"},
			EventTime: time.Now(),
		}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	claims := decode(t, raw)

	sub, ok := claims["sub_id"].(map[string]any)
	if !ok {
		t.Fatalf("no top-level sub_id; §3.1 makes it the claim that describes the "+
			"subject and §3.1.1 requires it even for CAEP events: %v", claims)
	}
	if sub["sub"] != "user-1" || sub["iss"] != "https://idp.example" {
		t.Errorf("sub_id does not name the subject: %v", sub)
	}
	if sub["format"] != "iss_sub" {
		t.Errorf("sub_id carries no format: %v", sub)
	}

	// The event-level subject is kept for receivers written against the earlier
	// drafts. §3.1.1 requires the top-level claim for existing CAEP types; it does
	// not forbid this one.
	events, _ := claims["events"].(map[string]any)
	ev, _ := events[EventSessionRevoked].(map[string]any)
	if _, ok := ev["subject"].(map[string]any); !ok {
		t.Errorf("the event-level subject was dropped; a pre-1.0 receiver would "+
			"now be unable to read it: %v", ev)
	}
}
