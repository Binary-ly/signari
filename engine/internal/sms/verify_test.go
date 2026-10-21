package sms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The verification contract, version 1, as an operator's service sees it, and
// approval only on the one answer that means it.
func TestTheVerifyWebhookSpeaksTheContract(t *testing.T) {
	var got []map[string]any
	answer := `{"approved":true}`
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers: %v", r.Header)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	v, err := NewVerifierFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "verify-webhook",
		"SIGNARI_SMS_VERIFY_URL": srv.URL, "SIGNARI_SMS_VERIFY_AUTH": "Bearer s3"}))
	if err != nil || v == nil {
		t.Fatalf("a loopback service was refused: %v", err)
	}
	ctx := context.Background()
	answer = `{"id":"VE123"}`
	id, err := v.Start(ctx, "+447700900123")
	if err != nil || id != "VE123" {
		t.Fatalf("start gave id %q (%v)", id, err)
	}
	answer = `{"approved":true}`
	if ok, err := v.Check(ctx, "+447700900123", "", "123456"); err != nil || !ok {
		t.Fatalf("approved: %v %v", ok, err)
	}
	// A number kept only as a hash: the id alone.
	if ok, err := v.Check(ctx, "", "VE123", "123456"); err != nil || !ok {
		t.Fatalf("approved by id: %v %v", ok, err)
	}
	if len(got) != 3 || got[0]["action"] != "start" || got[0]["version"] != float64(1) ||
		got[1]["action"] != "check" || got[1]["code"] != "123456" || got[1]["to"] != "+447700900123" ||
		got[1]["id"] != nil || got[2]["id"] != "VE123" || got[2]["to"] != nil {
		t.Errorf("the service was sent %v", got)
	}
	if _, err := v.Check(ctx, "", "", "123456"); err == nil {
		t.Error("a check with neither a number nor an id was sent")
	}
	// A service that gives no id is allowed.
	answer = ``
	if id, err := v.Start(ctx, "+447700900123"); err != nil || id != "" {
		t.Errorf("an empty start answer gave id %q (%v)", id, err)
	}
	for name, c := range map[string]struct {
		status int
		body   string
		ok     bool
		err    bool
	}{
		"not approved":       {200, `{"approved":false}`, false, false},
		"no approved field":  {200, `{"status":"approved"}`, false, true},
		"approved as string": {200, `{"approved":"true"}`, false, true},
		"empty":              {200, ``, false, true},
		"a server error":     {500, `{"approved":true}`, false, true},
	} {
		status, answer = c.status, c.body
		ok, err := v.Check(ctx, "+447700900123", "", "123456")
		if ok != c.ok || (err != nil) != c.err {
			t.Errorf("%s: approved %v, err %v", name, ok, err)
		}
	}
}

func TestTheVerifyWebhookIsConfiguredOrRefused(t *testing.T) {
	for name, e := range map[string]map[string]string{
		"no URL":     {"SIGNARI_SMS_GATEWAY": "verify-webhook"},
		"plain http": {"SIGNARI_SMS_GATEWAY": "verify-webhook", "SIGNARI_SMS_VERIFY_URL": "http://verify.example/v1"},
		"not a URL":  {"SIGNARI_SMS_GATEWAY": "verify-webhook", "SIGNARI_SMS_VERIFY_URL": "verify"},
	} {
		if _, err := NewVerifierFromEnv(env(e)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// No sender: the service sends only its own codes.
	if s, err := NewFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "verify-webhook"})); s != nil || err != nil {
		t.Errorf("verify-webhook built a sender %v (%v)", s, err)
	}
	if v, err := NewVerifierFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "webhook"})); v != nil || err != nil {
		t.Errorf("the plain webhook built a verifier %v (%v)", v, err)
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
