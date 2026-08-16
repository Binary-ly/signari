package sms

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormaliseNumber(t *testing.T) {
	ok := []struct{ in, want string }{
		{"+447700900123", "+447700900123"},
		{"+44 7700 900123", "+447700900123"},
		{"+1 (555) 010-9999", "+15550109999"},
		{"00447700900123", "+447700900123"},
		{"  +33612345678  ", "+33612345678"},
	}
	for _, c := range ok {
		got, err := NormaliseNumber(c.in)
		if err != nil {
			t.Errorf("%q was refused: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}

	bad := []string{
		"07700900123",        // national format: which country?
		"7700900123",         // no code at all
		"+0123456789",        // country codes do not start with zero
		"+44770090012345678", // longer than E.164 allows
		"+44abc",
		"",
		"+",
	}
	for _, c := range bad {
		if got, err := NormaliseNumber(c); err == nil {
			t.Errorf("%q was accepted as %q; a wrong number sends the code to "+
				"somebody else's phone", c, got)
		}
	}
}

// TestNationalFormatIsRefusedNotGuessed is the case worth naming.
func TestNationalFormatIsRefusedNotGuessed(t *testing.T) {
	_, err := NormaliseNumber("07700900123")
	if err == nil {
		t.Fatal("a national-format number was accepted")
	}
	if !strings.Contains(err.Error(), "international") {
		t.Fatalf("the error does not say how to fix it: %v", err)
	}
}

func TestRedactNumber(t *testing.T) {
	got := RedactNumber("+447700900123")
	if strings.Contains(got, "7700900") {
		t.Fatalf("%q still shows enough of the number to attack the operator", got)
	}
	if !strings.HasSuffix(got, "23") {
		t.Fatalf("%q does not show the last two digits, so nobody can recognise "+
			"their own number", got)
	}
}

// TestLogSenderRefuses: with no gateway, enrolment must fail rather than
// succeed and be undeliverable.
func TestLogSenderRefuses(t *testing.T) {
	s := NewLogSender(discardLogger())
	if err := s.Send(context.Background(), Message{To: "+447700900123", Body: "x"}); err == nil {
		t.Fatal("the log sender reported success; a factor nobody receives is a lockout")
	}
}

func TestTwilioSend(t *testing.T) {
	var gotTo, gotBody, gotFrom, gotService, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotTo, gotBody = r.PostForm.Get("To"), r.PostForm.Get("Body")
		gotFrom, gotService = r.PostForm.Get("From"), r.PostForm.Get("MessagingServiceSid")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM1"}`))
	}))
	defer srv.Close()

	s := &TwilioSender{AccountSID: "AC123", AuthToken: "secret", From: "+15550000000",
		BaseURL: srv.URL}
	if err := s.Send(context.Background(),
		Message{To: "+447700900123", Body: "Your code is 123456"}); err != nil {
		t.Fatal(err)
	}
	if gotTo != "+447700900123" || gotBody != "Your code is 123456" {
		t.Fatalf("sent To=%q Body=%q", gotTo, gotBody)
	}
	if gotFrom != "+15550000000" || gotService != "" {
		t.Fatalf("a phone number went in From=%q ServiceSid=%q", gotFrom, gotService)
	}
	if gotAuth == "" {
		t.Fatal("no basic auth was sent")
	}

	// A messaging service SID belongs in a DIFFERENT field, and sending it as
	// From is rejected with a message that does not say which one is wrong.
	s.From = "MG9999"
	if err := s.Send(context.Background(), Message{To: "+447700900123", Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if gotService != "MG9999" || gotFrom != "" {
		t.Fatalf("a messaging service went in From=%q ServiceSid=%q", gotFrom, gotService)
	}
}

// TestTwilioErrorCarriesTheCode: the code is the part with a fix attached.
func TestTwilioErrorCarriesTheCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":21610,"message":"Attempt to send to unsubscribed recipient","more_info":"https://www.twilio.com/docs/errors/21610"}`))
	}))
	defer srv.Close()

	s := &TwilioSender{AccountSID: "AC1", AuthToken: "t", From: "+1555", BaseURL: srv.URL}
	err := s.Send(context.Background(), Message{To: "+447700900123", Body: "x"})
	if err == nil {
		t.Fatal("a 400 was reported as success")
	}
	if !strings.Contains(err.Error(), "21610") {
		t.Fatalf("the error lost the code an operator needs: %v", err)
	}
}

func TestWebhookSend(t *testing.T) {
	var got map[string]string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = decodeJSON(r, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &WebhookSender{URL: srv.URL, AuthHeader: "Bearer abc"}
	if err := s.Send(context.Background(),
		Message{To: "+447700900123", Body: "code"}); err != nil {
		t.Fatal(err)
	}
	if got["to"] != "+447700900123" || got["body"] != "code" {
		t.Fatalf("posted %v", got)
	}
	if auth != "Bearer abc" {
		t.Fatalf("auth header %q", auth)
	}
}

func TestNewFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	if s, err := NewFromEnv(env(nil)); err != nil || s != nil {
		t.Fatalf("unset should be (nil, nil), got %v %v", s, err)
	}
	if _, err := NewFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "twilio"})); err == nil {
		t.Fatal("twilio with no credentials was accepted")
	}
	if _, err := NewFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "carrier-pigeon"})); err == nil {
		t.Fatal("an unknown gateway was accepted")
	}
	// A misspelt gateway must not silently become "no SMS".
	_, err := NewFromEnv(env(map[string]string{"SIGNARI_SMS_GATEWAY": "twilo"}))
	if err == nil {
		t.Fatal("a misspelt gateway fell back to nothing")
	}

	// A plaintext webhook carries a live code in the clear.
	if _, err := NewFromEnv(env(map[string]string{
		"SIGNARI_SMS_GATEWAY":     "webhook",
		"SIGNARI_SMS_WEBHOOK_URL": "http://sms.internal/send",
	})); err == nil {
		t.Fatal("a plaintext webhook URL was accepted")
	}
	// ...but localhost is how you test.
	if _, err := NewFromEnv(env(map[string]string{
		"SIGNARI_SMS_GATEWAY":     "webhook",
		"SIGNARI_SMS_WEBHOOK_URL": "http://localhost:9999/send",
	})); err != nil {
		t.Fatalf("localhost was refused: %v", err)
	}
}

func decodeJSON(r *http.Request, into any) error {
	return json.NewDecoder(r.Body).Decode(into)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
