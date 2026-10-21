package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Verifier is a delegated verification service: it makes the code, sends it
// and checks it, so this engine never holds one. Its own rules still apply
// here -- the countries, the daily allowances, the lifetime, the attempts per
// code and the consecutive-failure ceiling -- because they are this engine's
// promises about its factor, not the service's.
type Verifier interface {
	// Start asks for a code to be sent to an E.164 number.
	Start(ctx context.Context, to string) error
	// Check reports whether code is the one the service sent to. Anything but
	// a clear yes is no: an error says the service could not answer, and the
	// caller refuses the code rather than letting an outage sign anybody in.
	Check(ctx context.Context, to, code string) (bool, error)
	// Describe names the service for logs and for `signari doctor`.
	Describe() string
}

// VerifyWebhook speaks version 1 of this engine's verification contract to an
// operator's service, which can front any provider's verification API:
//
//	POST {"version":1,"action":"start","to":"+447700900123"}
//	     2xx: a code was sent
//	POST {"version":1,"action":"check","to":"+447700900123","code":"123456"}
//	     2xx {"approved":true}: the code is right, and the service spends it
//	     2xx {"approved":false}: it is not
//
// Every other answer is an error, so a check is approved only by the one
// answer that means approved.
type VerifyWebhook struct {
	HTTPGateway
	URL        string
	AuthHeader string
}

func (v *VerifyWebhook) Describe() string { return "verify-webhook (" + redactURL(v.URL) + ")" }

func (v *VerifyWebhook) Start(ctx context.Context, to string) error {
	_, err := v.post(ctx, map[string]any{"version": 1, "action": "start", "to": to})
	return err
}

func (v *VerifyWebhook) Check(ctx context.Context, to, code string) (bool, error) {
	body, err := v.post(ctx, map[string]any{"version": 1, "action": "check", "to": to, "code": code})
	if err != nil {
		return false, err
	}
	var answer struct {
		Approved *bool `json:"approved"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&answer); err != nil || answer.Approved == nil {
		return false, fmt.Errorf("the verification service's answer has no approved field: %.80q", body)
	}
	return *answer.Approved, nil
}

func (v *VerifyWebhook) post(ctx context.Context, payload map[string]any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if v.AuthHeader != "" {
		req.Header.Set("Authorization", v.AuthHeader)
	}
	resp, err := v.client(v.URL).Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting to the verification service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("the verification service answered %d: %s", resp.StatusCode,
			strings.TrimSpace(string(body)))
	}
	return body, nil
}
