package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Gateways.
//
// Two shapes cover almost everything: Twilio's form-encoded API, which several
// providers clone outright, and a generic JSON webhook for everybody else --
// including the in-house SMS relay that large organisations tend to have and
// that no vendor SDK will ever support.
//
// # Why no vendor SDKs
//
// Each one is a dependency in the authentication path, updated on somebody
// else's schedule, pulling in its own transitive tree. These two requests are
// twenty lines each. The trade is not close.

// HTTPGateway is the shared HTTP behaviour of both.
type HTTPGateway struct {
	Client *http.Client
	// Timeout bounds a send. A gateway that hangs must not hold a sign-in open:
	// the person is staring at a form waiting for a code.
	Timeout time.Duration
}

func (g *HTTPGateway) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	t := g.Timeout
	if t <= 0 {
		t = 10 * time.Second
	}
	return &http.Client{Timeout: t}
}

// TwilioSender speaks the Twilio Programmable Messaging API.
type TwilioSender struct {
	HTTPGateway
	AccountSID string
	AuthToken  string
	// From is the sending number or messaging service SID.
	From string
	// BaseURL is overridden in tests. Empty uses Twilio's own.
	BaseURL string
}

func (t *TwilioSender) Describe() string {
	return "twilio (account " + redactSID(t.AccountSID) + ")"
}

func (t *TwilioSender) Send(ctx context.Context, m Message) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.twilio.com"
	}
	endpoint := fmt.Sprintf("%s/2010-04-01/Accounts/%s/Messages.json", base, t.AccountSID)

	form := url.Values{}
	form.Set("To", m.To)
	form.Set("Body", m.Body)
	// A messaging service SID goes in a different field from a phone number,
	// and sending one as the other is rejected with a message that does not say
	// which of the two you got wrong.
	if strings.HasPrefix(t.From, "MG") {
		form.Set("MessagingServiceSid", t.From)
	} else {
		form.Set("From", t.From)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.AccountSID, t.AuthToken)

	resp, err := t.client().Do(req)
	if err != nil {
		return fmt.Errorf("sending via twilio: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		// Twilio's error codes are the useful part and the operator needs them:
		// 21211 is a bad number, 21608 is an unverified number on a trial
		// account, 21610 is a recipient who replied STOP. Each has a different
		// fix and "delivery failed" has none.
		return fmt.Errorf("twilio refused the message: %s", twilioDetail(resp.StatusCode, body))
	}
	return nil
}

func twilioDetail(status int, body []byte) string {
	var e struct {
		Message  string `json:"message"`
		Code     int    `json:"code"`
		MoreInfo string `json:"more_info"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Message != "" {
		if e.Code != 0 {
			return fmt.Sprintf("%s (code %d, %s)", e.Message, e.Code, e.MoreInfo)
		}
		return e.Message
	}
	return fmt.Sprintf("HTTP %d", status)
}

// WebhookSender posts JSON to an endpoint the deployment controls.
//
// For providers with their own API shape, and for the in-house relay a large
// organisation is likely to already have. The body is deliberately boring:
//
//	{"to": "+447700900123", "body": "Your code is 123456"}
type WebhookSender struct {
	HTTPGateway
	URL string
	// AuthHeader is sent verbatim, e.g. "Bearer ...". Empty sends none.
	AuthHeader string
}

func (w *WebhookSender) Describe() string { return "webhook (" + redactURL(w.URL) + ")" }

func (w *WebhookSender) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(map[string]string{"to": m.To, "body": m.Body})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.AuthHeader != "" {
		req.Header.Set("Authorization", w.AuthHeader)
	}

	resp, err := w.client().Do(req)
	if err != nil {
		return fmt.Errorf("posting to the SMS webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("the SMS webhook answered %d: %s", resp.StatusCode,
			strings.TrimSpace(string(detail)))
	}
	return nil
}

// NewFromEnv builds the configured gateway.
//
// Returns an error rather than falling back to the log sender: a deployment
// that sets SIGNARI_SMS_GATEWAY to something misspelt has stated an intention,
// and quietly doing nothing instead is how a second factor turns out to have
// been undeliverable for a month.
func NewFromEnv(getenv func(string) string) (Sender, error) {
	switch strings.ToLower(strings.TrimSpace(getenv("SIGNARI_SMS_GATEWAY"))) {
	case "":
		return nil, nil

	case "twilio":
		t := &TwilioSender{
			AccountSID: getenv("SIGNARI_SMS_TWILIO_SID"),
			AuthToken:  getenv("SIGNARI_SMS_TWILIO_TOKEN"),
			From:       getenv("SIGNARI_SMS_FROM"),
			BaseURL:    getenv("SIGNARI_SMS_TWILIO_BASE_URL"),
		}
		switch {
		case t.AccountSID == "":
			return nil, fmt.Errorf("SIGNARI_SMS_TWILIO_SID is required for the twilio gateway")
		case t.AuthToken == "":
			return nil, fmt.Errorf("SIGNARI_SMS_TWILIO_TOKEN is required for the twilio gateway")
		case t.From == "":
			return nil, fmt.Errorf("SIGNARI_SMS_FROM is required: the number or " +
				"messaging service SID messages are sent from")
		}
		return t, nil

	case "webhook":
		w := &WebhookSender{
			URL:        getenv("SIGNARI_SMS_WEBHOOK_URL"),
			AuthHeader: getenv("SIGNARI_SMS_WEBHOOK_AUTH"),
		}
		if w.URL == "" {
			return nil, fmt.Errorf("SIGNARI_SMS_WEBHOOK_URL is required for the webhook gateway")
		}
		u, err := url.Parse(w.URL)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("SIGNARI_SMS_WEBHOOK_URL is not a URL: %q", w.URL)
		}
		if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
			// The body carries a live one-time code. Over plaintext it is
			// readable by anything on the path, which makes the factor weaker
			// than the password it is protecting.
			return nil, fmt.Errorf("SIGNARI_SMS_WEBHOOK_URL must be https: the body " +
				"carries a live one-time code")
		}
		return w, nil

	default:
		return nil, fmt.Errorf("SIGNARI_SMS_GATEWAY must be twilio or webhook (got %q)",
			getenv("SIGNARI_SMS_GATEWAY"))
	}
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func redactSID(s string) string {
	if len(s) < 6 {
		return "•••"
	}
	return s[:2] + "•••" + s[len(s)-4:]
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "•••"
	}
	return u.Scheme + "://" + u.Host
}
