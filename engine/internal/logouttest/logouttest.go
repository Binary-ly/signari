// Package logouttest proves whether a relying party's back-channel logout
// endpoint actually works.
//
// # Why this exists
//
// Back-channel logout is the part of OpenID Connect that most often does not
// work, and the failure is silent in both directions. The identity provider
// records a 200 and considers the session ended. The application returns that
// 200 from a handler that parsed nothing, verified nothing and deleted nothing.
// Everybody's dashboard is green and the session is still alive.
//
// Nobody ships a way to check. So an operator's only evidence that logout works
// is that the code exists.
//
// # What this checks that nothing else does
//
// Delivering a VALID logout token and getting a 200 proves very little: an
// endpoint that returns 200 unconditionally passes that test. What separates a
// working relying party from a decorative one is whether it REFUSES a token it
// should refuse.
//
// So this sends a valid token and then a series of tokens that are wrong in one
// specific way each — wrong audience, wrong issuer, no events claim, a nonce
// (forbidden), expired, unsigned, replayed. An endpoint that accepts any of
// those accepts a logout instruction from anyone who can reach it, which is a
// denial-of-service at best and a session-fixation lever at worst.
//
// # It cannot prove the session was destroyed
//
// Only that the token was accepted or refused. A relying party that verifies
// everything correctly and then forgets to delete the session still passes, and
// the report says so rather than implying otherwise.
package logouttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// BackchannelLogoutEvent is the event URI a logout token must carry.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// Case is one probe.
type Case struct {
	Name string
	// Why explains what accepting this token would mean, for the report.
	Why string
	// WantAccepted is true only for the token that is entirely valid.
	WantAccepted bool

	mutate func(*claims)
	// unsign replaces the signature with rubbish.
	unsign bool
	// replay sends the previous case's token again.
	replay bool
}

// Result is what happened.
type Result struct {
	Case
	Status   int
	Accepted bool
	Passed   bool
	Err      string
}

type claims struct {
	Issuer   string         `json:"iss"`
	Audience string         `json:"aud"`
	IssuedAt int64          `json:"iat"`
	Expiry   int64          `json:"exp"`
	JTI      string         `json:"jti"`
	Events   map[string]any `json:"events,omitempty"`
	Subject  string         `json:"sub,omitempty"`
	SID      string         `json:"sid,omitempty"`
	// Nonce must never appear in a logout token. It is here so one case can put
	// it there: OpenID Connect names it explicitly as prohibited, because a
	// logout token carrying one is an ID token being replayed as a logout.
	Nonce string `json:"nonce,omitempty"`
}

// Config is what to test.
type Config struct {
	// Endpoint is the relying party's backchannel_logout_uri.
	Endpoint string
	// ClientID is the audience the relying party expects.
	ClientID string
	// Issuer is this deployment.
	Issuer string
	// Subject and SID identify a session. Real values make the test meaningful
	// for a relying party that checks whether it knows the session; invented
	// ones still exercise every validation before that point.
	Subject string
	SID     string

	Timeout time.Duration
}

// Cases returns the probes, in order. The valid one runs first so a totally
// broken endpoint is reported as such before anything subtler is tried.
func Cases() []Case {
	return []Case{
		{
			Name: "a valid logout token", WantAccepted: true,
			Why:    "the endpoint must accept a correctly-signed logout token",
			mutate: func(*claims) {},
		},
		{
			Name: "wrong audience",
			Why: "accepting this means any client's logout token ends this " +
				"application's sessions",
			mutate: func(c *claims) { c.Audience = "some-other-client" },
		},
		{
			Name: "wrong issuer",
			Why: "accepting this means a token from another identity provider " +
				"ends sessions here",
			mutate: func(c *claims) { c.Issuer = "https://not-your-idp.example" },
		},
		{
			Name: "no events claim",
			Why: "the events claim is what distinguishes a logout token from an " +
				"ID token; accepting a token without it means an ID token can be " +
				"replayed as a logout",
			mutate: func(c *claims) { c.Events = nil },
		},
		{
			Name: "events claim without the logout event",
			Why:  "a token for some other event must not end a session",
			mutate: func(c *claims) {
				c.Events = map[string]any{"http://example.com/event/other": map[string]any{}}
			},
		},
		{
			Name: "contains a nonce",
			Why: "OpenID Connect prohibits nonce in a logout token precisely so " +
				"an ID token cannot be presented as one",
			mutate: func(c *claims) { c.Nonce = "n-0S6_WzA2Mj" },
		},
		{
			Name: "expired",
			Why:  "accepting an expired token widens the replay window indefinitely",
			mutate: func(c *claims) {
				c.Expiry = time.Now().Add(-10 * time.Minute).Unix()
				c.IssuedAt = time.Now().Add(-20 * time.Minute).Unix()
			},
		},
		{
			Name: "neither sub nor sid",
			Why: "a token naming no session and no subject is an instruction to " +
				"end nothing; accepting it reports success for a logout that did " +
				"not happen",
			mutate: func(c *claims) { c.Subject, c.SID = "", "" },
		},
		{
			Name: "broken signature",
			Why: "accepting this means anyone who can reach the endpoint can end " +
				"any session, with no key material at all",
			mutate: func(*claims) {}, unsign: true,
		},
		{
			Name: "replay of the first token",
			Why: "a logout token is single-use; accepting the same jti twice " +
				"means a captured token can be replayed",
			replay: true,
		},
	}
}

// Run delivers every probe and reports what happened.
func Run(ctx context.Context, cfg Config, key keys.Key) ([]Result, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("give -rp-url, the relying party's backchannel_logout_uri")
	}
	if !strings.HasPrefix(cfg.Endpoint, "https://") &&
		!strings.HasPrefix(cfg.Endpoint, "http://localhost") &&
		!strings.HasPrefix(cfg.Endpoint, "http://127.0.0.1") {
		return nil, fmt.Errorf("-rp-url must be https (or localhost for a local test): "+
			"a logout token is a signed instruction and %q would carry it in the clear",
			cfg.Endpoint)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("give -client-id, the audience the relying party expects")
	}
	if _, err := url.Parse(cfg.Endpoint); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Subject == "" {
		cfg.Subject = "00000000-0000-0000-0000-000000000000"
	}

	client := &http.Client{Timeout: cfg.Timeout}
	signer := tokens.NewSigner(key)

	var out []Result
	var firstToken string

	for _, c := range Cases() {
		token := firstToken
		if !c.replay {
			jti, err := newJTI()
			if err != nil {
				return nil, err
			}
			now := time.Now()
			cl := claims{
				Issuer:   cfg.Issuer,
				Audience: cfg.ClientID,
				IssuedAt: now.Unix(),
				Expiry:   now.Add(2 * time.Minute).Unix(),
				JTI:      jti,
				Events:   map[string]any{BackchannelLogoutEvent: map[string]any{}},
				Subject:  cfg.Subject,
				SID:      cfg.SID,
			}
			c.mutate(&cl)

			signed, err := signer.SignJSON(cl, tokens.TypLogoutToken)
			if err != nil {
				return nil, fmt.Errorf("signing the %q token: %w", c.Name, err)
			}
			if c.unsign {
				// Keep the header and payload, replace the signature. A relying
				// party that does not verify accepts this happily.
				parts := strings.Split(signed, ".")
				if len(parts) == 3 {
					signed = parts[0] + "." + parts[1] + ".ZmFrZXNpZ25hdHVyZQ"
				}
			}
			token = signed
			if firstToken == "" && c.WantAccepted {
				firstToken = signed
			}
		}
		if token == "" {
			out = append(out, Result{Case: c, Err: "no earlier token to replay"})
			continue
		}

		status, err := deliver(ctx, client, cfg.Endpoint, token)
		r := Result{Case: c, Status: status}
		if err != nil {
			r.Err = err.Error()
			out = append(out, r)
			continue
		}
		// 2xx is acceptance. Everything else is a refusal, which is what most of
		// these probes want.
		r.Accepted = status >= 200 && status < 300
		r.Passed = r.Accepted == c.WantAccepted
		out = append(out, r)
	}
	return out, nil
}

func deliver(ctx context.Context, c *http.Client, endpoint, token string) (int, error) {
	body := url.Values{"logout_token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
