// Package captcha verifies a challenge response, when one is configured.
//
// # Off by default, and adaptive when on
//
// A CAPTCHA is a tax on real users. It is paid by everybody, every time, to
// inconvenience a population that increasingly solves them more reliably than
// people do -- and the people it fails hardest are the ones using a screen
// reader, an old browser, or a connection that looks unusual.
//
// So there are three modes and the default is off:
//
//	off       nothing is shown, nothing is checked
//	adaptive  shown only after repeated failures from the same address
//	always    shown on every login
//
// Adaptive is the one worth having. A person signing in normally never sees a
// CAPTCHA; a script working through a password list sees one after a handful of
// attempts.
//
// # What adaptive does not do
//
// It counts failures per source address, in memory. An attacker with a large
// pool of addresses gets a fresh allowance from each, and that is a real limit
// rather than an oversight -- it is stated here so nobody mistakes this for
// protection against a distributed attack. What it stops is the unsophisticated
// case, which is most of them, and it does so without charging every legitimate
// user for the privilege.
//
// The per-account throttle and the global rate limit in front of Argon2 are what
// bound the distributed case, and neither depends on this.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Mode is when a challenge is required.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeAdaptive Mode = "adaptive"
	ModeAlways   Mode = "always"
)

// Provider is which service verifies the response.
//
// All three take the same shape -- POST secret and response, receive JSON with a
// `success` boolean -- so they differ only in a URL. Supporting one and calling
// it pluggable would be a claim rather than a feature.
type Provider string

const (
	Turnstile Provider = "turnstile"
	HCaptcha  Provider = "hcaptcha"
	ReCaptcha Provider = "recaptcha"
)

var verifyURLs = map[Provider]string{
	Turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	HCaptcha:  "https://hcaptcha.com/siteverify",
	ReCaptcha: "https://www.google.com/recaptcha/api/siteverify",
}

// Config is how a deployment has set this up.
type Config struct {
	Mode     Mode
	Provider Provider
	SiteKey  string
	Secret   string
	// FailuresBeforeChallenge is the adaptive threshold, per source address.
	FailuresBeforeChallenge int
	// FailClosed decides what happens when the provider cannot be reached.
	//
	// Default false, deliberately. This check sits in FRONT of a password, not
	// instead of one: failing open degrades to exactly the security posture of
	// having no CAPTCHA, while failing closed turns somebody else's outage into
	// a total authentication outage on an identity provider. An operator who
	// would rather be down can set it, and the reasoning should be theirs.
	FailClosed bool
}

// Verifier checks responses and tracks pressure.
type Verifier struct {
	cfg    Config
	client *http.Client

	mu       sync.Mutex
	failures map[string]*counter
}

type counter struct {
	n    int
	seen time.Time
}

// failureWindow is how long a failed attempt counts toward a challenge.
const failureWindow = 15 * time.Minute

func New(cfg Config, client *http.Client) *Verifier {
	if cfg.FailuresBeforeChallenge <= 0 {
		cfg.FailuresBeforeChallenge = 3
	}
	if client == nil {
		// Short, because this is in front of a login. A provider that takes ten
		// seconds has already cost more than it is worth.
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{cfg: cfg, client: client, failures: map[string]*counter{}}
}

// Enabled reports whether anything is configured at all.
func (v *Verifier) Enabled() bool {
	return v != nil && v.cfg.Mode != "" && v.cfg.Mode != ModeOff && v.cfg.Secret != ""
}

// SiteKey is what the page needs to render a widget.
//
// Nil-safe like every method here. The login renderer reads it on every request
// whether or not a challenge is configured, and an unconfigured deployment is
// the common case -- so "the caller should check first" is a rule that will be
// broken, and was: this returned a panic on the sign-in page until a test found
// it.
func (v *Verifier) SiteKey() string {
	if v == nil {
		return ""
	}
	return v.cfg.SiteKey
}

// Provider names the service, so the page can load the right widget.
func (v *Verifier) Provider() Provider {
	if v == nil {
		return ""
	}
	return v.cfg.Provider
}

// Required reports whether this request must carry a solved challenge.
func (v *Verifier) Required(remoteAddr string) bool {
	if !v.Enabled() {
		return false
	}
	if v.cfg.Mode == ModeAlways {
		return true
	}

	key := addrKey(remoteAddr)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	c := v.failures[key]
	return c != nil && c.n >= v.cfg.FailuresBeforeChallenge
}

// RecordFailure counts a failed sign-in from an address.
//
// Called for EVERY failure, including ones where no such account exists.
// Counting only real accounts would make the appearance of a CAPTCHA an oracle
// for which usernames are worth guessing.
func (v *Verifier) RecordFailure(remoteAddr string) {
	if !v.Enabled() || v.cfg.Mode != ModeAdaptive {
		return
	}
	key := addrKey(remoteAddr)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	c := v.failures[key]
	if c == nil {
		c = &counter{}
		v.failures[key] = c
	}
	c.n++
	c.seen = time.Now()
}

// Clear forgets an address after a successful sign-in.
func (v *Verifier) Clear(remoteAddr string) {
	if !v.Enabled() {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.failures, addrKey(remoteAddr))
}

// sweepLocked drops entries past the window. Called on every access rather than
// by a timer: the map only grows while attacks are in progress, and an unbounded
// map fed by request data is itself a way to exhaust memory.
func (v *Verifier) sweepLocked() {
	cutoff := time.Now().Add(-failureWindow)
	for k, c := range v.failures {
		if c.seen.Before(cutoff) {
			delete(v.failures, k)
		}
	}
}

// Verify checks a response token with the provider.
func (v *Verifier) Verify(ctx context.Context, response, remoteAddr string) error {
	if !v.Enabled() {
		return nil
	}
	if strings.TrimSpace(response) == "" {
		return fmt.Errorf("no challenge response was submitted")
	}

	endpoint, ok := verifyURLs[v.cfg.Provider]
	if !ok {
		return fmt.Errorf("unknown captcha provider %q", v.cfg.Provider)
	}

	form := url.Values{}
	form.Set("secret", v.cfg.Secret)
	form.Set("response", response)
	if ip := addrKey(remoteAddr); ip != "" {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return v.unreachable(fmt.Errorf("the captcha provider could not be reached: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return v.unreachable(fmt.Errorf("the captcha provider gave an unreadable answer: %w", err))
	}
	if !body.Success {
		return fmt.Errorf("the challenge was not solved (%s)",
			strings.Join(body.ErrorCodes, ", "))
	}
	return nil
}

// unreachable applies the fail-open or fail-closed decision.
func (v *Verifier) unreachable(err error) error {
	if v.cfg.FailClosed {
		return err
	}
	// Deliberately nil: the password check still has to pass. See Config.
	return nil
}

// addrKey reduces a remote address to something worth counting.
func addrKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// ParseMode reads a configured mode, refusing anything it does not recognise.
//
// An unknown value becomes "off" in many systems, which is the worst outcome: an
// operator who typed "adaptative" believes they have a control they do not.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeOff:
		return ModeOff, nil
	case ModeAdaptive:
		return ModeAdaptive, nil
	case ModeAlways:
		return ModeAlways, nil
	default:
		return "", fmt.Errorf("unknown captcha mode %q: use off, adaptive or always", s)
	}
}

// ParseProvider likewise.
func ParseProvider(s string) (Provider, error) {
	p := Provider(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := verifyURLs[p]; ok {
		return p, nil
	}
	return "", fmt.Errorf("unknown captcha provider %q: use turnstile, hcaptcha or recaptcha", s)
}
