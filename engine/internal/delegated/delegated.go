package delegated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrRejected means the old provider said these credentials are wrong. The
	// user simply fails to sign in, exactly as they would have on the old system.
	ErrRejected = errors.New("delegated: the source provider rejected the credentials")

	// ErrUnavailable means we could not ask. Deliberately distinct from
	// ErrRejected: an outage at the old provider must NOT be reported to the user
	// as a wrong password, and must not count as a failed attempt against them.
	ErrUnavailable = errors.New("delegated: the source provider could not be reached")
)

// Source is one configured provider to migrate from.
type Source struct {
	ID            string
	Kind          string
	DisplayName   string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Scope         string
}

// Verifier asks a source whether a password is correct.
type Verifier struct {
	client *http.Client
}

func New() *Verifier {
	return &Verifier{
		client: &http.Client{
			// Short. This sits on the login path, and a slow third party must not
			// hold a connection open long enough to be a denial of service against
			// our own sign-in.
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A token endpoint does not redirect. Following one would forward
				// the user's password to wherever the redirect pointed, which is
				// the worst possible way to lose a credential.
				return http.ErrUseLastResponse
			},
		},
	}
}

// Verify forwards the credentials to the source provider.
//
// The password is sent to a THIRD PARTY. That is the entire point and it is also
// the risk, so two things are enforced here rather than left to configuration:
//
//   - HTTPS ONLY. Forwarding a password over plaintext would hand it to anyone
//     on the path, and no convenience justifies it.
//   - The response body is size-limited. A hostile or broken endpoint must not be
//     able to exhaust memory on the login path.
func (v *Verifier) Verify(ctx context.Context, s Source, username, password string) error {
	if s.Kind != "oidc_password" {
		return fmt.Errorf("delegated: unsupported source kind %q", s.Kind)
	}
	u, err := url.Parse(s.TokenEndpoint)
	if err != nil || u.Scheme != "https" {
		// Checked here, not only at configuration time: a source edited in the
		// database directly must not be able to downgrade the transport.
		return fmt.Errorf("%w: token endpoint must be https, got %q", ErrUnavailable, s.TokenEndpoint)
	}

	form := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      {s.Scope},
		"client_id":  {s.ClientID},
	}
	if s.ClientSecret != "" {
		form.Set("client_secret", s.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch {
	case resp.StatusCode == http.StatusOK:
		// A 200 alone is not proof: some gateways return 200 with an error body.
		// The presence of an access token is what means "accepted".
		var ok struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		if json.Unmarshal(body, &ok) == nil && ok.AccessToken != "" && ok.Error == "" {
			return nil
		}
		return ErrRejected

	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		// invalid_grant is a wrong password. invalid_client is OUR
		// misconfiguration and must not be reported as the user's fault -- it
		// would otherwise look like every user in the org suddenly typed their
		// password wrong.
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "invalid_client" || e.Error == "unauthorized_client" ||
			e.Error == "unsupported_grant_type" {
			return fmt.Errorf("%w: source rejected OUR client (%s)", ErrUnavailable, e.Error)
		}
		return ErrRejected

	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: source returned %d", ErrUnavailable, resp.StatusCode)

	case resp.StatusCode == http.StatusTooManyRequests:
		// Being rate limited by the old provider is not evidence about the user.
		return fmt.Errorf("%w: source rate limited us", ErrUnavailable)

	default:
		return fmt.Errorf("%w: source returned %d", ErrUnavailable, resp.StatusCode)
	}
}
