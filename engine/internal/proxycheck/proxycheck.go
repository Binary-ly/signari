// Package proxycheck proves that a forward-auth deployment actually protects
// the application behind it.
//
// # Why this exists
//
// Forward auth is configuration, not code, and it fails SILENTLY. The operator
// puts the middleware in front of the app, loads the home page, gets a login
// screen, and concludes it works. It very often does not:
//
//   - the middleware is attached to one router and not another
//   - `location /` is protected and `location /api` is not
//   - the app is still reachable on its own port, so the proxy is optional
//   - the proxy forwards the CALLER's X-Forwarded-User to the app unmodified
//
// Every one of those looks identical from a browser: you see a login page, so
// it must be working. Each is a full authentication bypass for anyone who
// requests a different path, method, or host.
//
// So this does what the operator cannot do by eye: it probes as an anonymous
// attacker would, and reports what answered.
//
// # What a result means
//
// A PASS here means "an unauthenticated request did not get content". It cannot
// mean "the application is secure" -- no external prober can establish that,
// and claiming otherwise would be the same false comfort this tool exists to
// remove. Everything is stated in terms of what was actually observed.
package proxycheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Status int

const (
	Protected Status = iota // refused, or sent to the identity provider
	Exposed                 // served content to nobody in particular
	Absent                  // nothing there; neither good nor bad news
	Unknown                 // could not reach it, or could not tell
)

type Result struct {
	Probe  string // what was tried, in the operator's terms
	Target string
	Status Status
	Detail string
	// Fix is printed only on failure and names the CONFIGURATION change, not the
	// symptom. An operator reading a report at speed acts on the fix line.
	Fix string
}

type Report struct {
	Results []Result
	// Reached records whether any probe got an HTTP response from the
	// application at all. Without it a typo'd hostname produces a report full of
	// "could not tell" that still ends in a verdict -- and an operator reading
	// quickly takes the absence of findings for a pass.
	Reached bool
}

func (r *Report) add(res Result) { r.Results = append(r.Results, res) }

// Exposed returns the findings that are genuine failures.
func (r *Report) Exposed() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Status == Exposed {
			out = append(out, res)
		}
	}
	return out
}

type Options struct {
	// BaseURL is the protected application AS THE BROWSER REACHES IT -- through
	// the proxy. Probing the app's own address instead would test nothing.
	BaseURL string
	// Issuer, when set, is checked to be where denials actually send people. A
	// deployment that redirects to some other identity provider is misconfigured
	// in a way that is invisible until someone reads the Location header.
	Issuer string
	// Origin is the application's DIRECT address, if the operator knows it
	// (`http://127.0.0.1:5678`). Supplying it turns on the bypass probe, which is
	// the highest-value check here and cannot be guessed.
	Origin string
	// Paths to probe in addition to the built-in list.
	Paths []string
	// Insecure skips certificate verification. It exists for internal CAs and
	// self-signed staging deployments. It is NOT a way to make a TLS failure go
	// away: a certificate the checker cannot verify is one browsers will refuse
	// too, so the report says plainly when it is on.
	Insecure bool
	Timeout  time.Duration
}

// riskyPaths are the ones that get forgotten.
//
// Not a scanner's wordlist -- each is here because it is a real hole in a real
// deployment. API and webhook prefixes are the dangerous ones: they are how the
// app is driven programmatically, they are frequently excluded from auth so
// that integrations keep working, and excluding them hands over the whole
// application to anyone who reads the app's own API documentation.
var riskyPaths = []string{
	"/",
	"/api",
	"/api/v1",
	"/rest",         // n8n's entire API lives here
	"/webhook",      // n8n, and most automation tools
	"/webhook-test", // n8n
	"/health",
	"/healthz",
	"/metrics", // Prometheus endpoints leak more than people expect
	"/admin",
	"/settings",
	"/static/../", // path traversal that some proxies normalise and some do not
	"/.env",
}

// Run executes every probe. It never stops early: an operator wants the whole
// list, not the first failure.
func Run(ctx context.Context, opt Options) (*Report, error) {
	if opt.Timeout == 0 {
		opt.Timeout = 10 * time.Second
	}
	base, err := url.Parse(strings.TrimRight(opt.BaseURL, "/"))
	if err != nil || !base.IsAbs() {
		return nil, fmt.Errorf("the application URL must be absolute, e.g. https://n8n.example.com")
	}

	client := &http.Client{
		Timeout: opt.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opt.Insecure}, //nolint:gosec // operator-selected, and reported
		},
		// Redirects are NOT followed. Following them would turn "sent to the login
		// page" into "200 from the login page" and invert the result of every
		// probe here.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	rep := &Report{}
	if opt.Insecure {
		rep.add(Result{
			Probe:  "certificate verification",
			Target: base.Host,
			Status: Unknown,
			Detail: "DISABLED by -insecure; nothing below says anything about TLS",
			Fix: "run without -insecure before trusting this report. A certificate " +
				"this checker will not verify is one a browser will not verify either.",
		})
	}
	paths := append(append([]string{}, riskyPaths...), opt.Paths...)
	seen := map[string]bool{}

	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		res := probePath(ctx, client, base, p, opt.Issuer)
		if res.Status != Unknown || !strings.Contains(res.Detail, "://") {
			// A transport error carries the URL it failed on; anything else means
			// something answered.
			rep.Reached = true
		}
		rep.add(res)
	}

	// Methods, because protection is sometimes written as a GET-only rule and a
	// POST then walks straight through.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rep.add(probeMethod(ctx, client, base, m))
	}

	rep.add(probeHeaderInjection(ctx, client, base))

	if opt.Origin != "" {
		rep.add(probeOriginBypass(ctx, client, opt.Origin, opt.Issuer))
	} else {
		rep.add(Result{
			Probe:  "direct-to-origin bypass",
			Target: "(not checked)",
			Status: Unknown,
			Detail: "no -origin given, so the most common bypass went unchecked",
			Fix: "re-run with -origin pointing at the application's own address " +
				"(the port in your compose file, e.g. -origin http://127.0.0.1:5678). " +
				"If that address answers from anywhere but the proxy, the proxy is optional.",
		})
	}

	sort.SliceStable(rep.Results, func(i, j int) bool {
		return rep.Results[i].Status < rep.Results[j].Status
	})
	return rep, nil
}

// classify turns a response into a verdict.
//
// The conservative direction matters: anything not clearly a refusal is treated
// as exposed, because a checker that resolves ambiguity in the deployment's
// favour is worse than no checker.
func classify(resp *http.Response, body []byte, issuer string) (Status, string) {
	loc := resp.Header.Get("Location")

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return Protected, fmt.Sprintf("%d, refused outright", resp.StatusCode)

	case resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "":
		if issuer != "" && strings.HasPrefix(loc, strings.TrimRight(issuer, "/")) {
			return Protected, fmt.Sprintf("%d to the identity provider", resp.StatusCode)
		}
		if issuer != "" {
			// Redirecting somewhere else is not automatically wrong -- it may be
			// the app's own login -- but it is not this identity provider doing
			// the protecting, and the operator believes it is.
			return Unknown, fmt.Sprintf("%d to %s, which is not the issuer given",
				resp.StatusCode, truncate(loc, 60))
		}
		return Protected, fmt.Sprintf("%d to %s", resp.StatusCode, truncate(loc, 60))

	case resp.StatusCode == http.StatusNotFound:
		return Absent, "404, nothing served here"

	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Exposed, fmt.Sprintf("%d, %d bytes served to an anonymous request",
			resp.StatusCode, len(body))
	}
	return Unknown, fmt.Sprintf("%d", resp.StatusCode)
}

func probePath(ctx context.Context, c *http.Client, base *url.URL, path, issuer string) Result {
	target := base.String() + path
	res := Result{Probe: "unauthenticated GET " + path, Target: target}

	resp, body, err := do(ctx, c, http.MethodGet, target, nil)
	if err != nil {
		res.Status, res.Detail = Unknown, err.Error()
		return res
	}
	res.Status, res.Detail = classify(resp, body, issuer)
	if res.Status == Exposed {
		if path == "/" {
			// The root being open means nothing is attached at all, which is a
			// different conversation from a path that slipped through.
			res.Fix = "the application root is served without authentication, so the " +
				"forward-auth middleware is not attached to this route at all. Check " +
				"that the router/location block naming this host lists the middleware."
		} else {
			res.Fix = fmt.Sprintf("%s is served without authentication. Attach the "+
				"forward-auth middleware to this path too -- protection applies per "+
				"route, and a rule on `/` does not cover `%s`.", path, path)
		}
	}
	return res
}

func probeMethod(ctx context.Context, c *http.Client, base *url.URL, method string) Result {
	target := base.String() + "/"
	res := Result{Probe: "unauthenticated " + method + " /", Target: target}

	resp, body, err := do(ctx, c, method, target, strings.NewReader("{}"))
	if err != nil {
		res.Status, res.Detail = Unknown, err.Error()
		return res
	}
	// 405 is the app declining the verb, which means the request REACHED the app.
	// That is an authentication bypass even though nothing useful came back.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		res.Status = Exposed
		res.Detail = "405 from the application: the request reached it unauthenticated"
		res.Fix = "the auth rule is conditional on the method. Protect all methods; " +
			"a rule written for GET leaves POST unauthenticated."
		return res
	}
	res.Status, res.Detail = classify(resp, body, "")
	if res.Status == Exposed {
		res.Fix = fmt.Sprintf("%s requests bypass authentication. Remove any method "+
			"condition from the auth rule.", method)
	}
	return res
}

// probeHeaderInjection is the most important probe in this file.
//
// The caller claims to be an administrator by simply saying so in a header. If
// the proxy passes the caller's header to the application rather than replacing
// it with the auth server's, and the application trusts that header -- which is
// exactly what forward auth asks it to do -- then authentication is a formality
// anyone can skip.
//
// Signari's own /proxy/verify deletes these headers before doing anything else.
// This probes the OTHER half of the deployment: the proxy configuration, which
// Signari does not control.
func probeHeaderInjection(ctx context.Context, c *http.Client, base *url.URL) Result {
	target := base.String() + "/"
	res := Result{Probe: "identity-header injection", Target: target}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		res.Status, res.Detail = Unknown, err.Error()
		return res
	}
	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Sub",
		"X-Auth-Request-User", "X-Auth-Request-Email", "Remote-User"} {
		req.Header.Set(h, "signari-proxy-check@invalid")
	}

	resp, err := c.Do(req)
	if err != nil {
		res.Status, res.Detail = Unknown, err.Error()
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	res.Status, res.Detail = classify(resp, body, "")
	if res.Status == Exposed {
		res.Detail = fmt.Sprintf("%d: an anonymous request that merely CLAIMED to be a "+
			"user in a header was served %d bytes", resp.StatusCode, len(body))
		res.Fix = "the proxy is forwarding the caller's identity headers instead of " +
			"replacing them. In nginx, set them from the auth response with " +
			"auth_request_set; in Traefik, list them in authResponseHeaders. Never " +
			"pass through a header the client can send."
	} else {
		res.Detail += "; a forged identity header did not get in"
	}
	return res
}

// probeOriginBypass answers the question that decides whether any of the rest
// matters: can the application be reached without going through the proxy?
func probeOriginBypass(ctx context.Context, c *http.Client, origin, issuer string) Result {
	target := strings.TrimRight(origin, "/") + "/"
	res := Result{Probe: "direct-to-origin bypass", Target: target}

	resp, body, err := do(ctx, c, http.MethodGet, target, nil)
	if err != nil {
		// Not answering is the DESIRED outcome, and the reason it did not answer
		// does not change the verdict -- refused, timed out and unresolvable all
		// mean the same thing to an attacker sitting where this check is running.
		//
		// "From here" is doing real work in that sentence. Run from the operator's
		// laptop this proves the origin is not reachable from the laptop, which is
		// not the same as unreachable from the internet.
		res.Status = Protected
		res.Detail = fmt.Sprintf("the origin did not answer from where this check ran (%s)",
			condense(err))
		return res
	}
	// Answering is not the same as bypassing. If that address enforces
	// authentication, it is very likely the proxy itself -- a misread of the
	// operator's own topology, not a hole. Calling that a critical finding is how
	// a checker teaches people to ignore it.
	st, detail := classify(resp, body, issuer)
	if st == Protected {
		res.Status = Protected
		res.Detail = detail + "; that address enforces authentication, so it is " +
			"the proxy rather than the origin behind it"
		return res
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.Status = Exposed
		res.Detail = fmt.Sprintf("%d: the application answered directly, bypassing the proxy entirely",
			resp.StatusCode)
		res.Fix = "the application's own port is reachable. Bind it to the internal " +
			"network only -- in Docker Compose, remove the `ports:` mapping and rely " +
			"on the shared network, so the proxy is the only route in. Everything " +
			"else in this report is irrelevant while this is true."
		return res
	}
	res.Status, res.Detail = st, detail
	return res
}

func do(ctx context.Context, c *http.Client, method, target string, body io.Reader) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "signari-proxy-check")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, b, nil
}

// condense shortens a transport error to its final clause, which is the part
// that says what happened ("connection refused") rather than the URL, which the
// report already prints on its own line.
func condense(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
