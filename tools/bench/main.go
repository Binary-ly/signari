// Command bench drives an identity provider over its standard protocols and
// reports throughput and latency per scenario, one JSON object per line.
//
// # What it measures, and against what
//
// Every scenario but two speaks a published protocol and finds its endpoints in
// the provider's discovery document: OpenID Connect discovery and JWKS, the
// OAuth token endpoint (client credentials, refresh chains), introspection
// (RFC 7662), revocation (RFC 7009), pushed requests (RFC 9126), device
// authorization (RFC 8628), token exchange (RFC 8693), userinfo, LDAP bind and
// search, RADIUS PAP (RFC 2865), SCIM (RFC 7644) and AuthZEN evaluation.
// So the same binary measures any deployment it is pointed at, and a comparison
// is the same command with a different -issuer. The exceptions are `admin-list`,
// which reads Signari's Admin API, and `signin`, which drives Signari's own login
// and consent forms to an authorization code; `refresh` and `userinfo` start from
// it, since no published protocol obtains a person's tokens without a browser.
//
// # Why it is committed
//
// Every number in the benchmark notes used to come from a harness in a session
// scratchpad that was gone the next day, so no figure could be reproduced and
// none could be checked. This is that harness, kept.
//
// Usage:
//
//	bench run -issuer https://id.example.com -client-id bench -client-secret ... client-credentials introspect
//	bench seed -dsn postgres://signari_engine@localhost/signari -org <uuid> -template alice@example.com -users 100000
//	bench upstream -tls-cert cert.pem -tls-key key.pem
//	bench scenarios
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("give a command: run, seed, upstream or scenarios")
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "seed":
		return seedCommand(args[1:])
	case "upstream":
		return upstreamCommand(args[1:])
	case "totp":
		// For a script enrolling the people of the mfa scenario.
		if len(args) != 2 {
			return fmt.Errorf("give the base32 seed")
		}
		code, err := totpCode(args[1], time.Now())
		if err != nil {
			return err
		}
		fmt.Println(code)
		return nil
	case "scenarios":
		names := make([]string, 0, len(scenarios))
		for n := range scenarios {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("  %-20s %s\n", n, scenarios[n].help)
		}
		return nil
	}
	if command, ok := commands[args[0]]; ok {
		return command(args[1:])
	}
	return fmt.Errorf("unknown command %q: run, seed, upstream or scenarios", args[0])
}

// commands are further commands a file of its own adds at init, as a driver of another
// provider's pages does (signin.go's drivers).
var commands = map[string]func([]string) error{}

// signariAdminList is a page of the Admin API's people, which admin-list reads by default.
const signariAdminList = "/admin/users?limit=100"

// config is everything a scenario may need. Most use a handful of fields.
type config struct {
	// Driver names the product whose sign-in pages a scenario fills in (signin.go).
	Driver                                             string
	Issuer, ClientID, ClientSecret, RedirectURI, Scope string
	CCScope                                            string
	Username, Password                                 string
	LDAPAddr, LDAPDNTemplate, LDAPBase, LDAPFilter     string
	RADIUSAddr, RADIUSSecret                           string
	SCIMURL, SCIMToken, PDPURL, PDPToken               string
	AdminURL, AdminToken                               string
	AdminList, AdminListBody                           string
	PersonFormat, AssertionKID, TOTPSeeds              string
	PersonCounter                                      string
	AssertionAudience                                  string
	AuthZENBody, Via, TOTPSeed                         string
	AssertionKey, AssertionIssuer, AssertionSubject    string
	Concurrency, People, SignInPeople, PersonOffset    int
	Duration, Warmup                                   time.Duration
	Insecure                                           bool

	// Introspection where a provider offers it apart from discovery or to another
	// client: one serves it only on an administrative listener, another only to a
	// client registered as an API. Empty, the discovered endpoint and -client-id.
	IntrospectURL, IntrospectClientID, IntrospectClientSecret string
	// IntrospectPerson introspects a signed-in person's access token rather than the
	// client's own, client credentials, token.
	IntrospectPerson bool

	// SAML, for saml-sso: the provider's single sign-on URL (redirect binding), the
	// service provider's entity id the requests are issued as, and the assertion
	// consumer URL they ask for, which the provider must have registered.
	SAMLSSO, SAMLSP, SAMLACS string
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.Issuer, "issuer", "", "the provider's issuer URL; endpoints come from its discovery document")
	fs.StringVar(&c.ClientID, "client-id", "", "OAuth client")
	fs.StringVar(&c.ClientSecret, "client-secret", "", "its secret (client_secret_basic); empty for a public client")
	fs.StringVar(&c.RedirectURI, "redirect-uri", "https://bench.invalid/cb", "registered redirect URI (signin, refresh, userinfo)")
	fs.StringVar(&c.Scope, "scope", "openid offline_access", "scope asked for by signin")
	fs.StringVar(&c.CCScope, "cc-scope", "", "scope asked for by client-credentials and introspect "+
		"(empty asks for none; a provider may then refuse a registered openid, which names no person)")
	fs.StringVar(&c.Username, "username", "", "a person's sign-in name (signin, ldap-*, radius-pap)")
	fs.StringVar(&c.Password, "password", "", "their password")
	fs.StringVar(&c.LDAPAddr, "ldap", "", "ldap:// or ldaps:// URL")
	fs.StringVar(&c.LDAPDNTemplate, "ldap-dn", "uid=%s,dc=example,dc=com", "bind DN, %s replaced by -username")
	fs.StringVar(&c.LDAPBase, "ldap-base", "dc=example,dc=com", "search base")
	// A directory that keeps the sign-in name in cn and gives uid something else
	// finds nobody by uid, so the attribute searched is the directory's to name.
	fs.StringVar(&c.LDAPFilter, "ldap-filter", "(uid=%s)", "ldap-search's filter, %s replaced by -username, escaped")
	fs.StringVar(&c.RADIUSAddr, "radius", "", "host:port of a RADIUS server")
	fs.StringVar(&c.RADIUSSecret, "radius-secret", "", "its shared secret")
	fs.StringVar(&c.SCIMURL, "scim", "", "SCIM base URL, e.g. https://id.example.com/scim/v2")
	fs.StringVar(&c.SCIMToken, "scim-token", "", "bearer token for SCIM")
	fs.StringVar(&c.AdminURL, "admin", "", "the Admin API's base URL, e.g. https://127.0.0.1:8090")
	fs.StringVar(&c.AdminToken, "admin-token", "", "bearer token for the Admin API")
	// Another product's administrative API lists its people elsewhere, and one of them
	// takes the page it wants as a JSON query rather than in the URL (E.21).
	fs.StringVar(&c.AdminList, "admin-list", signariAdminList, "admin-list's path under -admin")
	fs.StringVar(&c.AdminListBody, "admin-list-body", "", "a JSON body to POST to it; empty is a GET")
	// A product with no realms keeps its MFA people apart from its password people by name.
	fs.StringVar(&c.PersonFormat, "person", "", "the n'th person's sign-in name, %d the number (bench-%d@bench.invalid when empty)")
	// A provider that limits what is asked of one person in a window (CIBA prompts) is
	// measured over people no earlier run has asked, each run from its own offset.
	fs.IntVar(&c.PersonOffset, "person-offset", 0, "added to every person's number")
	fs.StringVar(&c.PersonCounter, "person-counter", "", "a file holding where the turns through -people stand, read at the start and written at the end")
	fs.StringVar(&c.PDPURL, "pdp", "", "AuthZEN PDP base URL (defaults to -issuer)")
	fs.StringVar(&c.PDPToken, "pdp-token", "", "bearer token for the PDP")
	fs.StringVar(&c.AuthZENBody, "authzen-body", `{"subject":{"type":"user","id":"bench"},`+
		`"action":{"name":"read"},"resource":{"type":"document","id":"1"}}`, "evaluation request")
	fs.IntVar(&c.People, "people", 0, "how many seeded people to take turns with (ciba-start, mfa); see `bench seed`")
	fs.IntVar(&c.SignInPeople, "signin-people", 0, "signin, and the sign-in each worker of refresh, userinfo, token-exchange "+
		"and end-session makes, take turns through this many seeded people instead of -username; see `bench seed`")
	fs.StringVar(&c.Via, "via", "", "the slug of the upstream provider to sign in through (federated)")
	fs.StringVar(&c.Driver, "driver", "signari", "whose sign-in pages to fill in: signari, or a driver of another provider's pages that a file of its own adds")
	fs.StringVar(&c.TOTPSeed, "totp-seed", "", "the base32 seed the -people hold, each as `user assign-otp` gave it (mfa)")
	fs.StringVar(&c.TOTPSeeds, "totp-seeds", "", "a file of a line per person, their name and base32 seed, where each has their own (mfa)")
	fs.StringVar(&c.AssertionKey, "assertion-key", "", "PKCS#8 P-256 key that signs assertions (jwt-bearer)")
	fs.StringVar(&c.AssertionIssuer, "assertion-issuer", "", "the assertions' iss")
	fs.StringVar(&c.AssertionSubject, "assertion-subject", "", "the assertions' sub, linked to a person")
	fs.StringVar(&c.AssertionKID, "assertion-kid", "", "the assertions' kid, where the provider named the key (the upstream's when empty)")
	fs.StringVar(&c.AssertionAudience, "assertion-audience", "", "the assertions' aud (-issuer when empty; a token endpoint's URL where only that is taken)")
	fs.IntVar(&c.Concurrency, "c", 8, "concurrent workers")
	fs.DurationVar(&c.Duration, "d", 20*time.Second, "measured duration per scenario")
	fs.DurationVar(&c.Warmup, "warmup", 5*time.Second, "unmeasured run before each scenario")
	fs.BoolVar(&c.Insecure, "insecure", false, "skip TLS verification (a self-signed test deployment only)")
	fs.StringVar(&c.IntrospectURL, "introspect-url", "", "introspect here rather than at the discovered endpoint (introspect)")
	fs.StringVar(&c.IntrospectClientID, "introspect-client-id", "", "introspect as this client rather than -client-id (introspect)")
	fs.StringVar(&c.IntrospectClientSecret, "introspect-client-secret", "", "its secret (client_secret_basic)")
	fs.BoolVar(&c.IntrospectPerson, "introspect-person", false, "introspect a signed-in person's access token, one sign-in per worker, not a client credentials one (introspect)")
	fs.StringVar(&c.SAMLSSO, "saml-sso", "", "the provider's SAML single sign-on URL, redirect binding (saml-sso)")
	fs.StringVar(&c.SAMLSP, "saml-sp", "", "the service provider's entity id the AuthnRequests are issued as (saml-sso)")
	fs.StringVar(&c.SAMLACS, "saml-acs", "", "the assertion consumer URL they ask for, registered with the provider (saml-sso)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("name at least one scenario; `bench scenarios` lists them")
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("-c must be at least 1")
	}
	if c.PDPURL == "" {
		c.PDPURL = c.Issuer
	}
	if c.PersonCounter != "" {
		defer resumeTurns(c.PersonCounter)()
	}
	enc := json.NewEncoder(os.Stdout)
	for _, name := range fs.Args() {
		sc, ok := scenarios[name]
		if !ok {
			return fmt.Errorf("no scenario %q; `bench scenarios` lists them", name)
		}
		res, err := measure(context.Background(), &c, name, sc)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return nil
}

// resumeTurns carries on from where the last run stopped taking turns through -people, and
// returns what writes where this run stopped, so a person is not taken again until everybody
// has been: a TOTP code is good once in its 30 seconds, and a run that started again from the
// first person would replay one. A missing file is the start.
func resumeTurns(path string) (save func()) {
	if raw, err := os.ReadFile(path); err == nil { // #nosec G304 -- a file the operator of the bench names
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			nextPerson.Store(n)
		}
	}
	return func() {
		_ = os.WriteFile(path, []byte(strconv.FormatInt(nextPerson.Load(), 10)+"\n"), 0o600)
	}
}

// result is one scenario's line of output.
type result struct {
	Scenario    string  `json:"scenario"`
	Target      string  `json:"target"`
	Concurrency int     `json:"concurrency"`
	Seconds     float64 `json:"seconds"`
	Ops         int     `json:"ops"`
	Errors      int     `json:"errors"`
	PerSecond   float64 `json:"per_second"`
	P50ms       float64 `json:"p50_ms"`
	P95ms       float64 `json:"p95_ms"`
	P99ms       float64 `json:"p99_ms"`
	MaxMs       float64 `json:"max_ms"`
	FirstError  string  `json:"first_error,omitempty"`

	// Shed counts 429s: load the server refused on purpose, not failures.
	Shed      int    `json:"shed"`
	FirstShed string `json:"first_shed,omitempty"`
}

// httpClient is one worker's browser: its own cookie jar, and redirects
// returned rather than followed, so a scenario sees each hop.
func httpClient(c *config) *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = c.Concurrency * 2
	if c.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- asked for by -insecure
	}
	return &http.Client{
		Jar: jar, Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// measure runs a scenario's warm-up, then its measured window, and reduces the
// latencies. A worker that cannot be set up fails the scenario: a number made
// from fewer workers than asked for is not the number asked for.
func measure(ctx context.Context, c *config, name string, sc scenario) (result, error) {
	env, err := newEnv(ctx, c, sc.needsDiscovery)
	if err != nil {
		return result{}, err
	}
	ops := make([]func(context.Context) error, c.Concurrency)
	for i := range ops {
		op, err := sc.worker(ctx, env)
		if err != nil {
			return result{}, fmt.Errorf("setting up worker %d: %w", i, err)
		}
		ops[i] = op
	}
	if c.Warmup > 0 {
		run(ctx, ops, c.Warmup)
	}
	t := run(ctx, ops, c.Duration)
	return summarise(name, c, t), nil
}

// tally is one measured window.
type tally struct {
	lat         []time.Duration
	errs, shed  int
	first, shd1 string
	took        time.Duration
}

type setupKey struct{}

// outside runs what an operation needs but did not come to measure, and keeps its
// time out of the latency. A sign-out needs a sign-in first, and timing the pair would
// report the password hash. The throughput still pays for it, so read such a
// scenario's latency and not its per_second.
func outside(ctx context.Context, f func() error) error {
	t := time.Now()
	err := f()
	return errors.Join(err, outsideFor(ctx, time.Since(t)))
}

// outsideFor is outside for time already spent.
func outsideFor(ctx context.Context, d time.Duration) error {
	if setup, ok := ctx.Value(setupKey{}).(*time.Duration); ok {
		*setup += d
	}
	return nil
}

// run calls every op as fast as it answers until d has passed.
func run(ctx context.Context, ops []func(context.Context) error, d time.Duration) tally {
	deadline := time.Now().Add(d)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all tally
	start := time.Now()
	for _, op := range ops {
		wg.Add(1)
		go func(op func(context.Context) error) {
			defer wg.Done()
			var mine tally
			for time.Now().Before(deadline) {
				setup := new(time.Duration)
				t := time.Now()
				err := op(context.WithValue(ctx, setupKey{}, setup))
				took := time.Since(t) - *setup
				var shed shedError
				switch {
				case err == nil:
					mine.lat = append(mine.lat, took)
				case errors.As(err, &shed):
					mine.shed++
					if mine.shd1 == "" {
						mine.shd1 = err.Error()
					}
				default:
					mine.errs++
					if mine.first == "" {
						mine.first = err.Error()
					}
				}
			}
			mu.Lock()
			all.lat = append(all.lat, mine.lat...)
			all.errs += mine.errs
			all.shed += mine.shed
			if all.first == "" {
				all.first = mine.first
			}
			if all.shd1 == "" {
				all.shd1 = mine.shd1
			}
			mu.Unlock()
		}(op)
	}
	wg.Wait()
	all.took = time.Since(start)
	return all
}

func summarise(name string, c *config, t tally) result {
	lat := t.lat
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	took := t.took
	r := result{
		Scenario: name, Target: target(c), Concurrency: c.Concurrency,
		Seconds: took.Seconds(), Ops: len(lat), Errors: t.errs, FirstError: t.first,
		Shed: t.shed, FirstShed: t.shd1,
	}
	if took > 0 {
		r.PerSecond = float64(len(lat)) / took.Seconds()
	}
	if len(lat) > 0 {
		r.P50ms, r.P95ms, r.P99ms = ms(percentile(lat, 50)), ms(percentile(lat, 95)), ms(percentile(lat, 99))
		r.MaxMs = ms(lat[len(lat)-1])
	}
	return r
}

// percentile is the nearest-rank percentile of sorted durations.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

func target(c *config) string {
	for _, t := range []string{c.Issuer, c.LDAPAddr, c.RADIUSAddr, c.SCIMURL} {
		if t != "" {
			return strings.TrimRight(t, "/")
		}
	}
	return ""
}
