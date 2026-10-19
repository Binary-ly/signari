// Command bench drives an identity provider over its standard protocols and
// reports throughput and latency per scenario, one JSON object per line.
//
// # What it measures, and against what
//
// Every scenario but one speaks a published protocol and finds its endpoints in
// the provider's discovery document: OpenID Connect discovery and JWKS, the
// OAuth token endpoint (client credentials, refresh chains), introspection
// (RFC 7662), userinfo, LDAP bind and search, RADIUS PAP (RFC 2865), SCIM
// (RFC 7644) and AuthZEN evaluation. So the same binary measures any deployment
// it is pointed at, and a comparison is the same command with a different
// -issuer. The one exception is `signin`, which drives Signari's own login and
// consent forms to an authorization code; `refresh` and `userinfo` start from
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
		return fmt.Errorf("give a command: run, seed or scenarios")
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "seed":
		return seedCommand(args[1:])
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
	return fmt.Errorf("unknown command %q: run, seed or scenarios", args[0])
}

// config is everything a scenario may need. Most use a handful of fields.
type config struct {
	Issuer, ClientID, ClientSecret, RedirectURI, Scope string
	CCScope                                            string
	Username, Password                                 string
	LDAPAddr, LDAPDNTemplate, LDAPBase                 string
	RADIUSAddr, RADIUSSecret                           string
	SCIMURL, SCIMToken, PDPURL, PDPToken               string
	AuthZENBody                                        string
	Concurrency                                        int
	Duration, Warmup                                   time.Duration
	Insecure                                           bool
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
	fs.StringVar(&c.RADIUSAddr, "radius", "", "host:port of a RADIUS server")
	fs.StringVar(&c.RADIUSSecret, "radius-secret", "", "its shared secret")
	fs.StringVar(&c.SCIMURL, "scim", "", "SCIM base URL, e.g. https://id.example.com/scim/v2")
	fs.StringVar(&c.SCIMToken, "scim-token", "", "bearer token for SCIM")
	fs.StringVar(&c.PDPURL, "pdp", "", "AuthZEN PDP base URL (defaults to -issuer)")
	fs.StringVar(&c.PDPToken, "pdp-token", "", "bearer token for the PDP")
	fs.StringVar(&c.AuthZENBody, "authzen-body", `{"subject":{"type":"user","id":"bench"},`+
		`"action":{"name":"read"},"resource":{"type":"document","id":"1"}}`, "evaluation request")
	fs.IntVar(&c.Concurrency, "c", 8, "concurrent workers")
	fs.DurationVar(&c.Duration, "d", 20*time.Second, "measured duration per scenario")
	fs.DurationVar(&c.Warmup, "warmup", 5*time.Second, "unmeasured run before each scenario")
	fs.BoolVar(&c.Insecure, "insecure", false, "skip TLS verification (a self-signed test deployment only)")
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
				t := time.Now()
				err := op(ctx)
				var shed shedError
				switch {
				case err == nil:
					mine.lat = append(mine.lat, time.Since(t))
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
