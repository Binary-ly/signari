package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func good() Provider {
	return Provider{
		Name: "p", Hook: HookAuthorize, URL: "https://pdp.example.test/decide",
		Mode: FailClosed, Timeout: time.Second,
	}
}

// A provider that does not say what happens when it is unreachable must be
// refused at registration.
//
// This is the whole safety argument of the package. The zero Mode is not one of
// the two valid values precisely so that a caller who forgets the field is
// stopped, rather than acquiring whichever constant happens to be declared first
// -- which today would be FailClosed, and would therefore look correct until the
// day somebody reorders a const block.
func TestAProviderWithNoFailureModeIsRefused(t *testing.T) {
	p := good()
	p.Mode = ""
	err := p.Validate()
	if err == nil {
		t.Fatal("a provider with no failure mode was accepted; the one question that " +
			"must never be defaulted was defaulted")
	}
	// The message has to name both options, because the author is about to choose
	// one and the wrong choice is silent.
	if !strings.Contains(err.Error(), string(FailClosed)) ||
		!strings.Contains(err.Error(), string(FailOpen)) {
		t.Errorf("the refusal does not name both modes: %v", err)
	}
}

// The predicate that keeps this package honest about its own staging.
//
// A hook that is DEFINED but not CONSULTED is a control an operator can
// configure that does nothing, which is the failure this project keeps finding
// in other systems and had for months in its own flow engine. The gap is
// declared rather than described, so it cannot rot in either direction: wire a
// hook up without updating Called() and operators keep being warned about one
// that now runs; widen Called() without wiring one and they stop being warned
// about one that does not.
//
// When a hook is wired, this test is what fails and says so.
func TestCalledMatchesWhatIsWired(t *testing.T) {
	// The hooks a decision point actually consults. HookAuthorize is called from
	// httpapi.consultAuthorizeProvider, on the AuthZEN evaluation path.
	wired := map[Hook]bool{HookAuthorize: true}

	for _, h := range allHooks {
		if h.Called() != wired[h] {
			t.Errorf("hook %q: Called() = %v, but the wired set says %v. If a decision "+
				"point now calls this hook, update both -- and if it does not, the "+
				"registration command is telling operators their provider runs when "+
				"nothing consults it", h, h.Called(), wired[h])
		}
	}

	var uncalled int
	for range Uncalled() {
		uncalled++
	}
	if uncalled != len(allHooks)-len(wired) {
		t.Errorf("Uncalled() returned %d hooks; %d are defined and %d wired, so it "+
			"is not reporting the gap accurately", uncalled, len(allHooks), len(wired))
	}
}

func TestValidateRefusesWhatCannotBeSafelyCalled(t *testing.T) {
	for _, tc := range []struct {
		name string
		with func(*Provider)
		want string
	}{
		{"no name", func(p *Provider) { p.Name = "" }, "name"},
		{"unknown hook", func(p *Provider) { p.Hook = "enrich_claims" }, "not a hook"},
		{"no timeout", func(p *Provider) { p.Timeout = 0 }, "timeout"},
		{"timeout above the ceiling", func(p *Provider) { p.Timeout = time.Hour }, "ceiling"},
		{"plaintext url", func(p *Provider) { p.URL = "http://pdp.example.test/d" }, ""},
		{"loopback url", func(p *Provider) { p.URL = "https://127.0.0.1/d" }, ""},
		{"link-local url", func(p *Provider) { p.URL = "https://169.254.169.254/latest" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := good()
			tc.with(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The metadata endpoint of a cloud instance is the canonical target of a
// server-side request forgery, and a provider URL is the kind of field that
// reaches one. Named separately from the table above because it is the case that
// matters rather than one of seven.
func TestAProviderCannotBePointedAtTheCloudMetadataService(t *testing.T) {
	p := good()
	p.URL = "https://169.254.169.254/latest/meta-data/iam/security-credentials/"
	if err := p.Validate(); err == nil {
		t.Fatal("a provider pointed at the link-local metadata address was accepted")
	}
}

type answer struct {
	Decision bool `json:"decision"`
}

// The ordinary case: the provider answers and the answer is decoded.
func TestCallDecodesAnAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	defer srv.Close()

	p := good()
	p.URL, p.Token = srv.URL, "s3cret"

	var out answer
	if err := p.Call(context.Background(), srv.Client(), map[string]any{"subject": "alice"}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !out.Decision {
		t.Error("the answer was not decoded")
	}
}

// A field this engine does not know must not fail the call.
//
// The opposite of the rule on our INBOUND surfaces, and deliberately: a provider
// written against a later revision of the contract will send fields we have never
// heard of, and refusing them would make every additive change to the contract a
// breaking change for the party we control least.
func TestAnUnknownFieldFromAProviderIsIgnoredRatherThanRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":true,"reason_v2":{"nested":1},"future":"x"}`))
	}))
	defer srv.Close()

	p := good()
	p.URL = srv.URL
	var out answer
	if err := p.Call(context.Background(), srv.Client(), struct{}{}, &out); err != nil {
		t.Fatalf("an answer carrying unknown fields was refused: %v", err)
	}
	if !out.Decision {
		t.Error("the known field was not decoded")
	}
}

// Every way of not answering is one error, because the caller's decision is the
// same for all of them.
func TestEveryFailureToAnswerIsUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"a 500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }},
		{"a 403", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }},
		{"an unparseable body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			p := good()
			p.URL = srv.URL
			var out answer
			err := p.Call(context.Background(), srv.Client(), struct{}{}, &out)
			var unreachable *ErrUnreachable
			if !errors.As(err, &unreachable) {
				t.Fatalf("err = %v, want ErrUnreachable", err)
			}
			if unreachable.Provider != p.Name {
				t.Errorf("the error does not name the provider: %v", err)
			}
		})
	}
}

// A 4xx is not a decision.
//
// Worth its own test because the tempting reading is the opposite: the provider
// answered, with a status, so surely that is an answer. It is not -- "I did not
// understand your request" is a contract mismatch, and treating it as a decision
// turns a version skew into a silent authorization change.
func TestARefusedRequestIsNotTreatedAsADecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	defer srv.Close()

	p := good()
	p.URL = srv.URL
	var out answer
	if err := p.Call(context.Background(), srv.Client(), struct{}{}, &out); err == nil {
		t.Fatal("a 400 carrying a decision-shaped body was accepted as a decision")
	}
	if out.Decision {
		t.Error("the body of a refused request was decoded into the answer")
	}
}

// The timeout is enforced, and the call does not outlive it.
func TestASlowProviderIsCutOff(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() { close(release); srv.Close() }()

	p := good()
	p.URL, p.Timeout = srv.URL, 50*time.Millisecond

	start := time.Now()
	var out answer
	err := p.Call(context.Background(), srv.Client(), struct{}{}, &out)
	if err == nil {
		t.Fatal("a provider that never answered was not cut off")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the call took %s; the timeout did not bound it", elapsed)
	}
}

// Decide is the single place the failure mode is applied, and it must apply it
// in both directions.
func TestDecideAppliesTheDeclaredFailureMode(t *testing.T) {
	boom := errors.New("connection refused")

	closed := good()
	closed.Mode = FailClosed
	if closed.Decide(boom) {
		t.Error("a fail-closed provider that was unreachable told the caller to " +
			"proceed. An authorization hook that fails open stops enforcing exactly " +
			"when something is wrong")
	}
	if !closed.Decide(nil) {
		t.Error("a fail-closed provider that ANSWERED stopped the journey; the mode " +
			"applies to being unreachable, not to every call")
	}

	open := good()
	open.Mode = FailOpen
	if !open.Decide(boom) {
		t.Error("a fail-open provider that was unreachable stopped the journey")
	}
	if !open.Decide(nil) {
		t.Error("a fail-open provider that answered stopped the journey")
	}
}
