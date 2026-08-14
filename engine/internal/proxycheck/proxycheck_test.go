package proxycheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testIssuer = "https://auth.example.test"

// find returns the result for a probe whose name contains sub.
func find(t *testing.T, rep *Report, sub string) Result {
	t.Helper()
	for _, r := range rep.Results {
		if strings.Contains(r.Probe, sub) {
			return r
		}
	}
	t.Fatalf("no probe matching %q in %d results", sub, len(rep.Results))
	return Result{}
}

func run(t *testing.T, opt Options) *Report {
	t.Helper()
	rep, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// TestUnprotectedAppIsReportedOpen is the base case: the middleware was never
// attached. If this does not fail, the tool is decoration.
func TestUnprotectedAppIsReportedOpen(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret dashboard"))
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	if len(rep.Exposed()) == 0 {
		t.Fatal("an application that serves 200 to everyone was reported as protected")
	}
	if root := find(t, rep, "GET /"); root.Status != Exposed {
		t.Errorf("root probe = %v, want Exposed", root.Status)
	}
}

// TestProtectedAppPasses guards the other direction. False alarms are not a
// safe failure mode here: a checker that cries wolf gets muted, and then the
// real finding is muted too.
func TestProtectedAppPasses(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, testIssuer+"/proxy/start?rd=x", http.StatusFound)
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	for _, r := range rep.Exposed() {
		t.Errorf("false alarm on a correctly protected app: %s -- %s", r.Probe, r.Detail)
	}
}

// TestPartialCoverageIsCaught is the failure this tool exists for. The home
// page redirects to sign-in, so a browser check looks perfect, while the API
// the application is actually driven through is wide open.
func TestPartialCoverageIsCaught(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/rest") {
			_, _ = w.Write([]byte("api"))
			return
		}
		http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})

	if root := find(t, rep, "GET /"); root.Status != Protected {
		t.Errorf("root = %v, want Protected -- this is the part that looks fine in a browser", root.Status)
	}
	rest := find(t, rep, "GET /rest")
	if rest.Status != Exposed {
		t.Fatalf("/rest = %v, want Exposed", rest.Status)
	}
	if rest.Fix == "" {
		t.Error("an exposed path was reported with no fix; the operator is left to guess")
	}
}

// TestMethodOnlyRuleIsCaught covers auth written as a GET-only condition.
func TestMethodOnlyRuleIsCaught(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("created"))
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	if post := find(t, rep, "POST /"); post.Status != Exposed {
		t.Errorf("POST = %v, want Exposed: a GET-only auth rule leaves writes unauthenticated", post.Status)
	}
}

// TestMethodNotAllowedCountsAsReaching pins a subtle one. A 405 carries no data,
// so it reads like a refusal -- but only the APPLICATION can say a verb is not
// allowed, which means the request got past authentication to reach it.
func TestMethodNotAllowedCountsAsReaching(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	if post := find(t, rep, "POST /"); post.Status != Exposed {
		t.Errorf("POST = %v, want Exposed: a 405 means the application answered", post.Status)
	}
}

// TestHeaderInjection covers the deployment where the proxy passes the caller's
// identity headers straight through.
func TestHeaderInjection(t *testing.T) {
	// A proxy that trusts what the client sent, which is the whole bug.
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-User") != "" {
			_, _ = w.Write([]byte("welcome back"))
			return
		}
		http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	inj := find(t, rep, "identity-header injection")
	if inj.Status != Exposed {
		t.Fatalf("header injection = %v, want Exposed", inj.Status)
	}
	if !strings.Contains(inj.Fix, "auth_request_set") {
		t.Error("the fix should name the proxy directive that repairs it")
	}
}

// TestOriginBypass: reaching the app's own address means the proxy is optional,
// which makes every other result in the report beside the point.
func TestOriginBypass(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("the app itself"))
	}))
	defer origin.Close()
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
	}))
	defer proxied.Close()

	rep := run(t, Options{BaseURL: proxied.URL, Issuer: testIssuer, Origin: origin.URL})
	if b := find(t, rep, "direct-to-origin"); b.Status != Exposed {
		t.Errorf("origin bypass = %v, want Exposed", b.Status)
	}
}

// TestOriginPointingAtTheProxyIsNotABypass is the false-positive guard.
//
// Operators mix up which address is which, and reporting a critical bypass
// because someone passed the proxy's own URL trains them to disbelieve the
// finding that matters.
func TestOriginPointingAtTheProxyIsNotABypass(t *testing.T) {
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, testIssuer+"/proxy/start", http.StatusFound)
	}))
	defer proxied.Close()

	rep := run(t, Options{BaseURL: proxied.URL, Issuer: testIssuer, Origin: proxied.URL})
	if b := find(t, rep, "direct-to-origin"); b.Status != Protected {
		t.Errorf("origin = proxy reported %v, want Protected: that address enforces auth", b.Status)
	}
}

// TestRedirectToSomewhereElseIsNotAPass -- being sent to a DIFFERENT identity
// provider is not proof that this one is protecting anything, and quietly
// passing it would hide a deployment pointed at the wrong issuer.
func TestRedirectToSomewhereElseIsNotAPass(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://some-other-idp.test/login", http.StatusFound)
	}))
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL, Issuer: testIssuer})
	root := find(t, rep, "GET /")
	if root.Status == Protected {
		t.Error("a redirect to an unrelated issuer was reported as protected by this one")
	}
	if !strings.Contains(root.Detail, "not the issuer given") {
		t.Errorf("detail should say the issuer did not match; got %q", root.Detail)
	}
}

// TestRedirectsAreNotFollowed. Following them would fetch the login page and
// score its 200 as the application being open, inverting every verdict.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var loginHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHits++
		_, _ = w.Write([]byte("<form>sign in</form>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	app := httptest.NewServer(mux)
	defer app.Close()

	rep := run(t, Options{BaseURL: app.URL})
	if loginHits != 0 {
		t.Errorf("the checker followed %d redirect(s) to the login page; the 200 there "+
			"would be scored as an unprotected application", loginHits)
	}
	for _, r := range rep.Exposed() {
		t.Errorf("false alarm from a redirect: %s -- %s", r.Probe, r.Detail)
	}
}

func TestRunRejectsARelativeURL(t *testing.T) {
	if _, err := Run(context.Background(), Options{BaseURL: "n8n.example.com"}); err == nil {
		t.Error("a URL with no scheme was accepted; every probe would then be meaningless")
	}
}
