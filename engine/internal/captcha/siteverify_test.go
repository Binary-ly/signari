package captcha

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func siteverifyConfig(verifyURL string) Config {
	return Config{Mode: ModeAlways, Provider: Siteverify, SiteKey: "site", Secret: "the-secret", FailClosed: true,
		Widget: Widget{VerifyURL: verifyURL, ScriptURL: "https://captcha.example.test/widget.js",
			Class: "my-captcha", ResponseField: "my-captcha-response"}}
}

// A service an operator runs is asked what the vendors are asked, at the address
// they named, and its answer is taken the same way.
func TestASelfHostedServiceIsAskedAndBelieved(t *testing.T) {
	var secret, response string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		secret, response = r.PostForm.Get("secret"), r.PostForm.Get("response")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": response == "solved",
			"error-codes": []string{"invalid-input-response"}})
	}))
	t.Cleanup(srv.Close)
	v := New(siteverifyConfig(srv.URL), srv.Client())

	if err := v.Verify(ctx, "solved", "198.51.100.7:1234"); err != nil {
		t.Errorf("a solved challenge was refused: %v", err)
	}
	if secret != "the-secret" || response != "solved" {
		t.Errorf("the service was sent secret %q, response %q", secret, response)
	}
	if err := v.Verify(ctx, "guessed", "198.51.100.7:1234"); err == nil ||
		!strings.Contains(err.Error(), "invalid-input-response") {
		t.Errorf("an unsolved challenge answered %v", err)
	}
}

// The address is configuration and receives the secret, so with no client given
// it goes through the outbound guard like any other configured address.
func TestAConfiguredAddressGoesThroughTheOutboundGuard(t *testing.T) {
	asked := false
	// Plain, so a certificate nobody trusts is not what stops the call.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked = true }))
	t.Cleanup(srv.Close)
	if err := New(siteverifyConfig(srv.URL), nil).Verify(ctx, "solved", "198.51.100.7:1234"); err == nil {
		t.Error("a loopback address was accepted, or refused by nothing")
	}
	if asked {
		t.Error("the loopback service was reached with the secret")
	}
}

func TestAWidgetIsCheckedBeforeItIsUsed(t *testing.T) {
	good := siteverifyConfig("https://captcha.example.test/siteverify").Widget
	if err := good.Validate(); err != nil {
		t.Fatalf("a sound widget was refused: %v", err)
	}
	for name, change := range map[string]func(*Widget){
		"no verify address":      func(w *Widget) { w.VerifyURL = "" },
		"a plain verify address": func(w *Widget) { w.VerifyURL = "http://captcha.example.test/siteverify" },
		"a plain script":         func(w *Widget) { w.ScriptURL = "http://captcha.example.test/widget.js" },
		"no class":               func(w *Widget) { w.Class = "" },
		"a class that breaks out": func(w *Widget) {
			w.Class = `x" onload="alert(1)`
		},
		"no response field": func(w *Widget) { w.ResponseField = "" },
	} {
		w := good
		change(&w)
		if err := w.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSiteverifyIsAProviderByName(t *testing.T) {
	if p, err := ParseProvider("Siteverify"); err != nil || p != Siteverify {
		t.Errorf("read as %q, %v", p, err)
	}
}
