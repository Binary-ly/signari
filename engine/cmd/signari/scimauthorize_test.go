package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The loopback callback answers only the authorization it was opened for: a
// request with another state, from another program on the interface or an old
// tab, is told so and the wait goes on; anything off the path is a 404; the
// answer that matches ends it, code or refusal.
func TestTheCallbackWaitsForItsOwnAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + l.Addr().String()
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := awaitCode(context.Background(), l, "/callback", "the-state")
		done <- result{code, err}
	}()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s answered as %q", path, resp.Header.Get("Content-Type"))
		}
		return resp.StatusCode, string(body)
	}
	if code, _ := get("/favicon.ico"); code != http.StatusNotFound {
		t.Errorf("another path answered %d", code)
	}
	if code, body := get("/callback?code=theirs&state=another"); code != http.StatusBadRequest ||
		!strings.Contains(body, "not the answer to the authorization") || strings.Contains(body, "theirs") {
		t.Errorf("another state answered %d %q", code, body)
	}
	select {
	case r := <-done:
		t.Fatalf("a stray request ended the wait: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
	if code, body := get("/callback?code=ours&state=the-state"); code != http.StatusOK || !strings.Contains(body, "Done") {
		t.Errorf("the answer got %d %q", code, body)
	}
	if r := <-done; r.code != "ours" || r.err != nil {
		t.Errorf("the wait ended with %+v", r)
	}
}

// A target that refuses says why, and the wait ends with that; nobody coming
// back ends it when the authorization does.
func TestTheCallbackEndsWithARefusalOrTheDeadline(t *testing.T) {
	if _, err := codeFrom(url.Values{"state": {"s"}, "error": {"access_denied"},
		"error_description": {"the administrator said no"}}, "s"); err == nil ||
		!strings.Contains(err.Error(), "access_denied: the administrator said no") {
		t.Errorf("a refusal answered %v", err)
	}
	if _, err := codeFrom(url.Values{"state": {"s"}}, "s"); err == nil {
		t.Error("an answer with no code was taken")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := awaitCode(ctx, l, "/callback", "s"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("nobody coming back answered %v", err)
	}
}

// The address pasted from the browser carries the code, and one from another
// authorization is refused.
func TestThePastedAddressCarriesTheCode(t *testing.T) {
	ctx := context.Background()
	code, err := pastedCode(ctx, strings.NewReader("  https://console.example.test/cb?code=ours&state=the-state \n"),
		"the-state")
	if err != nil || code != "ours" {
		t.Errorf("pasted for %q, %v", code, err)
	}
	if _, err := pastedCode(ctx, strings.NewReader("https://console.example.test/cb?code=x&state=old\n"),
		"the-state"); !errors.Is(err, errStrayRequest) {
		t.Errorf("another authorization's address answered %v", err)
	}
	if _, err := pastedCode(ctx, strings.NewReader(""), "the-state"); err == nil {
		t.Error("nothing pasted was taken")
	}
}
