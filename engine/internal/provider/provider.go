// Package provider calls an operator's own service to extend a decision this
// engine makes (ADR-011).
//
// # Why out of process
//
// Go has no usable dynamic plugin story -- `plugin` is Linux-only, demands the
// identical toolchain and dependency graph, cannot unload, and shares an address
// space with the signing keys. An embedded expression language is remote code
// execution with a configuration screen in front of it, and this project already
// declined that surface deliberately. WebAssembly is the strongest in-process
// option and the largest commitment: a runtime dependency plus a host ABI to
// design and version forever.
//
// So an extension is a service the operator runs. The engine calls it over HTTP
// with JSON, which is what every other integration here already speaks, through
// the SSRF-safe dialer that already exists.
//
// # The rule this package exists to enforce
//
// A provider WILL be unreachable at some point. What happens then is not a
// default and never inferred -- it is declared per provider, because the safe
// answer differs per hook and getting it wrong is silent in both directions:
//
//   - An authorization hook that fails OPEN is not an authorization hook. It
//     stops enforcing precisely when something is wrong, which is when it
//     mattered.
//   - A claims-enrichment hook that fails CLOSED locks every user out of a
//     deployment because a directory was slow.
//
// Both are one-word mistakes and neither announces itself, so the word is
// mandatory at registration and Decide is the single place it is applied.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/safedial"
)

// Mode is what happens when a provider does not answer.
//
// A string rather than a bool, and the values say what happens rather than
// naming a policy: `fail_closed` reads the same way in a config file, a log line
// and an audit event, where `strict: true` has to be looked up.
type Mode string

const (
	// FailClosed refuses the journey when the provider cannot be reached.
	FailClosed Mode = "fail_closed"
	// FailOpen continues as though the hook were not registered.
	FailOpen Mode = "fail_open"
)

// Valid reports whether a mode was actually chosen.
//
// The zero value is deliberately NOT one of them. A Provider built by a future
// caller that forgets the field is refused at registration rather than silently
// acquiring whichever behaviour happened to be first in the const block.
func (m Mode) Valid() bool { return m == FailClosed || m == FailOpen }

// Hook names a decision an operator may extend.
//
// A closed set, for the same reason StageName is one in the flow package: a hook
// resolved from a string at run time means a typo is a hook that silently never
// fires, and the first person to find out is whoever needed it.
type Hook string

const (
	// HookAuthorize asks whether a subject may do something. The body is an
	// AuthZEN evaluation request: we implement that specification's PDP side
	// already, so calling somebody else's PDP is the same protocol pointed the
	// other way rather than a second dialect of a thing we already speak.
	HookAuthorize Hook = "authorize"
)

var allHooks = []Hook{HookAuthorize}

// AllHooks returns every defined hook, for the CLI's help text and listings.
func AllHooks() []Hook { return append([]Hook(nil), allHooks...) }

// Known reports whether a hook name is one this engine defines.
func (h Hook) Known() bool {
	for _, k := range allHooks {
		if k == h {
			return true
		}
	}
	return false
}

// Called reports whether a hook is actually CONSULTED at a decision point.
//
// # Why this exists
//
// This package is the mechanism, and hooks are wired one at a time (ADR-011).
// `authorize` is consulted today; anything else defined here is staged and
// governs nothing yet. That is a legitimate state to be in and a dangerous one
// to leave undeclared, because it is
// precisely the shape of the bug the flow engine had for months: a thing an
// operator can configure, which parses, validates, has tests, and governs
// nothing. flow.Designation.Driven exists for the same reason and is the model
// for this.
//
// So the gap is a predicate rather than a comment. `signari doctor` and the
// registration command read it, so an operator registering a provider for a hook
// nothing calls is told at that moment. Wire a hook up and this must move in the
// same commit -- the test in this package fails if it does not, in both
// directions.
func (h Hook) Called() bool {
	// HookAuthorize is consulted by the AuthZEN evaluation path
	// (httpapi.consultAuthorizeProvider), after every local check has already
	// allowed. It can only turn that allow into a deny; it can never grant.
	return h == HookAuthorize
}

// Uncalled returns every hook that is defined and not consulted.
func Uncalled() []Hook {
	var out []Hook
	for _, h := range allHooks {
		if !h.Called() {
			out = append(out, h)
		}
	}
	return out
}

// Provider is one registered extension.
type Provider struct {
	// Name identifies it in logs, audit events and `signari doctor`.
	Name string
	// Hook is which decision it extends.
	Hook Hook
	// URL is the endpoint. Must be https and must not resolve into the private
	// network -- checked at registration AND again at dial time, because DNS can
	// change between the two.
	URL string
	// Token, when set, is sent as a bearer credential. Optional: an operator may
	// prefer mutual TLS at the network layer.
	Token string
	// Mode is what happens when the call does not succeed. Required.
	Mode Mode
	// Timeout bounds the call. Required, and bounded again by maxTimeout, because
	// an extension point is also a way to make every sign-in as slow as the
	// slowest thing an operator registered.
	Timeout time.Duration
}

// maxTimeout is the ceiling on any provider call.
//
// Five seconds is already far too long to hold a sign-in, and the point of a
// ceiling is not to pick the right number -- it is that no configured value can
// remove the bound. Without it a provider registered with a ten-minute timeout
// is a way to exhaust the server's connections from the outside.
const maxTimeout = 5 * time.Second

// Validate refuses a provider that cannot be safely called.
//
// At registration, so the operator learns at `signari provider add` rather than
// at the first sign-in that depends on it.
func (p Provider) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("a provider needs a name; it is what names it in the audit trail")
	}
	if !p.Hook.Known() {
		return fmt.Errorf("%q is not a hook this engine calls (%s)", p.Hook, hookList())
	}
	if !p.Mode.Valid() {
		return fmt.Errorf("provider %q must say what happens when it cannot be reached: "+
			"%s refuses the journey, %s continues without it. There is no default, "+
			"because the safe answer differs per hook and both mistakes are silent",
			p.Name, FailClosed, FailOpen)
	}
	if p.Timeout <= 0 {
		return fmt.Errorf("provider %q needs a timeout; without one a slow extension "+
			"is an outage", p.Name)
	}
	if p.Timeout > maxTimeout {
		return fmt.Errorf("provider %q has a timeout of %s, above the %s ceiling: a "+
			"provider call happens while somebody is waiting", p.Name, p.Timeout, maxTimeout)
	}
	// The same check webhook and event delivery use. A provider URL is chosen by
	// an operator rather than by a client, so this is defence in depth rather than
	// the primary control -- but "an operator would not do that" is how every
	// server-side request forgery starts.
	if err := safedial.CheckURL(p.URL); err != nil {
		return fmt.Errorf("provider %q: %w", p.Name, err)
	}
	return nil
}

func hookList() string {
	out := make([]string, len(allHooks))
	for i, h := range allHooks {
		out[i] = string(h)
	}
	return fmt.Sprint(out)
}

// maxResponse bounds what a provider may return.
//
// A hostile or broken extension must not be able to exhaust memory by answering
// with a stream. One megabyte is far beyond any decision body.
const maxResponse = 1 << 20

// ErrUnreachable is returned when the provider did not give a usable answer.
//
// Deliberately one error for every failure -- refused connection, timeout, 500,
// unparseable body. The caller's decision is the same in all of them, and giving
// them separate types invites a caller to handle three and forget the fourth.
type ErrUnreachable struct {
	Provider string
	Err      error
}

func (e *ErrUnreachable) Error() string {
	return fmt.Sprintf("provider %q did not answer: %v", e.Provider, e.Err)
}
func (e *ErrUnreachable) Unwrap() error { return e.Err }

// Call posts req to the provider and decodes its answer into out.
//
// The client is passed in rather than built here so a caller can share one, and
// so a test can supply its own. It should be a safedial.Client: this package
// checks the URL, but only the dialer can refuse an address that resolved into
// the private network AFTER the check.
func (p Provider) Call(ctx context.Context, client *http.Client, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return &ErrUnreachable{Provider: p.Name, Err: fmt.Errorf("encoding the request: %w", err)}
	}

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		return &ErrUnreachable{Provider: p.Name, Err: err}
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	if p.Token != "" {
		hreq.Header.Set("Authorization", "Bearer "+p.Token)
	}

	resp, err := client.Do(hreq)
	if err != nil {
		return &ErrUnreachable{Provider: p.Name, Err: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// Any non-200 is unreachable, including 4xx. A provider that rejects our
		// request has not made a decision, and treating "you sent me something I
		// did not understand" as a decision is how a contract mismatch becomes a
		// silent authorization change.
		return &ErrUnreachable{Provider: p.Name,
			Err: fmt.Errorf("status %d", resp.StatusCode)}
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponse))
	// Unknown fields are ALLOWED, deliberately, and this is the opposite of the
	// rule on our inbound surfaces. A provider written against a later version of
	// this contract will send fields we do not know; refusing them would make
	// every additive change to the contract a breaking one for the party we have
	// least control over.
	if err := dec.Decode(out); err != nil {
		return &ErrUnreachable{Provider: p.Name,
			Err: fmt.Errorf("decoding the answer: %w", err)}
	}
	return nil
}

// Decide applies the provider's failure mode to a call that did not answer.
//
// The single place the mode is read. Every caller funnels through it so that
// "what happens when this is down" cannot be answered differently, or forgotten,
// at each hook that gets added later.
//
// Returns whether the caller should PROCEED as though the hook had not run. A
// fail-closed provider returns false, and the caller must refuse.
func (p Provider) Decide(err error) (proceed bool) {
	if err == nil {
		return true
	}
	return p.Mode == FailOpen
}
