package store

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
)

// Consulting an operator's provider while a token is minted.
//
// # The composition rule, which is the whole security argument
//
// Three properties, and each is the reason the next one is safe:
//
//  1. CONSULTED AFTER THE LOCAL DECISION. The grant has already been
//     authorised by this engine when this runs. So the provider is never
//     deciding whether to issue — it is deciding whether to withdraw an
//     issuance this engine already approved.
//
//  2. A VETO IS THE ONLY DENIAL IT CAN CAUSE, and it can cause no grant. A
//     provider that returned "allow" for something the engine refused would
//     never be asked, because it is not called on that path at all.
//
//  3. CONTRIBUTED CLAIMS ARE BOUNDED BY THE OPERATOR'S LIST. Not by the
//     provider's response, and never including a protocol claim. A provider
//     that could set `sub` would issue tokens impersonating any subject at
//     every relying party trusting this issuer; one that could set `scope`
//     would grant itself access.
//
// Together these mean the worst a hostile or compromised provider can do is
// refuse issuance and write values into claim names an operator already agreed
// it could write. Both are recoverable by removing the registration. Neither
// widens what anybody can reach.
//
// # Failure is decided by the provider's own declaration
//
// fail_open continues, fail_closed refuses, exactly as for the authorize hook.
// Registering an extension point without saying which is refused at
// registration, because a default here would be a security decision made by
// whoever wrote this file for a deployment they have never seen.

// TokenHookRequest is what a provider is asked.
//
// Deliberately not the token itself, and deliberately no credential material:
// the provider is told WHO and WHAT FOR so it can make a decision, not handed
// something it could replay. A provider that needs the token can be given one
// through the ordinary grant it is entitled to.
type TokenHookRequest struct {
	Subject  string   `json:"subject"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	Grant    string   `json:"grant_type"`
	OrgID    string   `json:"org_id"`
}

// TokenHookResponse is what it may answer.
type TokenHookResponse struct {
	// Decision false vetoes the issuance.
	Decision bool `json:"decision"`
	// Reason is surfaced in the log and the audit record, never to the client:
	// a provider's refusal text is written by somebody outside this deployment
	// and must not become part of an OAuth error a stranger reads.
	Reason string `json:"reason,omitempty"`
	// Claims the provider would like to contribute. Filtered against the
	// operator's allow-list; anything else is dropped.
	Claims map[string]any `json:"claims,omitempty"`
}

// TokenHookResult is what the caller acts on.
type TokenHookResult struct {
	// Vetoed means do not issue.
	Vetoed bool
	Reason string
	// Claims are the contributions that survived the allow-list.
	Claims map[string]any
	// Dropped names the claims the provider tried to set and was not permitted
	// to. Logged rather than returned to the provider: a provider that learned
	// which names were rejected could probe for the boundary.
	Dropped []string
}

// ConsultTokenProvider asks the operator's provider about one issuance.
//
// Returns a zero result when no provider is registered, which is the common case
// and must cost nothing beyond the lookup.
// `client` is a FACTORY, not a client, and that is not a style choice.
//
// The first version took a built *http.Client and the call site had to build it
// before the provider was loaded — so it passed a zero timeout, meaning no
// timeout at all. A registered provider that accepted the connection and never
// answered would have held the token endpoint open indefinitely, which is a
// denial of service reachable by anyone who can register a provider, and it hung
// the test suite until it was found.
//
// The provider carries its own bound (already capped by provider.maxTimeout), so
// the client can only be built after the row is read. Taking a factory makes
// that ordering the only one the signature permits.
func ConsultTokenProvider(ctx context.Context, q providerReader, root *keys.RootKey,
	client func(time.Duration) *http.Client,
	log *slog.Logger, orgID string, req TokenHookRequest) (TokenHookResult, error) {
	return ConsultHook(ctx, q, root, client, log, orgID, provider.HookTokenIssue, req)
}

// AuthenticateHookRequest is what the authenticate hook is told: who has got through,
// and by what. Nothing that proves it.
type AuthenticateHookRequest struct {
	Subject  string   `json:"subject"`
	OrgID    string   `json:"org_id"`
	AMR      []string `json:"amr"`
	ClientIP string   `json:"client_ip,omitempty"`
}

// UserCreateHookRequest is what the user_create hook is told. Source is `signup`, `federation` or
// `kerberos`.
type UserCreateHookRequest struct {
	OrgID  string `json:"org_id"`
	Email  string `json:"email"`
	Source string `json:"source"`
}

// UserinfoHookRequest is what the userinfo hook is told.
type UserinfoHookRequest struct {
	Subject  string   `json:"subject"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	OrgID    string   `json:"org_id"`
}

// SAMLAssertionHookRequest is what the saml_assertion hook is told.
type SAMLAssertionHookRequest struct {
	Subject  string `json:"subject"`
	EntityID string `json:"entity_id"`
	OrgID    string `json:"org_id"`
}

// GateHookResponse is what a hook that contributes nothing answers.
type GateHookResponse struct {
	Decision bool   `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// FlowConditionResponse is what the flow_condition hook answers: `decision` for
// provider_condition, and facts for the conditions the language names that only the
// operator's own service can know. A fact not said is false.
type FlowConditionResponse struct {
	Decision bool            `json:"decision"`
	Facts    map[string]bool `json:"facts,omitempty"`
}

// FlowConditionResult is what a walk acts on. Down means no answer came from a provider
// registered fail_closed, which is for the walk to refuse: a `false` here would be a
// guess, and which way it goes would be the file's and not the provider's mode's.
type FlowConditionResult struct {
	FlowConditionResponse
	Down bool
}

// ConsultFlowCondition asks the flow_condition provider about a sign-in in progress. No
// provider is the zero result, every condition false, as for any condition nobody can
// answer: each guards an additional stage, so false invents nothing.
func ConsultFlowCondition(ctx context.Context, q providerReader, root *keys.RootKey,
	client func(time.Duration) *http.Client, log *slog.Logger, orgID string,
	req AuthenticateHookRequest) (FlowConditionResult, error) {

	p, err := LoadProvider(ctx, q, root, orgID, provider.HookFlowCondition)
	if err != nil || p == nil {
		return FlowConditionResult{}, err
	}
	var answer FlowConditionResponse
	if callErr := p.Call(ctx, client(p.Timeout), req, &answer); callErr != nil {
		if p.Decide(callErr) {
			log.Warn("a provider did not answer; every condition it answers reads false because it is "+
				"registered fail_open", "provider", p.Name, "err", callErr)
			return FlowConditionResult{}, nil
		}
		log.Error("a provider did not answer; refusing the sign-in because it is registered fail_closed",
			"provider", p.Name, "err", callErr)
		return FlowConditionResult{Down: true}, nil
	}
	return FlowConditionResult{FlowConditionResponse: answer}, nil
}

// ConsultHook asks the operator's providers for a hook about something this engine has
// already said yes to, by the rule at the top of this file: a yes can be taken back,
// and what is added is bounded by the operator's list, which for a hook that does not
// Contribute is empty. The same for every hook, so no hook has a composition of its own.
//
// They compose as AND, in their order, and the first to refuse ends it: a provider
// further down is not asked about what is already refused. What they add is merged, and
// a claim has one source by SetProviderClaims.
func ConsultHook(ctx context.Context, q providerReader, root *keys.RootKey,
	client func(time.Duration) *http.Client,
	log *slog.Logger, orgID string, hook provider.Hook, req any) (TokenHookResult, error) {

	ps, err := LoadProviders(ctx, q, root, orgID, hook)
	if err != nil {
		// A provider row that will not load is a configuration fault, not a
		// decision. Failing rather than silently issuing: the operator
		// registered something, and quietly ignoring it is the "a written
		// policy governs nothing" bug this codebase keeps finding.
		return TokenHookResult{}, err
	}
	var all TokenHookResult
	for _, p := range ps {
		res := consultProvider(ctx, p, client, log, hook, req)
		if res.Vetoed {
			return res, nil
		}
		all.Dropped = append(all.Dropped, res.Dropped...)
		for name, value := range res.Claims {
			if all.Claims == nil {
				all.Claims = map[string]any{}
			}
			all.Claims[name] = value
		}
	}
	return all, nil
}

func consultProvider(ctx context.Context, p *provider.Provider, client func(time.Duration) *http.Client,
	log *slog.Logger, hook provider.Hook, req any) TokenHookResult {

	var answer TokenHookResponse
	callErr := p.Call(ctx, client(p.Timeout), req, &answer)
	if callErr != nil {
		// Logged either way. A fail_open provider that has silently stopped
		// answering means an operator's veto is no longer being enforced, and
		// nothing else would record that.
		if p.Decide(callErr) {
			log.Warn("a provider did not answer; going on because it is registered fail_open",
				"hook", string(hook), "provider", p.Name, "err", callErr)
			return TokenHookResult{}
		}
		log.Error("a provider did not answer; refusing because it is registered fail_closed",
			"hook", string(hook), "provider", p.Name, "err", callErr)
		return TokenHookResult{
			Vetoed: true,
			Reason: fmt.Sprintf("the %s provider was unreachable and is registered fail_closed", p.Name),
		}
	}

	if !answer.Decision {
		return TokenHookResult{Vetoed: true, Reason: answer.Reason}
	}

	res := TokenHookResult{}
	for name, value := range answer.Claims {
		if p.MayContribute(name) {
			if res.Claims == nil {
				res.Claims = map[string]any{}
			}
			res.Claims[name] = value
			continue
		}
		res.Dropped = append(res.Dropped, name)
	}
	if len(res.Dropped) > 0 {
		// Named in the log so an operator can see a provider reaching for
		// something it was not granted -- which is either a misconfiguration
		// worth fixing or a provider worth removing.
		log.Warn("a provider returned claims it may not contribute",
			"hook", string(hook), "provider", p.Name, "dropped", res.Dropped)
	}
	return res
}
