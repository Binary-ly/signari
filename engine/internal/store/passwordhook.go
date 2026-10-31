package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
)

// A password checked by the operator's own service, for somebody migrating from a system
// this engine cannot reach (10.07, 10.14). provider.HookPasswordVerify says when.

// PasswordHookRequest is what the provider is asked.
type PasswordHookRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OrgID    string `json:"org_id"`
}

// PasswordHookResponse is its answer. Verified is a pointer because a 200 that does not
// say is no answer: read as false, a provider that broke would charge everybody still to
// migrate with a wrong password.
type PasswordHookResponse struct {
	Verified *bool `json:"verified"`
}

// ErrNoPasswordProvider is a `hook` source with no provider to ask.
var ErrNoPasswordProvider = errors.New("no provider is registered for the password_verify hook")

// ConsultPasswordProvider asks whether a password is correct. An answer is a verdict; a
// provider that gave none is an error, never a refusal, so that the caller can tell an
// outage from a wrong password and not charge the person for it. Nothing here says yes
// except the provider saying so: there is no failing open from this hook, which
// provider.Provider.Validate refuses at registration.
func ConsultPasswordProvider(ctx context.Context, q providerReader, root *keys.RootKey,
	client func(time.Duration) *http.Client, orgID, username, password string) (bool, error) {

	// Never sent, as no other source is sent one: what a service behind the hook makes of
	// an empty password is not something to find out at a sign-in.
	if password == "" {
		return false, nil
	}
	p, err := LoadProvider(ctx, q, root, orgID, provider.HookPasswordVerify)
	if err != nil {
		return false, err
	}
	if p == nil {
		return false, ErrNoPasswordProvider
	}
	var answer PasswordHookResponse
	if err := p.Call(ctx, client(p.Timeout), PasswordHookRequest{Username: username, Password: password,
		OrgID: orgID}, &answer); err != nil {
		return false, err
	}
	if answer.Verified == nil {
		return false, fmt.Errorf("%s answered without a boolean verified, which contract %s requires",
			p.URL, provider.ContractVersion)
	}
	return *answer.Verified, nil
}

// TryPasswordProvider is delegated.Verifier.Test for a `hook` source: the call a pending
// person's sign-in makes, and the step it stopped at (7.18).
func TryPasswordProvider(ctx context.Context, q providerReader, root *keys.RootKey,
	client func(time.Duration) *http.Client, orgID, username, password string) delegated.Result {

	verified, err := ConsultPasswordProvider(ctx, q, root, client, orgID, username, password)
	switch {
	case errors.Is(err, ErrNoPasswordProvider):
		return delegated.Result{Step: delegated.StepConfiguration, Detail: err.Error()}
	case err != nil:
		return delegated.Result{Step: delegated.StepAnswer, Detail: err.Error()}
	case !verified:
		return delegated.Result{Step: delegated.StepAnswer, Detail: "the provider answered that the credential is wrong"}
	}
	return delegated.Result{OK: true, Detail: "the provider accepted the credential"}
}
