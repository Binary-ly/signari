package store

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/provider"
)

// jsonMembers names what a type sends, read off its tags.
func jsonMembers(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func schemaMembers(schema map[string]any) []string {
	properties, _ := schema["properties"].(map[string]any)
	out := make([]string, 0, len(properties))
	for name := range properties {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// The published contract is what the engine actually sends and reads. It is
// written by hand, because the two hooks' types live in different packages, so
// without this a member added to a request would be missing from what a provider
// is told, and nothing would say so.
func TestTheHookContractsMatchTheTypesOnTheWire(t *testing.T) {
	type answer struct {
		Decision bool           `json:"decision"`
		Context  map[string]any `json:"context"`
	}
	for _, c := range []struct {
		hook              provider.Hook
		request, response reflect.Type
	}{
		{provider.HookAuthorize, reflect.TypeOf(authzen.Request{}), reflect.TypeOf(answer{})},
		{provider.HookTokenIssue, reflect.TypeOf(TokenHookRequest{}), reflect.TypeOf(TokenHookResponse{})},
		{provider.HookPasswordVerify, reflect.TypeOf(PasswordHookRequest{}), reflect.TypeOf(PasswordHookResponse{})},
		{provider.HookAuthenticate, reflect.TypeOf(AuthenticateHookRequest{}), reflect.TypeOf(GateHookResponse{})},
		{provider.HookUserCreate, reflect.TypeOf(UserCreateHookRequest{}), reflect.TypeOf(GateHookResponse{})},
		{provider.HookClientAccess, reflect.TypeOf(authzen.Request{}), reflect.TypeOf(GateHookResponse{})},
		{provider.HookUserinfo, reflect.TypeOf(UserinfoHookRequest{}), reflect.TypeOf(TokenHookResponse{})},
		{provider.HookSAMLAssertion, reflect.TypeOf(SAMLAssertionHookRequest{}), reflect.TypeOf(TokenHookResponse{})},
		{provider.HookFlowCondition, reflect.TypeOf(AuthenticateHookRequest{}), reflect.TypeOf(FlowConditionResponse{})},
	} {
		contract, ok := provider.ContractFor(c.hook)
		if !ok {
			t.Fatalf("%s has no contract", c.hook)
		}
		if got, want := schemaMembers(contract.Request), jsonMembers(c.request); !slices.Equal(got, want) {
			t.Errorf("%s: the contract's request names %v, the engine sends %v", c.hook, got, want)
		}
		if got, want := schemaMembers(contract.Response), jsonMembers(c.response); !slices.Equal(got, want) {
			t.Errorf("%s: the contract's answer names %v, the engine reads %v", c.hook, got, want)
		}
	}
	if len(provider.AllHooks()) != 9 {
		t.Error("a hook was added: name its request and answer here")
	}
}
