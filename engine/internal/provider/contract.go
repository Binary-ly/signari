package provider

import "fmt"

// The wire contract a provider is written against (ADR-011). A provider lives
// outside this repository and outlives any one release, so what it is sent and
// what it may answer are published, and each call says which version it is.

const (
	// VersionHeader carries ContractVersion on every call.
	VersionHeader = "Signari-Hook-Version"

	// ContractVersion moves when a provider has to act: a member it relies on
	// changes or goes. A new optional member does not move it, because a provider
	// must ignore what it does not know, as this engine does of what it answers.
	ContractVersion = "1"

	// TestHeader marks a call `signari provider test` made, so a provider can
	// answer it without recording a decision about nobody.
	TestHeader = "Signari-Hook-Test"
)

// Contract is one hook's request and answer, as JSON Schema, and the request
// `signari provider test` sends.
type Contract struct {
	Hook     Hook           `json:"hook"`
	Request  map[string]any `json:"request"`
	Response map[string]any `json:"response"`
	// Sample names nobody real and nothing that exists.
	Sample map[string]any `json:"-"`
	// Verdict is the member of the response that decides.
	Verdict string `json:"-"`
}

func objectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "required": required, "properties": properties,
		"additionalProperties": true}
}

func stringSchema() map[string]any { return map[string]any{"type": "string"} }

func anyObjectSchema() map[string]any { return map[string]any{"type": "object"} }

// Contracts lists every hook's contract, in allHooks's order.
func Contracts() []Contract {
	entity := func(required ...string) map[string]any {
		return objectSchema(required, map[string]any{"type": stringSchema(), "id": stringSchema(),
			"properties": anyObjectSchema()})
	}
	gate := objectSchema([]string{"decision"}, map[string]any{
		"decision": map[string]any{"type": "boolean"}, "reason": stringSchema()})
	out := make([]Contract, 0, len(allHooks))
	for _, h := range allHooks {
		switch h {
		case HookAuthorize:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "resource", "action"}, map[string]any{
					"subject": entity("type", "id"), "resource": entity("type"),
					"action": objectSchema([]string{"name"}, map[string]any{"name": stringSchema(),
						"properties": anyObjectSchema()}),
					"context": anyObjectSchema()}),
				Response: objectSchema([]string{"decision"}, map[string]any{
					"decision": map[string]any{"type": "boolean"}, "context": anyObjectSchema()}),
				Sample: map[string]any{"subject": map[string]any{"type": "user", "id": "provider-test"},
					"resource": map[string]any{"type": "provider-test", "id": "provider-test"},
					"action":   map[string]any{"name": "provider-test"}}})
		case HookTokenIssue:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "client_id", "scopes", "grant_type", "org_id"}, map[string]any{
					"subject": stringSchema(), "client_id": stringSchema(),
					"scopes":     map[string]any{"type": "array", "items": stringSchema()},
					"grant_type": stringSchema(), "org_id": stringSchema()}),
				Response: objectSchema([]string{"decision"}, map[string]any{
					"decision": map[string]any{"type": "boolean"}, "reason": stringSchema(),
					"claims": anyObjectSchema()}),
				Sample: map[string]any{"subject": "provider-test", "client_id": "provider-test",
					"scopes": []string{}, "grant_type": "provider-test", "org_id": "provider-test"}})
		case HookPasswordVerify:
			out = append(out, Contract{Hook: h, Verdict: "verified",
				Request: objectSchema([]string{"username", "password", "org_id"}, map[string]any{
					"username": stringSchema(), "password": stringSchema(), "org_id": stringSchema()}),
				Response: objectSchema([]string{"verified"}, map[string]any{
					"verified": map[string]any{"type": "boolean"}}),
				Sample: map[string]any{"username": "provider-test", "password": "provider-test",
					"org_id": "provider-test"}})
		case HookAuthenticate:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "org_id", "amr"}, map[string]any{
					"subject": stringSchema(), "org_id": stringSchema(), "client_ip": stringSchema(),
					"amr": map[string]any{"type": "array", "items": stringSchema()}}),
				Response: gate,
				Sample: map[string]any{"subject": "provider-test", "org_id": "provider-test",
					"amr": []string{"pwd"}}})
		case HookUserCreate:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"org_id", "email", "source"}, map[string]any{
					"org_id": stringSchema(), "email": stringSchema(), "source": stringSchema()}),
				Response: gate,
				Sample: map[string]any{"org_id": "provider-test", "email": "provider-test@example.invalid",
					"source": "provider-test"}})
		case HookClientAccess:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "resource", "action"}, map[string]any{
					"subject": entity("type", "id"), "resource": entity("type"),
					"action": objectSchema([]string{"name"}, map[string]any{"name": stringSchema(),
						"properties": anyObjectSchema()}),
					"context": anyObjectSchema()}),
				Response: gate,
				Sample: map[string]any{"subject": map[string]any{"type": "user", "id": "provider-test"},
					"resource": map[string]any{"type": "client", "id": "provider-test"},
					"action":   map[string]any{"name": "access"}}})
		case HookUserinfo:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "client_id", "scopes", "org_id"}, map[string]any{
					"subject": stringSchema(), "client_id": stringSchema(), "org_id": stringSchema(),
					"scopes": map[string]any{"type": "array", "items": stringSchema()}}),
				Response: objectSchema([]string{"decision"}, map[string]any{
					"decision": map[string]any{"type": "boolean"}, "reason": stringSchema(),
					"claims": anyObjectSchema()}),
				Sample: map[string]any{"subject": "provider-test", "client_id": "provider-test",
					"scopes": []string{}, "org_id": "provider-test"}})
		case HookSAMLAssertion:
			out = append(out, Contract{Hook: h, Verdict: "decision",
				Request: objectSchema([]string{"subject", "entity_id", "org_id"}, map[string]any{
					"subject": stringSchema(), "entity_id": stringSchema(), "org_id": stringSchema()}),
				Response: objectSchema([]string{"decision"}, map[string]any{
					"decision": map[string]any{"type": "boolean"}, "reason": stringSchema(),
					"claims": anyObjectSchema()}),
				Sample: map[string]any{"subject": "provider-test", "entity_id": "provider-test",
					"org_id": "provider-test"}})
		default:
			panic(fmt.Sprintf("the %q hook has no contract", h))
		}
	}
	return out
}

// ContractFor finds one hook's contract.
func ContractFor(h Hook) (Contract, bool) {
	for _, c := range Contracts() {
		if c.Hook == h {
			return c, true
		}
	}
	return Contract{}, false
}
