package config

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var schemaOut = flag.String("config-schema-out", "", "write the generated schema here, to copy over "+
	"docs/config.schema.json")

// The published schema is the one the types draw (6.19). Regenerate it with
// `go test ./internal/config -run TestTheConfigurationSchemaIsCurrent
// -config-schema-out <file>` and copy the file over docs/config.schema.json.
func TestTheConfigurationSchemaIsCurrent(t *testing.T) {
	got, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	if *schemaOut != "" {
		if err := os.WriteFile(*schemaOut, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, published) {
		t.Error("docs/config.schema.json is not the schema the configuration types draw; regenerate it " +
			"with -config-schema-out")
	}
}

// Each closed set the schema states is one Parse takes: every value in it
// accepted, and one outside it refused, so an editor does not flag a file for
// a value apply takes, nor pass one with a value it would refuse.
func TestEverySchemaEnumIsWhatParseAccepts(t *testing.T) {
	templates := map[string]string{
		"Attribute.value_type":        "attributes: [{name: a, value_type: %q}]",
		"ClaimMapper.destination":     "claim_mappers: [{attribute: a, claim: a, destination: %q, all_clients: true}]",
		"SAMLProvider.name_id_format": "saml_providers: [{entity_id: e, acs_urls: ['https://sp.example.test/acs'], name_id_format: %q}]",
		"Provider.mode":               "providers: [{hook: authorize, url: 'https://a.example.test/', mode: %q}]",
		"Provider.hook":               "providers: [{hook: %q, url: 'https://a.example.test/', mode: fail_open}]",
		"SCIMTarget.kind":             "scim_targets: [{slug: s, kind: %q, base_url: 'https://a.example.test/', token: {env: T}}]",
		"SCIMTarget.on_deactivate":    "scim_targets: [{slug: s, base_url: 'https://a.example.test/', token: {env: T}, on_deactivate: %q}]",
		"RACConnection.protocol":      "rac_connections: [{slug: r, protocol: %q, host: h}]",
		"SAMLUpstream.name_id_format": "identity_providers: [{slug: i, kind: saml, saml: {entity_id: e, sso_url: 'https://i.example.test/', certificate: %q, name_id_format: %q}}]",
		// The WebAuthn policy's, store.CheckWebAuthnPolicy's sets.
		"WebAuthnPolicy.attestation":       "webauthn_policy: {attestation: %q}",
		"WebAuthnPolicy.user_verification": "webauthn_policy: {user_verification: %q}",
		"WebAuthnPolicy.resident_key":      "webauthn_policy: {resident_key: %q}",
		"WebAuthnPolicy.attachment":        "webauthn_policy: {attachment: %q}",
	}
	cert := testCertificate(t)
	parse := func(key, value string) error {
		tmpl := templates[key]
		var raw string
		if key == "SAMLUpstream.name_id_format" {
			raw = fmt.Sprintf(tmpl, cert, value)
		} else {
			raw = fmt.Sprintf(tmpl, value)
		}
		_, err := Parse([]byte("version: 1\n" + raw + "\n"))
		return err
	}
	for key, values := range schemaEnums {
		if key == "IdentityProvider.kind" {
			continue // drawn from the presets, which registration resolves by the same list
		}
		if _, ok := templates[key]; !ok {
			t.Errorf("%s has no template here, so nothing checks its values against Parse", key)
			continue
		}
		for _, v := range values {
			// SCIM's google and entra need credentials, not a token; their
			// acceptance is the provisioning tests'.
			if key == "SCIMTarget.kind" && v != "scim" {
				continue
			}
			if err := parse(key, v); err != nil {
				t.Errorf("%s %q is in the schema and Parse refuses it: %v", key, v, err)
			}
		}
		if err := parse(key, "not-a-value"); err == nil {
			t.Errorf("%s: Parse takes a value the schema refuses", key)
		}
	}
	// A key the schema refuses outright Parse refuses too.
	for key := range schemaRefused {
		if key != "RADIUSClient.secret" {
			t.Errorf("%s has no file here, so nothing checks Parse refuses it", key)
			continue
		}
		if _, err := Parse([]byte("version: 1\nradius_clients: [{name: ap, network: 10.0.0.0/24, secret: s}]\n")); err == nil {
			t.Errorf("%s is refused by the schema and taken by Parse", key)
		}
	}
}
