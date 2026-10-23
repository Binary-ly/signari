package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/provider"
)

// The JSON Schema of a configuration file (6.19), for an editor to check a
// file as it is written. Drawn by reflection from the types Parse decodes
// into, so it cannot describe a key Parse refuses or leave out one it takes.
// Parse stays the authority: what a schema cannot say (a name given twice, a
// group the deployment lacks, a certificate past its date) it refuses and the
// schema accepts.

// schemaEnums are the closed sets of values, keyed "Type.key": each the set
// Validate accepts, or drawn from the list the engine itself keeps.
// TestEverySchemaEnumIsWhatParseAccepts checks that Parse takes every value in
// each and refuses one outside it; a value Parse takes and a set leaves out it
// cannot see, so a set changed in Validate is changed here in the same edit.
var schemaEnums = map[string][]string{
	// "" where the key has no omitempty: an export may write it, and it is
	// the default.
	"Attribute.value_type":        {"", "string", "number", "boolean", "date"},
	"ClaimMapper.destination":     {"id_token", "userinfo", "access_token"},
	"SAMLProvider.name_id_format": {"", "persistent", "emailAddress", "transient"},
	"Provider.mode":               {string(provider.FailClosed), string(provider.FailOpen)},
	"SCIMTarget.kind":             {"scim", "google", "entra"},
	"SCIMTarget.on_deactivate":    {"deactivate", "delete", "nothing"},
	"RACConnection.protocol":      {"rdp", "vnc", "ssh"},
	"SAMLUpstream.name_id_format": {"persistent", "emailAddress", "unspecified"},
	"Provider.hook":               hookNames(),
	"IdentityProvider.kind":       idpKinds(),
}

func hookNames() []string {
	var out []string
	for _, h := range provider.AllHooks() {
		out = append(out, string(h))
	}
	return out
}

func idpKinds() []string {
	out := []string{"saml", "assertion"}
	for _, k := range federation.Kinds() {
		out = append(out, string(k))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// schemaRefused are keys a type decodes only so that Parse can refuse them by
// name, a secret written into the file above all; the schema refuses them too.
var schemaRefused = map[string]bool{"RADIUSClient.secret": true}

// durationPattern is what time.ParseDuration takes, as YAML decodes a
// duration.
const durationPattern = `^-?([0-9]+(\.[0-9]*)?(ns|us|µs|ms|s|m|h))+$`

// Schema renders the schema.
func Schema() ([]byte, error) {
	defs := map[string]any{}
	root := objectSchema(reflect.TypeOf(File{}), defs)
	props := root["properties"].(map[string]any)
	props["version"] = map[string]any{"type": "integer", "const": 1}
	root["required"] = []string{"version"}
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["title"] = "Signari configuration"
	root["description"] = "What `signari plan` and `signari apply` take; see docs/config-as-code.md."
	root["$defs"] = defs
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// objectSchema is a struct's properties, by the keys YAML decodes them from;
// no others, since Parse refuses an unknown key.
func objectSchema(t reflect.Type, defs map[string]any) map[string]any {
	props := map[string]any{}
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		switch key {
		case "-":
			continue
		case "":
			key = strings.ToLower(f.Name)
		}
		if schemaRefused[t.Name()+"."+key] {
			props[key] = false
			continue
		}
		s := schemaOf(f.Type, defs)
		if enum, ok := schemaEnums[t.Name()+"."+key]; ok {
			s = map[string]any{"type": "string", "enum": enum}
		}
		props[key] = s
	}
	return map[string]any{"type": "object", "properties": props, "additionalProperties": false}
}

func schemaOf(t reflect.Type, defs map[string]any) map[string]any {
	if t == reflect.TypeOf(time.Duration(0)) {
		return map[string]any{"type": "string", "pattern": durationPattern}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return schemaOf(t.Elem(), defs)
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), defs)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem(), defs)}
	case reflect.Struct:
		if _, done := defs[t.Name()]; !done {
			defs[t.Name()] = nil
			defs[t.Name()] = objectSchema(t, defs)
		}
		return map[string]any{"$ref": "#/$defs/" + t.Name()}
	}
	// A kind no field has yet: anything, rather than a schema that refuses a
	// file Parse takes.
	return map[string]any{}
}
