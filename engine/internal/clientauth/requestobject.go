package clientauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A Request Object is an authorization request signed by the client (RFC 9101), so
// that what reaches this server is what the client asked for and not what passed
// through a browser on the way.

// maxRequestObjectBytes is more than a request comes to, with claims and details in it.
const maxRequestObjectBytes = 32 << 10

// MaxRequestObjectLifetime bounds how long one stays good, when it says. FAPI 2.0
// Message Signing §5.3.1 asks for "a lifetime of no longer than 60 minutes after the
// nbf claim" (specs/fapi2-message-signing.txt:193), which is a sensible bound for anybody.
const MaxRequestObjectLifetime = 60 * time.Minute

// requestObjectClaims are the JWT's own, and not parameters of the request.
var requestObjectClaims = map[string]bool{"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true}

// VerifyRequestObject checks a signed Request Object and answers the parameters in it.
//
// clientID is the `client_id` the request came with, and jwksJSON that client's
// registered keys. Only what is signed comes back: RFC 9101 §6.3 says the server "MUST
// only use the parameters in the Request Object, even if the same parameter is
// provided in the query parameter", and a caller merging the two would give back the
// integrity this exists for.
//
// `iss` and `aud` are required here, where §4 says SHOULD. Without `aud` an object
// signed for another authorization server is good at this one, which is the
// confused-deputy case; a client that signs already has them to hand.
func VerifyRequestObject(raw, clientID, jwksJSON string, audiences []string, now time.Time) (url.Values, error) {
	if len(raw) > maxRequestObjectBytes {
		return nil, fmt.Errorf("the request object is %d bytes, over the limit", len(raw))
	}
	if strings.Count(raw, ".") == 4 {
		return nil, fmt.Errorf("an encrypted request object cannot be read here; send it signed")
	}
	if strings.TrimSpace(jwksJSON) == "" {
		return nil, fmt.Errorf("this client has no registered keys, so a request object cannot be verified")
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		return nil, fmt.Errorf("the client's registered key set did not parse: %w", err)
	}

	// allowedAlgs holds nothing symmetric and not `none`: §10.1 says a Request Object
	// "MUST be either signed ... or signed and then encrypted", and one signed with a
	// shared secret proves nothing about which party holding it made it.
	tok, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("the request object did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return nil, fmt.Errorf("the request object has %d signatures, want one", len(tok.Signatures))
	}

	// §6.2: "If a 'kid' Header Parameter is present, the key identified MUST be the
	// key used and MUST be a key associated with the client."
	keys := jwks.Keys
	if kid := tok.Signatures[0].Header.KeyID; kid != "" {
		if keys = jwks.Key(kid); len(keys) == 0 {
			return nil, fmt.Errorf("the request object names a key this client has not registered")
		}
	}
	var payload []byte
	var verifiedBy *jose.JSONWebKey
	for _, k := range keys {
		if !k.IsPublic() {
			return nil, fmt.Errorf("the client's registered key set contains private key material; " +
				"register the PUBLIC keys only")
		}
		if k.Use == "enc" {
			continue
		}
		if p, verr := tok.Verify(k); verr == nil {
			payload = p
			key := k
			verifiedBy = &key
			break
		}
	}
	if payload == nil {
		return nil, fmt.Errorf("the request object was not signed by a key registered for this client")
	}
	if err := keyStrength(verifiedBy); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("the request object's claims did not parse: %w", err)
	}
	if err := checkRequestObject(claims, clientID, audiences, now); err != nil {
		return nil, err
	}

	params := url.Values{}
	for name, value := range claims {
		if requestObjectClaims[name] {
			continue
		}
		values, err := parameterValues(name, value)
		if err != nil {
			return nil, err
		}
		params[name] = values
	}
	return params, nil
}

func checkRequestObject(claims map[string]any, clientID string, audiences []string, now time.Time) error {
	// §4: "'request' and 'request_uri' parameters MUST NOT be included in Request Objects."
	for _, name := range []string{"request", "request_uri"} {
		if _, present := claims[name]; present {
			return fmt.Errorf("a request object may not contain %s", name)
		}
	}
	// §6.3: "The client ID values in the 'client_id' request parameter and in the
	// Request Object 'client_id' claim MUST be identical."
	if claims["client_id"] != clientID {
		return fmt.Errorf("the request object's client_id is not the request's")
	}
	if claims["iss"] != clientID {
		return fmt.Errorf("the request object's iss is not this client")
	}
	if raw, err := json.Marshal(claims["aud"]); err != nil || !audienceMatches(raw, audiences) {
		return fmt.Errorf("the request object's audience is not this server (accepted: %s)", strings.Join(audiences, ", "))
	}

	nbf, hasNotBefore, err := numericDate(claims, "nbf")
	if err != nil {
		return err
	}
	exp, hasExpiry, err := numericDate(claims, "exp")
	if err != nil {
		return err
	}
	if hasNotBefore && nbf.After(now.Add(MaxClockSkew)) {
		return fmt.Errorf("the request object is not valid until %s", nbf.UTC().Format(time.RFC3339))
	}
	if hasExpiry {
		if now.After(exp) {
			return fmt.Errorf("the request object expired at %s", exp.UTC().Format(time.RFC3339))
		}
		from := now
		if hasNotBefore {
			from = nbf
		}
		if exp.Sub(from) > MaxRequestObjectLifetime {
			return fmt.Errorf("the request object is good for %s, over the %s limit",
				exp.Sub(from).Round(time.Second), MaxRequestObjectLifetime)
		}
	}
	return nil
}

func numericDate(claims map[string]any, name string) (time.Time, bool, error) {
	raw, present := claims[name]
	if !present {
		return time.Time{}, false, nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return time.Time{}, false, fmt.Errorf("the request object's %s is not a date", name)
	}
	seconds, err := number.Float64()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("the request object's %s is not a date", name)
	}
	return time.Unix(int64(seconds), 0), true, nil
}

// parameterValues is a claim as the parameter it stands for. §4: "Parameter names and
// string values MUST be included as JSON strings ... Numerical values MUST be included
// as JSON numbers". An object or list is a parameter whose value is JSON, as `claims`
// and `authorization_details` are, but for `resource`, the one that repeats (RFC 8707).
func parameterValues(name string, value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case json.Number:
		return []string{v.String()}, nil
	case bool:
		return []string{strconv.FormatBool(v)}, nil
	case []any:
		if name == "resource" {
			out := make([]string, 0, len(v))
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("the request object's resource holds something that is not a string")
				}
				out = append(out, s)
			}
			return out, nil
		}
	case nil:
		return nil, fmt.Errorf("the request object's %s is null", name)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("the request object's %s could not be read: %w", name, err)
	}
	return []string{string(raw)}, nil
}
