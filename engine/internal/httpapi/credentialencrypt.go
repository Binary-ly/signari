package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// Encrypted Credential Requests and Responses, OpenID4VCI §10, on top of TLS for a wallet
// whose response passes through something it does not trust. The one rule that shapes
// this: §8.2, "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it being substituted
// by an attacker". The key a credential is sealed to has to reach here sealed itself, or
// whoever could read the credential could also have swapped in their own.

// credentialRequestBody reads a Credential or Deferred Credential Request and opens it if
// it came encrypted, §8.2's application/jwt. It answers for itself when it cannot.
func (s *Server) credentialRequestBody(w http.ResponseWriter, r *http.Request, limit int64) (body []byte, encrypted, ok bool) {
	ctx := r.Context()
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeCredentialError(w, http.StatusBadRequest, "invalid_credential_request", "the request is too large")
		return nil, false, false
	}
	if media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); media != "application/jwt" {
		return raw, false, true
	}
	set, err := keys.LoadSetFor(ctx, s.db, s.instanceID, keys.PurposeEncryption, s.root)
	if err != nil {
		s.log.ErrorContext(ctx, "loading the encryption keys", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return nil, false, false
	}
	opened, err := set.OpenJWE(string(raw), tokens.ContentEncryptions)
	if err != nil {
		s.log.InfoContext(ctx, "a credential request did not open", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusBadRequest, "invalid_encryption_parameters", "the request could not be decrypted")
		return nil, false, false
	}
	return opened, true, true
}

// credentialSeal is how a response goes back: nil in the clear, and otherwise to the key
// the wallet sent. §8.3: "this is done regardless of the content".
type credentialSeal struct {
	keys string
	how  tokens.Encryption
}

// sealFor reads a request's credential_response_encryption, refusing what cannot be
// honoured before anything is issued: a credential minted and then undeliverable has
// spent a proof and a nonce for nothing.
func sealFor(raw json.RawMessage, requestEncrypted bool) (*credentialSeal, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if !requestEncrypted {
		return nil, errors.New("credential_response_encryption has to come in an encrypted request (section 8.2)")
	}
	var asked struct {
		JWK json.RawMessage `json:"jwk"`
		Enc string          `json:"enc"`
		Zip string          `json:"zip"`
	}
	if err := json.Unmarshal(raw, &asked); err != nil {
		return nil, errors.New("credential_response_encryption did not parse")
	}
	// zip_values_supported is not published, so a wallet was told not to ask.
	if asked.Zip != "" {
		return nil, errors.New("this issuer does not compress")
	}
	if !slices.Contains(tokens.ContentEncryptions, asked.Enc) {
		return nil, errors.New("credential_response_encryption names an enc this issuer does not offer")
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(asked.JWK, &key); err != nil {
		return nil, errors.New("credential_response_encryption has no usable public key")
	}
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
	if err != nil {
		return nil, err
	}
	// §10: "The alg parameter MUST be present", and the JWE's has to equal it. Given none,
	// or one not on offer, or a private key or one for signing, there is nothing to choose.
	if _, err := tokens.EncryptionKey(string(set), key.Algorithm); err != nil {
		return nil, errors.New("the key's alg is missing or not on offer, or the key cannot be encrypted to")
	}
	return &credentialSeal{keys: string(set), how: tokens.Encryption{Alg: key.Algorithm, Enc: asked.Enc}}, nil
}

// write answers with payload, sealed if the wallet asked. What cannot be sealed is not
// sent in the clear, to a wallet that said it would not take it that way.
func (s *Server) writeCredentialAnswer(w http.ResponseWriter, r *http.Request, seal *credentialSeal, status int, payload any) {
	if seal == nil {
		writeJSON(w, status, payload)
		return
	}
	ctx := r.Context()
	body, err := json.Marshal(payload)
	if err != nil {
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	sealed, err := tokens.EncryptTo(body, false, seal.keys, seal.how)
	if err != nil {
		s.log.ErrorContext(ctx, "sealing a credential response", "err", err, "correlation_id", correlationID(ctx))
		writeCredentialError(w, http.StatusInternalServerError, "server_error", "the response could not be encrypted")
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(sealed)); err != nil {
		s.log.InfoContext(ctx, "writing a credential response", "err", err, "correlation_id", correlationID(ctx))
	}
}

// credentialEncryptionMetadata is what §12.2.4 publishes, and nothing until there is a key.
func (s *Server) credentialEncryptionMetadata(r *http.Request) map[string]any {
	ctx := r.Context()
	set, err := keys.LoadSetFor(ctx, s.db, s.instanceID, keys.PurposeEncryption, s.root)
	if err != nil {
		s.log.ErrorContext(ctx, "loading the encryption keys", "err", err, "correlation_id", correlationID(ctx))
		return nil
	}
	published := set.PublicEncryptionJWKS()
	if len(published.Keys) == 0 {
		return nil
	}
	return map[string]any{
		"credential_request_encryption": map[string]any{"jwks": published,
			"enc_values_supported": tokens.ContentEncryptions, "encryption_required": false},
		"credential_response_encryption": map[string]any{"alg_values_supported": tokens.EncryptionAlgorithms,
			"enc_values_supported": tokens.ContentEncryptions, "encryption_required": false},
	}
}
