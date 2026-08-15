package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/dpop"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// DPoP wiring: bind at the token endpoint, enforce at every resource.
//
// The two halves are useless apart. Binding without enforcement produces tokens
// that CLAIM to be sender-constrained and are not -- which is worse than plain
// bearer tokens, because a relying party reading `cnf` will believe them.

type dpopCtxKey struct{}

// withDPoPThumbprint carries a verified thumbprint down to token minting.
func withDPoPThumbprint(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, dpopCtxKey{}, jkt)
}

func dpopThumbprintFrom(ctx context.Context) string {
	s, _ := ctx.Value(dpopCtxKey{}).(string)
	return s
}

func confirmationFor(jkt string) *tokens.Confirmation {
	if jkt == "" {
		return nil
	}
	return &tokens.Confirmation{JKT: jkt}
}

// confirmationForCert is the mutual-TLS equivalent, RFC 8705 §3.1.
//
// Same claim, different member: `cnf.x5t#S256` instead of `cnf.jkt`. A token can
// carry only one -- a client authenticating with both DPoP and mTLS would be
// asserting two different possession proofs for one token, and deciding which
// one a resource server must check is not a question to leave open.
func confirmationForCert(thumbprint string) *tokens.Confirmation {
	if thumbprint == "" {
		return nil
	}
	return &tokens.Confirmation{X5TS256: thumbprint}
}

// bearerOrDPoP names the token type.
//
// RFC 9449 §5: a sender-constrained token is issued as token_type "DPoP", not
// "Bearer". The distinction is not cosmetic -- a client told "Bearer" will send
// `Authorization: Bearer ...` and no proof, and the request will be refused.
func bearerOrDPoP(jkt string) string {
	if jkt == "" {
		return "Bearer"
	}
	return "DPoP"
}

// verifyDPoPForRequest checks a proof and its replay record.
//
// Returns the thumbprint on success. An absent header is not an error here: the
// caller decides whether a proof was required, because that depends on whether
// the token being presented is bound.
func (s *Server) verifyDPoPForRequest(r *http.Request, accessToken string) (string, error) {
	header := r.Header.Get("DPoP")
	if header == "" {
		return "", nil
	}

	// The URI as WE saw it, rebuilt from the configured issuer rather than from
	// request headers. Taking the host from the Host header would let a caller
	// choose what their proof authorises by lying about where they sent it.
	uri := s.cfg.Issuer + r.URL.Path

	proof, err := dpop.Verify(header, r.Method, uri, accessToken, time.Now())
	if err != nil {
		return "", err
	}

	// Replay. The proof is fresh, signed and correctly bound -- and still
	// replayable within its lifetime by whoever captured it.
	fresh, err := store.MarkDPoPProofSeen(r.Context(), s.db, proof.JKT, proof.JTI,
		dpop.MaxAge+dpop.MaxSkew)
	if err != nil {
		s.log.Error("recording a DPoP proof", "err", err)
		// Fail CLOSED. If replay detection is unavailable, the proof cannot be
		// shown to be fresh, and accepting it would silently drop the protection
		// exactly when the database is unhappy.
		return "", errDPoPUnavailable
	}
	if !fresh {
		return "", errDPoPReplay
	}
	return proof.JKT, nil
}

var (
	errDPoPReplay      = errors.New("this DPoP proof has already been used")
	errDPoPUnavailable = errors.New("DPoP replay detection is unavailable")
)

// bindingFor chooses the one confirmation a token may carry.
//
// DPoP wins when both are present. A client doing both is asserting two
// possession proofs for one token, and a resource server has to know which to
// check -- so one is chosen here rather than leaving the question open in the
// claim. DPoP is preferred because it is the proof the client had to construct
// deliberately for this request; the certificate is a property of a connection
// it may not even know is mutually authenticated.
func bindingFor(jkt, certThumbprint string) *tokens.Confirmation {
	if jkt != "" {
		return confirmationFor(jkt)
	}
	return confirmationForCert(certThumbprint)
}

type certThumbKey struct{}

// withCertThumbprint carries the presented certificate's thumbprint.
func withCertThumbprint(ctx context.Context, thumb string) context.Context {
	if thumb == "" {
		return ctx
	}
	return context.WithValue(ctx, certThumbKey{}, thumb)
}

func certThumbprintFrom(ctx context.Context) string {
	t, _ := ctx.Value(certThumbKey{}).(string)
	return t
}
