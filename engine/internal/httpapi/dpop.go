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
