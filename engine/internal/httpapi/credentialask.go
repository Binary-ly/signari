package httpapi

import (
	"context"
	"slices"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/rar"
	"signari.dev/engine/internal/store"
)

// The authorization code flow of OID4VCI (12.06): a wallet asks for a credential at
// the authorization endpoint with details of type openid_credential, the holder
// signs in and approves it, and the token it gets names what it was granted.

// credentialDetailsRefused is what a request for credentials has to be whoever
// signs in, refused as RFC 9396 §5 refuses any other detail.
//
// Alone among the details of a request, because the token it gets is good at the
// credential endpoint and nowhere else (see issuanceOnly): another detail beside
// it would be approved on the consent screen and carried by a token no resource
// server takes, which is a permission weaker than it was shown to be.
func (s *Server) credentialDetailsRefused(ctx context.Context, c *clients.Client,
	details []rar.Detail) *oauth.AuthzError {

	wanted := rar.CredentialConfigurations(details)
	if len(wanted) == 0 {
		return nil
	}
	refuse := func(why string) *oauth.AuthzError {
		return &oauth.AuthzError{Code: rar.ErrorCode, Description: why, Disposition: oauth.DispositionRedirect}
	}
	if len(wanted) != len(details) {
		return refuse("details of type " + rar.CredentialType + " get a token good only at the credential " +
			"endpoint, so they are asked for alone")
	}
	configured, err := store.CredentialConfigurations(ctx, s.db, c.OrgID)
	if err != nil {
		s.log.Error("reading credential configurations", "err", err, "correlation_id", correlationID(ctx))
		return &oauth.AuthzError{Code: "server_error", Description: "unavailable",
			Disposition: oauth.DispositionRedirect}
	}
	for _, d := range details {
		if _, known := configured[d.CredentialConfigurationID]; !known {
			return refuse("this issuer offers no credential configuration " + d.CredentialConfigurationID)
		}
		// §5.1.1 asks for locations where metadata names authorization servers,
		// which this issuer's does not. One sent anyway has to mean this issuer.
		if len(d.Locations) > 0 && !slices.Contains(d.Locations, s.credentialIssuerID()) {
			return refuse("locations does not name this Credential Issuer")
		}
	}
	return nil
}

// credentialAskOf reads what an authorization request asks to have issued.
func credentialAskOf(req oauth.AuthzRequest, c *clients.Client, userID string) store.CredentialAsk {
	return store.CredentialAsk{OrgID: c.OrgID, UserID: userID, ClientID: c.ClientID,
		IssuerState: req.IssuerState, Configurations: rar.CredentialConfigurations(req.AuthorizationDetails)}
}

// credentialNotOpen is the refusal of a person who may not have what was asked for.
// It does not say which of the reasons, or that an offer exists for somebody else.
func credentialNotOpen() *oauth.AuthzError {
	return &oauth.AuthzError{Code: "access_denied", Description: "this credential has not been offered to this account",
		Disposition: oauth.DispositionRedirect}
}
