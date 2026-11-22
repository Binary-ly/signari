package store

import (
	"context"
	"encoding/json"
	"slices"

	"signari.dev/engine/internal/ssf"
)

// The words CAEP fixes for a credential-change's credential_type and change_type.
// An emailed code and a recovery code have no word there, so neither is reported.
const (
	CredentialPassword = "password"
	CredentialApp      = "app"
	CredentialSMS      = "phone-sms"

	credentialPlatformKey = "fido2-platform"
	credentialRoamingKey  = "fido2-roaming"

	ChangeCreate = "create"
	ChangeUpdate = "update"
	ChangeDelete = "delete"
)

// factorCredentialTypes names the sign-in methods with one row each. A passkey is
// not here, because which word it gets depends on the passkey.
var factorCredentialTypes = map[string]string{
	"totp":    CredentialApp,
	"duo":     CredentialApp,
	"sms_otp": CredentialSMS,
}

// ChangeOf says whether a method replaced one of its kind or is the first.
func ChangeOf(replaced bool) string {
	if replaced {
		return ChangeUpdate
	}
	return ChangeCreate
}

// passkeyCredentialType reads what a passkey is from how it says it is reached.
func passkeyCredentialType(transports []string) string {
	if slices.Contains(transports, "internal") {
		return credentialPlatformKey
	}
	return credentialRoamingKey
}

// QueueSecurityEvent tells the streams that asked for an event, and whose client
// has met this person, in the transaction of the change (migration 0212).
func QueueSecurityEvent(ctx context.Context, e Execer, userID, event string, claims map[string]any) error {
	raw, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	_, err = e.Exec(ctx, `SELECT core.queue_security_event($1::uuid, $2, $3::jsonb)`, userID, event, string(raw))
	return err
}

// QueueCredentialChange reports a change to one of a person's ways in. initiator
// is who made it, "user" or "admin".
func QueueCredentialChange(ctx context.Context, e Execer, userID, credentialType, change, initiator string) error {
	return QueueSecurityEvent(ctx, e, userID, ssf.EventCredentialChange, map[string]any{
		"credential_type":   credentialType,
		"change_type":       change,
		"initiating_entity": initiator,
	})
}
