package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// A signed LogoutRequest to a service provider's SOAP address (8.03), for a session
// that ended with no browser to walk through the redirect chain. Retried like a
// back-channel logout, since a provider down for a minute has still to be told.

// maxSOAPAnswer is as much of an answer as is read.
const maxSOAPAnswer = 1 << 20

func (w *Worker) drainSAMLLogouts(ctx context.Context) (int, error) {
	return w.drainTopic(ctx, drainSpec{
		topic: store.SAMLLogoutTopic,
		batch: w.batch,
		deliver: func(ctx context.Context, raw []byte) error {
			var n store.SAMLLogoutNotice
			if err := json.Unmarshal(raw, &n); err != nil {
				return fmt.Errorf("decoding a SAML logout: %w", err)
			}
			return w.tellSAMLProvider(ctx, n)
		},
		backoff: backoffFor,
		onFailure: func(raw []byte, attempts int, err error) {
			var n store.SAMLLogoutNotice
			_ = json.Unmarshal(raw, &n)
			w.log.Warn("telling a SAML service provider of a logout failed",
				"provider_id", n.ProviderID, "attempt", attempts+1, "err", err)
		},
	})
}

func (w *Worker) tellSAMLProvider(ctx context.Context, n store.SAMLLogoutNotice) error {
	t, err := store.SAMLLogoutTargetOf(ctx, w.db, n.SID, n.ProviderID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &droppedError{reason: "the service provider no longer takes this"}
	}
	if err != nil {
		return err
	}
	as, err := w.signerOfInstance(t.InstanceID)
	if err != nil {
		return err
	}
	alg := keys.RS256
	if t.SignatureAlg == saml.SignatureAlgECDSASHA256 {
		alg = keys.ES256
	}
	key, err := as.keys.Active(alg)
	if err != nil {
		return fmt.Errorf("no active %s key to sign a logout with: %w", alg, err)
	}
	cert, err := w.samlCertificate(ctx, key, as.issuer)
	if err != nil {
		return err
	}
	format := t.NameIDFormat
	if format == "" {
		format = saml.NameIDFormatPersistent
	}
	doc, err := saml.BuildLogoutRequest(saml.LogoutRequestInput{Issuer: as.issuer + "/saml", Destination: t.URL,
		NameID: t.NameID, NameIDFormat: format, SessionIndex: t.SessionIndex, Now: time.Now()}, key.Signer(), cert)
	if err != nil {
		return err
	}
	var sent saml.LogoutRequest
	if err := saml.Unmarshal([]byte(doc), &sent); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, strings.NewReader(saml.SOAPEnvelope(doc)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", saml.SOAPAction)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSOAPAnswer))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the provider answered %d", resp.StatusCode)
	}
	return saml.ReadSOAPLogoutResponse(body, sent.ID)
}

// samlCertificate is the certificate a signature is carried with.
func (w *Worker) samlCertificate(ctx context.Context, k keys.Key, issuer string) ([]byte, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	der, err := saml.EnsureCertificate(ctx, tx, k.KID(), issuer, k.Signer())
	if err != nil {
		return nil, err
	}
	return der, tx.Commit(ctx)
}
