package httpapi

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/store"
)

// signInPage is what the sign-in page decides from on every render: what it wears, the
// providers it offers, and whether it links sign-up, keeps a person signed in, routes
// by address, offers passkeys and offers a Kerberos ticket (its link, or "").
type signInPage struct {
	brand        *brand.Brand
	providers    []externalProvider
	signup       bool
	persistent   bool
	singleSignOn bool
	passkeys     bool
	kerberos     string
}

// readSignInPage reads it in one round trip (E.36), each statement the one its own reader
// asks, still on every render, so a brand or a provider set a moment ago is on the next
// page. It was a statement each, in turn: ten of a render's dozen. The instance's first
// organisation is kept for the request, for the recovery link's flow.
//
// read is false when anything in the batch failed, and the caller then asks each the way
// it always has, logging as each does: a failure here is never more than a slower page.
func (s *Server) readSignInPage(ctx context.Context, orgID, authzQuery, host string) (page signInPage, read bool) {
	if s.db == nil {
		return page, false
	}
	b := &pgx.Batch{}
	instanceBrand := store.QueueInstanceBrand(b, s.cfg.Issuer)
	firstOrg := store.QueueFirstOrg(b, s.cfg.Issuer)
	signup := store.QueueFirstOrgSignupRule(b, s.cfg.Issuer)
	realmOrg := store.QueueKerberosHostOrg(b, s.instanceID, host)

	unasked := errors.New("not asked")
	orgBrand := func() (*brand.Brand, error) { return nil, nil }
	singleSignOn := func() (bool, error) { return false, nil }
	providersErr, persistentErr, passkeysErr := error(nil), error(nil), error(nil)
	if orgID != "" {
		orgBrand = store.QueueOrgBrand(b, orgID)
		singleSignOn = store.QueueRoutesByDomain(b, orgID)
		providersErr, persistentErr, passkeysErr = unasked, unasked, unasked
		b.Queue(externalProvidersStatement, orgID).Query(func(rows pgx.Rows) error {
			page.providers, providersErr = scanExternalProviders(rows, authzQuery)
			return nil
		})
		b.Queue(persistentOfferedStatement, orgID).QueryRow(func(row pgx.Row) error {
			persistentErr = row.Scan(&page.persistent)
			return nil
		})
		b.Queue(passkeysOfferedStatement, orgID).QueryRow(func(row pgx.Row) error {
			passkeysErr = row.Scan(&page.passkeys)
			return nil
		})
	}
	if err := s.db.SendBatch(ctx, b).Close(); err != nil {
		return signInPage{}, false
	}

	instance, ierr := instanceBrand()
	own, oerr := orgBrand()
	first, ferr := firstOrg()
	rule, rerr := signup()
	sso, serr := singleSignOn()
	hostOrg, kerr := realmOrg()
	for _, err := range []error{ierr, oerr, rerr, serr, kerr, providersErr, persistentErr, passkeysErr} {
		if err != nil {
			return signInPage{}, false
		}
	}
	if ferr != nil && !errors.Is(ferr, pgx.ErrNoRows) {
		return signInPage{}, false
	}

	// As brandOf: nothing with no issuer, the instance's on a page that is nobody's yet,
	// and an organisation's own over its instance's.
	switch {
	case s.cfg.Issuer == "":
		page.brand = nil
	case orgID == "":
		page.brand = instance
	default:
		page.brand = own.Over(instance)
	}
	page.signup = rule != nil
	page.singleSignOn = sso
	if memo, _ := ctx.Value(loginOrgKey{}).(*loginOrgMemo); memo != nil {
		memo.defaultAsked, memo.defaultOrg, memo.defaultErr = true, first, ferr
	}
	page.kerberos = s.kerberosLinkWith(ctx, orgID, authzQuery, hostOrg, first, true)
	return page, true
}
