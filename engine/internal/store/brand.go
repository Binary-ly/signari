package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/brand"
)

// LoadBrandByIssuer reads the appearance of the instance serving an issuer.
//
// Keyed on issuer because that is what a running engine knows about itself: an
// instance IS one issuer on one hostname, and the serving process is configured
// with the issuer rather than the row id.
//
// A missing row is not an error: an unbranded deployment is the normal state,
// and returning an error for it would make every page render log something.
func LoadBrandByIssuer(ctx context.Context, db *pgxpool.Pool, issuer string) (*brand.Brand, error) {
	var b brand.Brand
	err := db.QueryRow(ctx, `
		SELECT COALESCE(product_name,''), COALESCE(logo_url,''), COALESCE(support_url,''),
		       COALESCE(colour_primary,''), COALESCE(colour_on_primary,''),
		       COALESCE(colour_background,''), COALESCE(colour_text,'')
		FROM core.brands b
		JOIN core.instances i ON i.id = b.instance_id
		WHERE i.issuer = $1`, issuer).
		Scan(&b.ProductName, &b.LogoURL, &b.SupportURL,
			&b.Primary, &b.OnPrimary, &b.Background, &b.Text)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &b, nil
}

// SaveBrand writes one, replacing whatever was there.
//
// Validation happens in the brand package before this is called and again in
// the database constraints. Two gates rather than one because the failure mode
// -- an unreadable sign-in page, or a colour that escapes its declaration --
// is discovered by the people least able to report it.
func SaveBrand(ctx context.Context, db *pgxpool.Pool, instanceID string, b *brand.Brand) error {
	if err := b.Validate(); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `
		INSERT INTO core.brands (instance_id, product_name, logo_url, support_url,
		                         colour_primary, colour_on_primary,
		                         colour_background, colour_text)
		VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''),
		        NULLIF($5,''), NULLIF($6,''), NULLIF($7,''), NULLIF($8,''))
		ON CONFLICT (instance_id) DO UPDATE SET
			product_name = EXCLUDED.product_name,
			logo_url = EXCLUDED.logo_url,
			support_url = EXCLUDED.support_url,
			colour_primary = EXCLUDED.colour_primary,
			colour_on_primary = EXCLUDED.colour_on_primary,
			colour_background = EXCLUDED.colour_background,
			colour_text = EXCLUDED.colour_text,
			updated_at = now()`,
		instanceID, b.ProductName, b.LogoURL, b.SupportURL,
		b.Primary, b.OnPrimary, b.Background, b.Text)
	return err
}
