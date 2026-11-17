package doctor

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A policy asking which network an address is on, with nothing that can answer, is
// named: with no ASN source, with a GeoIP source and no ASN one (the check used to
// stop at the first), and with a file that is not an ASN database. With a source it is
// not.
func TestANetworkRuleWithNoASNSourceIsReported(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("no dsn")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skip(err)
	}
	defer conn.Close(ctx)

	// Rolled back: checkPolicy reads on this connection, inside the transaction.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var orgID string
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://asn-probe.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'asn-probe', 'probe' FROM i RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.access_policies (org_id, document) VALUES ($1::uuid, $2)`, orgID, `
version: 1
policies:
  - name: our-network
    require:
      from_asns: [64500]
tests:
  - {name: ours, given: {client: x, asn: 64500}, expect: allow}
`); err != nil {
		t.Fatal(err)
	}

	probe := func() *Finding {
		t.Helper()
		r := &Report{}
		if err := checkPolicy(ctx, conn, r); err != nil {
			t.Fatal(err)
		}
		for i, f := range r.Findings {
			if strings.Contains(f.Summary, "asn-probe") {
				return &r.Findings[i]
			}
		}
		return nil
	}
	for _, c := range []struct{ name, geo, asnDB, asnStatic, want string }{
		{"nothing configured", "", "", "", "SIGNARI_GEOIP_ASN_DB"},
		{"GeoIP and no ASN source", "203.0.113.0/24=GB,51.5,-0.1", "", "", "SIGNARI_GEOIP_ASN_DB"},
		{"a city database named as the ASN one", "", "../risk/testdata/GeoIP2-City-Test.mmdb", "", "holds no autonomous system numbers"},
		{"a map that does not parse", "", "", "203.0.113.0/24", "could not be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SIGNARI_GEOIP_DB", "")
			t.Setenv("SIGNARI_GEOIP_STATIC", c.geo)
			t.Setenv("SIGNARI_GEOIP_ASN_DB", c.asnDB)
			t.Setenv("SIGNARI_GEOIP_ASN_STATIC", c.asnStatic)
			f := probe()
			if f == nil || f.Severity != Warning || !strings.Contains(f.Summary, "which network") ||
				!strings.Contains(f.Fix, c.want) {
				t.Fatalf("want a warning whose fix names %q, got %+v", c.want, f)
			}
		})
	}
	t.Setenv("SIGNARI_GEOIP_DB", "")
	t.Setenv("SIGNARI_GEOIP_STATIC", "")
	t.Setenv("SIGNARI_GEOIP_ASN_DB", "../risk/testdata/asn-test.mmdb")
	t.Setenv("SIGNARI_GEOIP_ASN_STATIC", "")
	if f := probe(); f != nil {
		t.Errorf("reported with an ASN database that answers: %+v", f)
	}
}
