// Command mmdbfixture writes the small MaxMind-format ASN database the engine's tests
// read in place of a licensed one, laid out as GeoLite2-ASN and DB-IP's IP-to-ASN Lite
// are (the field names read from DB-IP's file in November 2026). Documentation ranges
// only. The city database the ASN reader must refuse is the GeoIP2-City test file
// already in that directory.
//
//	cd tools/mmdbfixture && go run . ../../engine/internal/risk/testdata
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mmdbfixture <directory>")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := write(filepath.Join(dir, "asn-test.mmdb"), "Signari-Test-ASN", map[string]mmdbtype.Map{
		"203.0.113.0/24": {"autonomous_system_number": mmdbtype.Uint32(64500),
			"autonomous_system_organization": mmdbtype.String("Example Network A")},
		"198.51.100.0/24": {"autonomous_system_number": mmdbtype.Uint32(64666),
			"autonomous_system_organization": mmdbtype.String("Example Hosting B")},
		"2001:db8::/32": {"autonomous_system_number": mmdbtype.Uint32(64501),
			"autonomous_system_organization": mmdbtype.String("Example Network A")},
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func write(path, kind string, records map[string]mmdbtype.Map) error {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: kind,
		RecordSize:   24,
		// The documentation ranges are reserved, and reserved ranges are what a
		// fixture must use, so nothing in it is anybody's address.
		IncludeReservedNetworks: true,
		Description:             map[string]string{"en": "Signari test fixture, documentation ranges only"},
	})
	if err != nil {
		return err
	}
	for cidr, rec := range records {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		if err := w.Insert(n, rec); err != nil {
			return fmt.Errorf("%s: %w", cidr, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := w.WriteTo(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
