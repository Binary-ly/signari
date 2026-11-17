# Test fixtures

`GeoIP2-City-Test.mmdb` is MaxMind's own test database, taken from
`maxmind/MaxMind-DB` at `test-data/`, which is published under **Apache-2.0**.

It is here so the database reader can be exercised against real records without
licensing production data. It contains a handful of documentation ranges and
their positions — no real subscriber data.

`asn-test.mmdb` is written by `tools/mmdbfixture` (`go run . ../../engine/internal/risk/testdata`)
in the layout of GeoLite2-ASN and DB-IP's IP-to-ASN Lite, whose field names were read
from DB-IP's own file: 203.0.113.0/24 is AS64500, 198.51.100.0/24 AS64666, and
2001:db8::/32 AS64501. Documentation ranges and private-use AS numbers only.
