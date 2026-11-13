module signari.dev/engine

// The go version is a FLOOR, not a preference, and it has moved twice for the
// same reason. On 1.26.5 govulncheck found seven standard library advisories
// reachable from this code (encoding/xml, net/url, html/template, crypto/tls,
// net/http, encoding/asn1), fixed in 1.26.6. On 1.26.6 it found twelve more,
// fixed in 1.26.9: html/template escaping on every page we render, HTTP/1 and
// HTTP/2 desynchronisation, memory and CPU exhaustion in the HTTP/2 server, MIME
// header and Range limits, and ECH parsing in crypto/tls. On 1.26.9 it found
// GO-2026-6809, crypto/x509 trusting compromised intermediate certificates,
// reachable from the FIDO metadata check that anchors an authenticator's
// attestation; fixed in 1.26.10, and the release script refused to build until it
// moved. On 1.26.10 it found GO-2026-6859, an HTTP/1 server crash through a header
// race in MaxBytesReader, which bounds request bodies on 24 paths here; fixed in
// 1.26.11, and again the release script refused to build. Building with an older
// toolchain reintroduces all of them, and nothing else in this repository would say
// so -- which is why CI runs govulncheck. See docs/security-scanning.md.
go 1.26.11

require (
	github.com/beevik/etree v1.7.0
	github.com/coder/websocket v1.8.15
	github.com/eclipse-keypont/crypto11 v1.6.8
	github.com/go-asn1-ber/asn1-ber v1.5.8
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/jcmturner/gofork v1.7.6
	github.com/jcmturner/goidentity/v6 v6.0.1
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/openwall/yescrypt-go v1.0.0
	github.com/oschwald/maxminddb-golang/v2 v2.5.0
	github.com/russellhaering/goxmldsig v1.6.1
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	golang.org/x/crypto v0.57.0
	golang.org/x/sync v0.23.0
	golang.org/x/text v0.42.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
