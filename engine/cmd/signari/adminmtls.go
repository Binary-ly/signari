package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// adminClientAuth is what the admin listener asks of a caller's certificate. With no
// SIGNARI_ADMIN_CLIENT_CA it asks nothing, and a token alone admits. With one, a caller
// must also hold a certificate that authority signed (V12.3.5), so a token lifted from
// a console's environment opens nothing from anywhere else.
//
// Refused outright on a listener with no certificate of its own. A client certificate
// is asked for in the TLS handshake, so on plaintext nothing would ask, and an operator
// who set it would believe it was on. A setting that does nothing is worse than none.
func adminClientAuth(caFile, tlsCert string) (*tls.Config, error) {
	if caFile == "" {
		return nil, nil
	}
	if tlsCert == "" {
		return nil, fmt.Errorf("SIGNARI_ADMIN_CLIENT_CA needs the admin API on TLS, and it has no " +
			"certificate: pass -tls-cert and -tls-key, or a client certificate is asked for by nothing")
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 -- the operator names the file
	if err != nil {
		return nil, fmt.Errorf("SIGNARI_ADMIN_CLIENT_CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("SIGNARI_ADMIN_CLIENT_CA: %s holds no PEM certificate", caFile)
	}
	return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
