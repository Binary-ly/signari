package httpapi

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Turning a verified client certificate into a user.
//
// The TLS layer has already proved two things by the time this runs: the
// certificate chains to a configured authority, and the supplicant holds its
// private key. Neither says who the person is or whether they may still be
// here, and those are different questions:
//
//	chains to our CA   the certificate is genuine
//	names a live user  the person still works here
//
// A certificate is valid until it expires or is revoked, and a deactivated
// employee's certificate stays cryptographically perfect for as long as it has
// left to run. Checking the account status is what makes deprovisioning work at
// the network door as well as at the login page.

// EAPCertAuthenticator maps a certificate to a username.
type EAPCertAuthenticator struct {
	db    *pgxpool.Pool
	orgID string
	// identityFrom names which part of the certificate carries the identity.
	identityFrom string
}

// NewEAPCertAuthenticator builds the mapping used by the RADIUS listener.
//
// identityFrom is "cn", "email" or "upn":
//
//	cn     the subject common name, what most internal PKI puts a username in
//	email  an rfc822Name in the subject alternative name
//	upn    the Microsoft userPrincipalName SAN, which is what AD-issued
//	       certificates carry and what an AD-joined laptop presents
func NewEAPCertAuthenticator(db *pgxpool.Pool, orgID, identityFrom string) *EAPCertAuthenticator {
	if identityFrom == "" {
		identityFrom = "cn"
	}
	return &EAPCertAuthenticator{db: db, orgID: orgID, identityFrom: identityFrom}
}

// oidUPN is the Microsoft userPrincipalName other-name in a SAN.
var oidUPN = []int{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// AuthenticateCertificate returns the username a certificate represents.
func (a *EAPCertAuthenticator) AuthenticateCertificate(cert *x509.Certificate) (string, error) {
	identity, err := a.identity(cert)
	if err != nil {
		return "", err
	}

	// A short deadline: an access point retransmits, and a slow answer here
	// becomes a supplicant retry rather than a login.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var userID, status string
	err = a.db.QueryRow(ctx, `
		SELECT id::text, status FROM core.users
		WHERE org_id = $1::uuid
		  AND (lower(email) = lower($2) OR lower(username) = lower($2))`,
		a.orgID, identity).Scan(&userID, &status)
	if err != nil {
		// Deliberately the same shape of answer for "no such user" as for a
		// database problem: the supplicant is told nothing either way, and the
		// distinction belongs in the log.
		return "", fmt.Errorf("no account matches %q in this organisation", identity)
	}
	if status != "active" {
		// The certificate is still cryptographically valid. That is precisely
		// why this check exists: revoking a certificate requires a CRL or OCSP
		// the access point may never consult, while deactivating the account
		// takes effect at the next association.
		return "", fmt.Errorf("the account for %q is %s", identity, status)
	}
	return identity, nil
}

// identity reads the configured field out of the certificate.
func (a *EAPCertAuthenticator) identity(cert *x509.Certificate) (string, error) {
	switch a.identityFrom {
	case "email":
		if len(cert.EmailAddresses) == 0 {
			return "", fmt.Errorf("this certificate has no email address in its " +
				"subject alternative name, and this listener is configured to " +
				"identify users by one")
		}
		return strings.TrimSpace(cert.EmailAddresses[0]), nil

	case "upn":
		upn, ok := upnFromSAN(cert)
		if !ok {
			return "", fmt.Errorf("this certificate has no userPrincipalName, and " +
				"this listener is configured to identify users by one")
		}
		return upn, nil

	default: // "cn"
		cn := strings.TrimSpace(cert.Subject.CommonName)
		if cn == "" {
			return "", fmt.Errorf("this certificate has an empty subject common name")
		}
		return cn, nil
	}
}

// upnFromSAN extracts the Microsoft userPrincipalName.
//
// Read from the raw extension because crypto/x509 does not surface otherName
// entries. Everything AD issues puts the identity here and leaves the common
// name as a display string, so a deployment that identifies by CN against
// AD-issued certificates matches the wrong field or nothing at all.
func upnFromSAN(cert *x509.Certificate) (string, bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal([]int{2, 5, 29, 17}) { // subjectAltName
			continue
		}
		if upn, ok := scanUPN(ext.Value); ok {
			return upn, true
		}
	}
	return "", false
}

// scanUPN walks the SAN extension for an otherName with the UPN OID.
//
// A deliberately small hand-rolled scan rather than a full ASN.1 decoder: the
// structure needed is one nested tag, and pulling in a parser to reach it would
// add a dependency to the network authentication path for twenty lines of work.
func scanUPN(der []byte) (string, bool) {
	// The encoded UPN OID, as it appears inside the otherName.
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03}
	idx := indexBytes(der, oid)
	if idx < 0 {
		return "", false
	}
	rest := der[idx+len(oid):]
	// [0] EXPLICIT, then a UTF8String: skip the two wrappers and read the value.
	if len(rest) < 4 || rest[0] != 0xa0 {
		return "", false
	}
	// rest[1] is the length of the explicit wrapper; rest[2] should be a string
	// tag (0x0c UTF8String, 0x16 IA5String) and rest[3] its length.
	if rest[2] != 0x0c && rest[2] != 0x16 {
		return "", false
	}
	n := int(rest[3])
	if n <= 0 || 4+n > len(rest) {
		return "", false
	}
	return strings.TrimSpace(string(rest[4 : 4+n])), true
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
