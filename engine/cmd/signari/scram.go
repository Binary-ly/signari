package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// The engine role's password reaches PostgreSQL as a SCRAM-SHA-256 verifier,
// never as the password. Of a password given in clear, ALTER ROLE's page says
// it "will be transmitted to the server in cleartext, and it might also be
// logged in the client's command history or the server log"; CREATE ROLE's
// says that "If the presented password string is already in MD5-encrypted or
// SCRAM-encrypted format, then it is stored as-is" (PostgreSQL 17,
// sql-alterrole.html and sql-createrole.html). A verifier is what psql's
// \password sends. Setup also reads the verifier back, with a superuser's
// connection, to tell whether the role already has the password the env file
// holds without depending on pg_hba.conf to answer.

// scramIterations is PostgreSQL's own default: "The default is 4096"
// (scram_iterations, runtime-config-connection.html).
const scramIterations = 4096

// scramVerifier is password's SCRAM-SHA-256 verifier as pg_authid holds one,
// "SCRAM-SHA-256$<iteration count>:<salt>$<StoredKey>:<ServerKey>" with the
// last three in base64 (PostgreSQL 17, catalog-pg-authid.html), with a new
// random salt.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return scramVerifierWith(password, salt, scramIterations)
}

func scramVerifierWith(password string, salt []byte, iterations int) (string, error) {
	stored, server, err := scramKeys(password, salt, iterations)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(stored), b64(server)), nil
}

// scramKeys are StoredKey and ServerKey for password, derived as the driver
// that later signs in with it derives them (pgx v5.10.0, pgconn/auth_scram.go
// lines 322, 354-355 and 369): the salted password is PBKDF2 with SHA-256, 32
// bytes; ClientKey and ServerKey are its HMACs of "Client Key" and "Server
// Key"; StoredKey is the SHA-256 of ClientKey. The password is used as given,
// as the driver uses it, which for the letters and digits setup generates is
// also what normalising it would leave.
func scramKeys(password string, salt []byte, iterations int) (stored, server []byte, err error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	mac := func(msg string) []byte {
		h := hmac.New(sha256.New, salted)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	client := sha256.Sum256(mac("Client Key"))
	return client[:], mac("Server Key"), nil
}

// scramVerifierHolds says whether verifier, as pg_authid stores it, is
// password's. Anything but a SCRAM-SHA-256 verifier (none at all, an md5 hash)
// says no, and setup sets the password again.
func scramVerifierHolds(verifier, password string) bool {
	method, rest, ok := strings.Cut(verifier, "$")
	if !ok || method != "SCRAM-SHA-256" {
		return false
	}
	params, keys, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	iter, salt64, ok := strings.Cut(params, ":")
	if !ok {
		return false
	}
	stored64, server64, ok := strings.Cut(keys, ":")
	if !ok {
		return false
	}
	iterations, err := strconv.Atoi(iter)
	if err != nil || iterations < 1 || iterations > 1<<24 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil {
		return false
	}
	wantStored, err := base64.StdEncoding.DecodeString(stored64)
	if err != nil {
		return false
	}
	wantServer, err := base64.StdEncoding.DecodeString(server64)
	if err != nil {
		return false
	}
	stored, server, err := scramKeys(password, salt, iterations)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(stored, wantStored) == 1 && subtle.ConstantTimeCompare(server, wantServer) == 1
}
