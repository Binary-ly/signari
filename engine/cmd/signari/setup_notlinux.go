//go:build !linux

package main

import "github.com/jackc/pgx/v5/pgconn"

// peerSupported is false away from Linux, where a local PostgreSQL is reached
// as the user who runs setup (Homebrew's, on macOS, trusts that user).
const peerSupported = false

// peerDial is never called where peerSupported is false.
func peerDial(int) pgconn.DialFunc { return nil }
