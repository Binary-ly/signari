//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
)

// peerSupported says whether setup, running as root, can reach a local
// PostgreSQL as the postgres system user.
const peerSupported = true

// peerDial connects over a Unix socket as the system user uid, for
// PostgreSQL's peer authentication, which names the database role after the
// operating-system user at the other end of the socket. On Debian and Ubuntu
// `local all postgres peer` is the way to the postgres role, and root is not
// postgres.
//
// The server reads who is connecting from the socket's peer credentials, which
// "are those that were in effect at the time of the call to connect(2)"
// (unix(7), SO_PEERCRED), and the kernel reports the effective uid there. So
// the effective uid is uid for the dial alone, and root again before anything
// else runs; setup's end-to-end run on Debian is what proves it.
func peerDial(uid int) pgconn.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := syscall.Seteuid(uid); err != nil {
			return nil, fmt.Errorf("becoming the postgres system user to connect: %w", err)
		}
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if rerr := syscall.Seteuid(0); rerr != nil {
			// Never go on as another user: every file setup writes next
			// would be written as postgres.
			fmt.Fprintf(os.Stderr, "signari: could not become root again after connecting as uid %d: %v\n", uid, rerr)
			os.Exit(1)
		}
		return conn, err
	}
}
