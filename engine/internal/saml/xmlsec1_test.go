package saml

import (
	"os/exec"
	"strings"
	"sync"
)

var (
	laxOnce sync.Once
	laxArgs []string
)

// laxKeySearch is `--lax-key-search` where this xmlsec1 has it, and nothing where it does
// not. xmlsec1 1.3 finds a key loaded with --privkey-pem or --pubkey-cert-pem for a
// template that names none only when told to search laxly; 1.2, which Ubuntu 24.04 ships
// (1.2.39), has no such flag and refuses the whole command line with "parameter
// "--lax-key-search" is not supported". Every test that signed or encrypted with xmlsec1
// failed that way in CI, which runs on that release, and passed on a machine with 1.3.
// The flag is listed by a command's own help, `sign --help`, not by the top-level one.
func laxKeySearch(bin string) []string {
	laxOnce.Do(func() {
		out, _ := exec.Command(bin, "sign", "--help").CombinedOutput()
		if strings.Contains(string(out), "--lax-key-search") {
			laxArgs = []string{"--lax-key-search"}
		}
	})
	return laxArgs
}

// xmlsec1Args is the command line for one xmlsec1 operation, with the lax key search
// where this version has it, placed right after the command as 1.3 takes it.
func xmlsec1Args(bin, command string, rest ...string) []string {
	return append(append([]string{command}, laxKeySearch(bin)...), rest...)
}
