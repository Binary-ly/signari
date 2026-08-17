package kerberos

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Listing the principals in a realm, so accounts can be created from it.
//
// # Why this shells out to kadmin
//
// The Kerberos administration protocol is RPC over GSSAPI with its own wire
// format, and there is no Go implementation of it. Writing one to list
// principals would be a large amount of protocol code whose only consumer is
// this function.
//
// `kadmin` is on every machine that administers a realm, it is the command an
// administrator already uses, and running it with a keytab is exactly how a
// scheduled job would do this by hand. The dependency is stated rather than
// hidden: Available reports whether the binary is there, and the sync says so
// plainly instead of returning an empty list.
//
// # LDAP is usually the better route, and the docs say so
//
// Active Directory and FreeIPA both publish the same principals over LDAP, with
// richer attributes and an immutable identifier this engine already understands.
// This exists for a realm that has neither -- MIT Kerberos on its own -- which
// is the only case where kadmin is the answer rather than a worse alternative.

// Admin lists principals in a realm.
type Admin struct {
	// Realm to administer.
	Realm string
	// Principal is the administrative principal, e.g. signari/admin@EXAMPLE.COM.
	Principal string
	// KeytabPath holds that principal's key.
	KeytabPath string
	// Binary overrides the kadmin path, for testing.
	Binary string
	// Timeout bounds the command.
	Timeout time.Duration
}

// Available reports whether kadmin can be run at all.
//
// Checked before a sync rather than after: "kadmin is not installed" and "the
// realm has no users" produce the same empty list otherwise, and only one of
// them is a problem somebody can fix.
func (a Admin) Available() error {
	bin := a.binary()
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("%s is not on PATH. Kerberos directory sync runs the "+
			"realm's own administration client; install the Kerberos workstation "+
			"package, or sync over LDAP instead, which Active Directory and "+
			"FreeIPA both support and which carries more than a principal name", bin)
	}
	return nil
}

func (a Admin) binary() string {
	if a.Binary != "" {
		return a.Binary
	}
	return "kadmin"
}

// Principals lists the principals in the realm.
//
// Service and administrative principals are filtered out here rather than by
// the caller: they have instance components, they are not people, and an
// account created from `host/web01@REALM` is an account nobody can explain.
func (a Admin) Principals(ctx context.Context) ([]string, error) {
	switch {
	case a.Realm == "":
		return nil, fmt.Errorf("no realm given")
	case a.Principal == "":
		return nil, fmt.Errorf("give the administrative principal kadmin authenticates as")
	case a.KeytabPath == "":
		return nil, fmt.Errorf("give the keytab holding that principal's key")
	}
	if err := a.Available(); err != nil {
		return nil, err
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// -k -t: authenticate with the keytab rather than prompting, which is what
	// makes this runnable from a scheduled job.
	cmd := exec.CommandContext(ctx, a.binary(),
		"-r", strings.ToUpper(a.Realm),
		"-p", a.Principal,
		"-k", "-t", a.KeytabPath,
		"-q", "list_principals")

	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if stderr == "" {
			stderr = err.Error()
		}
		return nil, fmt.Errorf("kadmin failed: %s", stderr)
	}
	return ParsePrincipals(string(out), a.Realm), nil
}

// ParsePrincipals extracts user principals from kadmin's output.
//
// Separate from the command so it can be tested without a realm. kadmin prints
// a header line and then one principal per line, and the header changes between
// versions -- so anything that does not look like a principal in this realm is
// skipped rather than parsed.
func ParsePrincipals(out, realm string) []string {
	var names []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, r, found := strings.Cut(line, "@")
		if !found || !strings.EqualFold(r, realm) {
			// A header, a warning, or a principal from a realm we do not manage.
			continue
		}
		// Instance components mean a service or administrative principal.
		if strings.Contains(name, "/") {
			continue
		}
		// kadmin's own principals, which exist in every realm and are not people.
		switch name {
		case "kadmin", "krbtgt", "changepw", "K":
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
