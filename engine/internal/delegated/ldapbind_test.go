package delegated

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Verifying against a directory being migrated from.
//
// The password goes to a third party. That is the point and it is the risk, so
// the rules below are enforced rather than configured — there is no option to
// turn any of them off, for the same reason the HTTP verifier has no option to
// allow http://.

func TestAPlaintextURLIsRefused(t *testing.T) {
	err := VerifyLDAP(context.Background(), LDAPSource{
		URL:            "ldap://dir.example.test",
		BindDNTemplate: "uid={username},dc=example,dc=test",
	}, "alice", "hunter2")

	if !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("err = %v, want ErrInsecureTransport. A plaintext simple bind "+
			"puts the user's password on the wire in the clear.", err)
	}
}

// The refusal happens before any connection is attempted.
func TestAnEmptyPasswordIsRefusedBeforeDialling(t *testing.T) {
	// An unroutable address: if this dialled, the test would hang or return a
	// connection error rather than the refusal.
	err := VerifyLDAP(context.Background(), LDAPSource{
		URL:            "ldaps://192.0.2.1:636",
		BindDNTemplate: "uid={username},dc=example,dc=test",
	}, "alice", "")

	if err == nil {
		t.Fatal("an empty password was accepted")
	}
	if !strings.Contains(err.Error(), "unauthenticated bind") {
		t.Errorf("err = %v; it should name the RFC 4513 unauthenticated bind, "+
			"which is what a directory answering success to this would be doing", err)
	}
}

// A template with no placeholder is a configuration mistake, not a DN.
func TestABindTemplateWithoutThePlaceholderIsRefused(t *testing.T) {
	err := VerifyLDAP(context.Background(), LDAPSource{
		URL:            "ldaps://192.0.2.1:636",
		BindDNTemplate: "uid=fixed,dc=example,dc=test",
	}, "alice", "hunter2")

	if err == nil || !strings.Contains(err.Error(), "{username}") {
		t.Fatalf("err = %v; a template with no placeholder would bind as the same "+
			"DN for every user, authenticating everybody as one account", err)
	}
}

// ldaps:// is accepted as far as the dial.
//
// The address is unroutable, so a connection error proves the transport check
// passed and the refusals above are not simply refusing everything.
func TestALDAPSURLPassesTheTransportCheck(t *testing.T) {
	err := VerifyLDAP(context.Background(), LDAPSource{
		URL:            "ldaps://192.0.2.1:636",
		BindDNTemplate: "uid={username},dc=example,dc=test",
	}, "alice", "hunter2")

	if errors.Is(err, ErrInsecureTransport) {
		t.Fatal("ldaps:// was refused as insecure; the transport check is " +
			"refusing everything")
	}
	if err == nil {
		t.Fatal("an unroutable address returned success")
	}
	if !strings.Contains(err.Error(), "connecting to the source directory") {
		t.Errorf("err = %v; expected a connection failure, which is what proves "+
			"the transport check let this through", err)
	}
}

// A bind failure says nothing about which half was wrong.
//
// Some directories distinguish "no such user" from "wrong password". Passing
// that through would make this a user-enumeration oracle for a system we do not
// control and cannot fix.
func TestABindFailureDoesNotDistinguishTheCause(t *testing.T) {
	// Checked at the source rather than over a live connection: the property is
	// that the directory's own message never reaches the caller, and there is no
	// way to assert the absence of a string in an error that is never produced.
	src := readSourceFile(t, "ldapbind.go")

	bind := src[strings.Index(src, "conn.Bind(dn, password)"):]
	if i := strings.Index(bind, "}"); i > 0 {
		bind = bind[:i]
	}
	if strings.Contains(bind, "%w") || strings.Contains(bind, "err)") {
		t.Error("the directory's bind error is wrapped into the returned error. " +
			"Some directories distinguish `no such user` from `wrong password`, " +
			"and passing that through makes this a user-enumeration oracle for " +
			"a system we do not control and cannot fix.")
	}
	// "enumeration oracle" rather than a longer phrase: the reason is written
	// across several comment lines, so anything spanning a line break is
	// matching the formatting rather than the meaning. The first version
	// searched for a phrase that wrapped, and failed on a file that said
	// exactly the right thing.
	if !strings.Contains(src, "enumeration oracle") {
		t.Error("the reason the bind error is swallowed is not recorded, so " +
			"somebody will helpfully add it back")
	}
}

// The dial is bounded, not only the operations after it.
//
// `SetTimeout` applies once a connection exists. Without a dial timeout an
// unreachable directory blocks for the operating system's TCP timeout — about a
// minute — holding a sign-in open for every attempt.
func TestTheDialIsBounded(t *testing.T) {
	start := time.Now()
	_ = VerifyLDAP(context.Background(), LDAPSource{
		URL:            "ldaps://192.0.2.1:636", // TEST-NET-1, unroutable
		BindDNTemplate: "uid={username},dc=example,dc=test",
	}, "alice", "hunter2")

	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("reaching an unreachable directory took %s. Without a dial "+
			"timeout this is a minute of held sign-in per attempt, on the one "+
			"path a third party controls the latency of.", elapsed)
	}
}
