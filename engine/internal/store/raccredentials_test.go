package store

import (
	"errors"
	"testing"

	"signari.dev/engine/internal/keys"
)

// A key reaches guacd by the parameter names it takes, and a connection holding
// nothing sends it nothing, which is what makes guacd ask the viewer (8.28). The two
// are one path: a credential merged in under another name would be sent empty, and
// the person would be asked for something the connection holds.
func TestWhatAConnectionHoldsIsWhatGuacdIsGiven(t *testing.T) {
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	const key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	sealed, err := RACCredentials{Login: "deploy", PrivateKey: key, Passphrase: "opens"}.seal(root, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	c := &RACConnection{Protocol: "ssh", Hostname: "h", Port: 22, secrets: sealed}
	got, err := c.Resolve(root, 800, 600, 96)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"username": "deploy", "private-key": key, "passphrase": "opens"} {
		if got.Parameters[name] != want {
			t.Errorf("%s reached guacd as %q", name, got.Parameters[name])
		}
	}
	if _, sent := got.Parameters["password"]; sent {
		t.Error("a password nobody gave was sent")
	}

	none, err := RACCredentials{}.seal(root, "rdp")
	if err != nil || none != nil {
		t.Fatalf("nothing sealed to %v (%v)", none, err)
	}
	if none, err = (RACCredentials{}).seal(nil, "rdp"); err != nil || none != nil {
		t.Errorf("a connection asking the viewer needs no root key: %v (%v)", none, err)
	}
	empty := &RACConnection{Protocol: "rdp", Hostname: "h", Port: 3389}
	asked, err := empty.Resolve(nil, 800, 600, 96)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"username", "password"} {
		if _, sent := asked.Parameters[name]; sent {
			t.Errorf("%s was sent for a connection holding none", name)
		}
	}

	for name, c := range map[string]struct {
		credentials RACCredentials
		protocol    string
	}{
		"a key on rdp":        {RACCredentials{PrivateKey: key}, "rdp"},
		"a key on vnc":        {RACCredentials{PrivateKey: key}, "vnc"},
		"something not a key": {RACCredentials{PrivateKey: "ssh-ed25519 AAAA"}, "ssh"},
		"a passphrase alone":  {RACCredentials{Passphrase: "opens nothing"}, "ssh"},
	} {
		if _, err := c.credentials.seal(root, c.protocol); !errors.Is(err, ErrRACKey) {
			t.Errorf("%s answered %v", name, err)
		}
	}
}

// Each credential is a parameter nobody can set in the clear beside it.
func TestEveryCredentialIsAReservedParameter(t *testing.T) {
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := RACCredentials{Login: "l", Password: "p", PrivateKey: "-----BEGIN K-----\nAAAA\n-----END K-----\n",
		Passphrase: "s"}.seal(root, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&RACConnection{Hostname: "h", secrets: sealed}).Resolve(root, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for name := range got.Parameters {
		reserved := false
		for _, r := range RACReservedParameters {
			reserved = reserved || r == name
		}
		if !reserved {
			t.Errorf("%s carries a credential and could also be set as a parameter", name)
		}
	}
}
