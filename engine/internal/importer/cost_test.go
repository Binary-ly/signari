package importer

import (
	"context"
	"strings"
	"testing"
)

// An imported hash whose cost is over what sign-in will verify is refused at
// import, by name and with the reason, rather than imported and then refused
// at every attempt. Both importers asked only "is the format known", so a
// phpass hash at 2^21 iterations or a Keycloak credential at two million
// became an account nobody could sign in to.

func TestAnImportedHashCostingMoreThanSignInAllowsIsSkippedWithTheReason(t *testing.T) {
	exp, err := ParseAuthentik(strings.NewReader(`[
	 {"model":"authentik_core.user","pk":1,"fields":{"username":"cheap","email":"cheap@x.test",
	  "password":"$P$Isaltsalt0123456789abcdefghij","is_active":true,"ak_groups":[]}},
	 {"model":"authentik_core.user","pk":2,"fields":{"username":"dear","email":"dear@x.test",
	  "password":"$P$Jsaltsalt0123456789abcdefghij","is_active":true,"ak_groups":[]}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportAuthentik(context.Background(), nil, "org", exp, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.UsersCreated != 1 {
		t.Errorf("%d users would be created, want only the one at 2^20 iterations", res.UsersCreated)
	}
	if len(res.UsersSkipped) != 1 || !strings.Contains(res.UsersSkipped[0], "dear@x.test") ||
		!strings.Contains(res.UsersSkipped[0], "2^21") {
		t.Errorf("the 2^21 hash was not skipped with its reason: %q", res.UsersSkipped)
	}

	realm, err := Parse(strings.NewReader(`{"realm":"r","users":[
	 {"username":"dear","email":"dear@x.test","enabled":true,"credentials":[{"type":"password",
	  "secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",
	  "credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":2000000}"}]},
	 {"username":"cheap","email":"cheap@x.test","enabled":true,"credentials":[{"type":"password",
	  "secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",
	  "credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":27500}"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	kres, err := Import(context.Background(), nil, "org", realm, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if kres.UsersCreated != 1 {
		t.Errorf("%d Keycloak users would be created, want only the one at 27500 iterations", kres.UsersCreated)
	}
	if len(kres.UsersSkipped) != 1 || !strings.Contains(kres.UsersSkipped[0], "2000000") {
		t.Errorf("the two-million-iteration credential was not skipped with its reason: %q", kres.UsersSkipped)
	}
}
