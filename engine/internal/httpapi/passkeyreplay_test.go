package httpapi

import (
	"net/http"
	"testing"
)

// A sign-in ceremony and the assertion made for it are spent by the sign-in
// they produced. Presented again, together, they must not produce a second
// session. The challenge travels in a signed cookie that the handler clears,
// and clearing it only asks the browser to forget it: until migration 0141
// the same pair, replayed, signed in again. A failed attempt spends the
// ceremony too, so it cannot be ground against.
func TestAPasskeyAssertionCannotBeReplayed(t *testing.T) {
	j := newPasskeyJourney(t)
	session := &http.Cookie{Name: SessionCookieName, Value: j.signInAndReturnCookie(t)}
	cred := j.register(t, session)

	begin := j.post(t, "/login/passkey/begin", nil)
	ceremony := cookieFrom(begin, CeremonyCookieName)
	body := j.auth.get(t, begin.Body.Bytes(), cred)
	if _, _, ok := j.sessionFor(t, j.post(t, "/login/passkey/finish", body, ceremony)); !ok {
		t.Fatal("the first presentation did not sign in")
	}
	if _, _, ok := j.sessionFor(t, j.post(t, "/login/passkey/finish", body, ceremony)); ok {
		t.Error("the same ceremony and assertion, presented again, signed in a second time")
	}

	// A ceremony whose first attempt failed is spent as well: a good
	// assertion for it, sent second, does not sign in.
	begin = j.post(t, "/login/passkey/begin", nil)
	ceremony = cookieFrom(begin, CeremonyCookieName)
	bad := j.auth.get(t, begin.Body.Bytes(), cred, func(p *ceremonyParts) { p.Flags = flagUP })
	if _, _, ok := j.sessionFor(t, j.post(t, "/login/passkey/finish", bad, ceremony)); ok {
		t.Fatal("an assertion without user verification signed in")
	}
	good := j.auth.get(t, begin.Body.Bytes(), cred)
	if _, _, ok := j.sessionFor(t, j.post(t, "/login/passkey/finish", good, ceremony)); ok {
		t.Error("a ceremony that had already failed once was finished by a second attempt")
	}

	// And registration: a captured registration cannot be presented again.
	// From a second device, since the first is excluded as already registered.
	phone := &virtualAuthenticator{origin: j.auth.origin}
	rbegin := j.post(t, "/account/passkeys/begin", nil, session)
	rceremony := cookieFrom(rbegin, CeremonyCookieName)
	rbody, _ := phone.create(t, rbegin.Body.Bytes())
	if rec := j.post(t, "/account/passkeys/finish", rbody, session, rceremony); rec.Code != http.StatusOK {
		t.Fatalf("registration answered %d: %s", rec.Code, rec.Body)
	}
	if rec := j.post(t, "/account/passkeys/finish", rbody, session, rceremony); rec.Code != http.StatusBadRequest {
		t.Errorf("a replayed registration answered %d, want 400 for a spent ceremony: %s", rec.Code, rec.Body)
	}
}
