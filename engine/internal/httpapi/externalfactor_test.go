package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/extfactor"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/prompts"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

const factorIssuer = "https://factor.example"

// factorFixture is a sign-in whose flow asks a service the test plays.
type factorFixture struct {
	*signInFixture
	key *ecdsa.PrivateKey
}

const factorFlow = `version: 1
flows:
  - name: with-a-service
    on: authentication
    stages:
      - password
      - {stage: external_factor, factor: push}
      - session
    tests:
      - name: asked
        given: {}
        expect: [password, external_factor, session]
`

func newFactorFixture(t *testing.T, doc string) *factorFixture {
	t.Helper()
	f := &factorFixture{signInFixture: newSignInFixture(t)}
	var err error
	if f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: f.key.Public(), KeyID: "k", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.SetExternalFactor(ctx, f.pool, f.orgID, store.ExternalFactor{
		Name: "push", URL: "https://factor.example/ask?tenant=a", Issuer: factorIssuer, JWKS: jwks,
		AMR: []string{"otp", "mfa"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.external_factors WHERE org_id = $1::uuid`, f.orgID)
	})
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET first_party = true WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	f.applyFlow(t, doc)
	return f
}

// asked signs in and reads the challenge the browser was sent away with.
func (f *factorFixture) asked(t *testing.T) (extfactor.Challenge, *http.Cookie) {
	t.Helper()
	rec := f.signInFrom(t, testClientIP(t))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusSeeOther || loc.Host != "factor.example" {
		t.Fatalf("the sign-in did not go to the service (%d): %q", rec.Code, rec.Header().Get("Location"))
	}
	if cookieFrom(rec, SessionCookieName) != nil {
		t.Fatal("a session was issued before the service answered")
	}
	if loc.Query().Get("tenant") != "a" {
		t.Errorf("the registered url's own query was lost: %s", loc)
	}
	raw, err := tokens.VerifyTyped(f.srv.cfg.Keys, f.srv.cfg.Issuer, loc.Query().Get("challenge"), extfactor.TypChallenge)
	if err != nil {
		t.Fatalf("the challenge does not verify against this issuer's keys: %v", err)
	}
	var c extfactor.Challenge
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	pending := cookieFrom(rec, PendingCookieName)
	if pending == nil {
		t.Fatal("the browser was sent away with nothing to come back to")
	}
	return c, pending
}

func (f *factorFixture) answer(t *testing.T, c extfactor.Challenge, change func(map[string]any)) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": factorIssuer, "aud": c.Issuer, "sub": c.Subject, "nonce": c.Nonce,
		"amr": []string{"otp"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	if change != nil {
		change(claims)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType(extfactor.TypResponse))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *factorFixture) back(t *testing.T, query url.Values, pending *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, factorCallbackPath+"?"+query.Encode(), nil)
	if pending != nil {
		r.AddCookie(pending)
	}
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (f *factorFixture) idTokenAMR(t *testing.T, session string) []string {
	t.Helper()
	body := f.redeemPlain(t, f.authorizeWith(t, session, nil))
	raw, _ := claimsOfJWT(t, body["id_token"].(string))["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestASignInPassesAServiceOnTheStrengthOfWhatItSigned(t *testing.T) {
	f := newFactorFixture(t, factorFlow)
	c, pending := f.asked(t)
	if c.Subject != f.userID || c.Audience != factorIssuer || c.Nonce == "" ||
		c.ReturnTo != "https://signin-test.example"+factorCallbackPath || c.LoginHint != f.email {
		t.Fatalf("the challenge says %+v", c)
	}
	rec := f.back(t, url.Values{"response": {f.answer(t, c, nil)}}, pending)
	session := cookieFrom(rec, SessionCookieName)
	if session == nil {
		t.Fatalf("no session after a good answer (%d): %.300s", rec.Code, rec.Body.String())
	}

	amr := f.idTokenAMR(t, session.Value)
	if !slices.Contains(amr, oauth.AMRPassword) || !slices.Contains(amr, oauth.AMROTP) {
		t.Errorf("the ID token says amr %v", amr)
	}
	for _, v := range amr {
		if strings.Contains(v, "push") || strings.Contains(v, ":") {
			t.Errorf("the walk's bookkeeping reached a relying party: %v", amr)
		}
	}
	// What the service proved counts as what it is: a second factor.
	var acr string
	if err := f.pool.QueryRow(context.Background(), `SELECT acr FROM core.sessions WHERE user_id = $1::uuid`,
		f.userID).Scan(&acr); err != nil {
		t.Fatal(err)
	}
	if acr != oauth.ACRFromAMR(amr) || !oauth.IsMultiFactor(amr) {
		t.Errorf("acr %q for amr %v", acr, amr)
	}
}

func TestAnAnswerIsSpentOnce(t *testing.T) {
	f := newFactorFixture(t, factorFlow)
	c, pending := f.asked(t)
	response := f.answer(t, c, nil)
	if rec := f.back(t, url.Values{"response": {response}}, pending); cookieFrom(rec, SessionCookieName) == nil {
		t.Fatalf("the first answer was refused (%d)", rec.Code)
	}
	// The browser that started it, and a pending token still good.
	if rec := f.back(t, url.Values{"response": {response}}, pending); cookieFrom(rec, SessionCookieName) != nil {
		t.Error("the same answer signed in twice")
	}
}

// The transaction that follows the answer is abandoned when a later stage takes
// over, so a nonce spent in it would come back to life.
func TestAStageAfterTheServiceNeitherAsksAgainNorRevivesTheAnswer(t *testing.T) {
	f := newFactorFixture(t, `version: 1
flows:
  - name: then-a-notice
    on: authentication
    stages:
      - password
      - {stage: external_factor, factor: push}
      - {stage: prompt, when: prompts_pending}
      - session
    tests:
      - name: asked
        given: {prompts_pending: true}
        expect: [password, external_factor, prompt, session]
`)
	f.saveTerms(t)

	c, pending := f.asked(t)
	response := f.answer(t, c, nil)
	page := f.back(t, url.Values{"response": {response}}, pending)
	if cookieFrom(page, SessionCookieName) != nil || !strings.Contains(page.Body.String(), "Terms") {
		t.Fatalf("the prompt did not follow the service (%d): %.300s", page.Code, page.Body.String())
	}
	carried := cookieFrom(page, PendingCookieName)
	if carried == nil {
		t.Fatal("the prompt carries nothing forward")
	}
	if rec := f.back(t, url.Values{"response": {response}}, pending); cookieFrom(rec, PendingCookieName) != nil {
		t.Error("the answer worked again once the next stage had abandoned its transaction")
	}

	// Answering the prompt walks again from the start, past the service.
	m := csrfValue.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no CSRF token on the prompt: %.300s", page.Body.String())
	}
	rec := f.answerTerms(t, m[1], cookieFrom(page, CSRFCookieName), carried)
	if strings.Contains(rec.Header().Get("Location"), "factor.example") {
		t.Fatal("the service was asked a second time")
	}
	session := cookieFrom(rec, SessionCookieName)
	if session == nil {
		t.Fatalf("no session after the prompt (%d) %q: %.300s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if amr := f.idTokenAMR(t, session.Value); !slices.Contains(amr, oauth.AMROTP) {
		t.Errorf("what the service proved was lost across the prompt: %v", amr)
	}
}

func TestAnAnswerIsRefusedAtTheDoor(t *testing.T) {
	f := newFactorFixture(t, factorFlow)
	var somebodyElse string
	if err := f.pool.QueryRow(context.Background(), `SELECT gen_random_uuid()::text`).Scan(&somebodyElse); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		query  func(c extfactor.Challenge) url.Values
		sent   bool // the browser kept its pending cookie
		reason string
	}{
		{name: "no answer", query: func(extfactor.Challenge) url.Values {
			return url.Values{"error": {"denied"}}
		}, sent: true},
		{name: "two answers", query: func(c extfactor.Challenge) url.Values {
			return url.Values{"response": {f.answer(t, c, nil), f.answer(t, c, nil)}}
		}, sent: true},
		{name: "an undeclared amr", query: func(c extfactor.Challenge) url.Values {
			return url.Values{"response": {f.answer(t, c, func(m map[string]any) { m["amr"] = []string{"hwk"} })}}
		}, sent: true},
		{name: "about somebody else", query: func(c extfactor.Challenge) url.Values {
			return url.Values{"response": {f.answer(t, c, func(m map[string]any) { m["sub"] = somebodyElse })}}
		}, sent: true},
		{name: "a nonce nobody issued", query: func(c extfactor.Challenge) url.Values {
			return url.Values{"response": {f.answer(t, c, func(m map[string]any) { m["nonce"] = "invented" })}}
		}, sent: true},
		{name: "another browser", query: func(c extfactor.Challenge) url.Values {
			return url.Values{"response": {f.answer(t, c, nil)}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearSignInBucket(t, f.pool)
			c, pending := f.asked(t)
			if !tc.sent {
				pending = nil
			}
			rec := f.back(t, tc.query(c), pending)
			if cookieFrom(rec, SessionCookieName) != nil {
				t.Fatal("signed in")
			}
			if tc.sent {
				cleared := false
				for _, ck := range rec.Result().Cookies() {
					cleared = cleared || (ck.Name == PendingCookieName && ck.MaxAge < 0)
				}
				if !cleared {
					t.Error("a refused answer left the pending sign-in in the browser")
				}
			}
		})
	}
}

func (f *factorFixture) saveTerms(t *testing.T) {
	t.Helper()
	if _, _, err := store.SavePrompt(context.Background(), f.pool, f.orgID, store.PromptDefinition{
		Slug: "terms", Title: "Terms", Body: "Read this.",
		Fields: []prompts.Field{{Name: "note", Label: "Note", Type: prompts.Text}}}); err != nil {
		t.Fatal(err)
	}
}

func (f *factorFixture) answerTerms(t *testing.T, csrf string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{csrfFormField: {csrf}, "prompt": {"terms"}, "version": {"1"}}
	r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.srv.handlePromptPost(rec, r)
	return rec
}

// A page that continues a sign-in walks it again from the top, so a person
// holding a pending token at this stage cannot go round the service through one.
func TestThePendingTokenAtAServiceOpensNoOtherStage(t *testing.T) {
	f := newFactorFixture(t, factorFlow)
	f.saveTerms(t)
	_, pending := f.asked(t)
	csrf := strings.Repeat("a", 43)
	round := f.answerTerms(t, csrf, pending, &http.Cookie{Name: CSRFCookieName, Value: csrf})
	if cookieFrom(round, SessionCookieName) != nil {
		t.Error("a prompt's page went round the service")
	}
	if !strings.Contains(round.Header().Get("Location"), "factor.example") {
		t.Errorf("the walk did not come back to the service: %d %q", round.Code, round.Header().Get("Location"))
	}

	// And a pending token no stage limits does not reach the callback, with an
	// answer good in every other way: only the stage stands in its way.
	c, _ := f.asked(t)
	rec := httptest.NewRecorder()
	if err := f.srv.setPendingCookie(rec, f.userID, f.orgID, []string{oauth.AMRPassword}, ""); err != nil {
		t.Fatal(err)
	}
	back := f.back(t, url.Values{"response": {f.answer(t, c, nil)}}, cookieFrom(rec, PendingCookieName))
	if cookieFrom(back, SessionCookieName) != nil {
		t.Error("a pending token from another stage came through the callback")
	}
}

func TestAFactorGoneSinceTheFlowWasAppliedRefusesRatherThanPasses(t *testing.T) {
	f := newFactorFixture(t, factorFlow)
	// By hand, as a stored document can be: the writer refuses this.
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM core.external_factors WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	rec := f.signInFrom(t, testClientIP(t))
	if cookieFrom(rec, SessionCookieName) != nil {
		t.Fatalf("signed in past a service that is not there (%d)", rec.Code)
	}
	if strings.Contains(rec.Header().Get("Location"), "factor.example") {
		t.Errorf("sent to %q", rec.Header().Get("Location"))
	}
}

// A flow can skip the stage, and the branch of a one_of it took decides which
// service is asked.
func TestAOneOfAsksTheServiceItChose(t *testing.T) {
	f := newFactorFixture(t, `version: 1
flows:
  - name: by-route
    on: authentication
    stages:
      - password
      - one_of:
          - {stage: external_factor, factor: push, when: user_has_second_factor}
          - {stage: external_factor, factor: other}
      - session
    tests:
      - name: other
        given: {}
        expect: [password, external_factor, session]
`)
	ctx := context.Background()
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: f.key.Public(), KeyID: "k", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetExternalFactor(ctx, f.pool, f.orgID, store.ExternalFactor{
		Name: "other", URL: "https://other.example/ask", Issuer: "https://other.example", JWKS: jwks,
		AMR: []string{"otp"}}); err != nil {
		t.Fatal(err)
	}
	rec := f.signInFrom(t, testClientIP(t))
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://other.example/ask?") {
		t.Fatalf("the branch taken names other, and the browser went to %q", rec.Header().Get("Location"))
	}
}

// A notice asked on every sign-in, which docs/prompts.md says `once: false` is.
// The walk starts again after an answer and the prompt is outstanding again,
// answered or not, so nobody could get past one.
func TestANoticeAskedEverySignInLetsThePersonThrough(t *testing.T) {
	f := newSignInFixture(t)
	if _, _, err := store.SavePrompt(context.Background(), f.pool, f.orgID, store.PromptDefinition{
		Slug: "notice", Title: "Notice", Once: false,
		Fields: []prompts.Field{{Name: "note", Label: "Note", Type: prompts.Text}}}); err != nil {
		t.Fatal(err)
	}
	for sign := range 2 {
		clearSignInBucket(t, f.pool)
		page := f.signInFrom(t, testClientIP(t))
		m := csrfValue.FindStringSubmatch(page.Body.String())
		if m == nil || !strings.Contains(page.Body.String(), "Notice") {
			t.Fatalf("sign-in %d was not asked (%d): %.300s", sign, page.Code, page.Body.String())
		}
		form := url.Values{csrfFormField: {m[1]}, "prompt": {"notice"}, "version": {"1"}}
		r := httptest.NewRequest(http.MethodPost, "/login/prompt", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookieFrom(page, PendingCookieName))
		r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: m[1]})
		rec := httptest.NewRecorder()
		f.srv.handlePromptPost(rec, r)
		if cookieFrom(rec, SessionCookieName) == nil {
			t.Fatalf("sign-in %d was asked again after answering (%d): %.300s", sign, rec.Code, rec.Body.String())
		}
		if strings.Contains(strings.Join(sessionAMR(t, f, rec), " "), "walk:") {
			t.Error("the walk's mark reached the session")
		}
	}
}

func TestAnEmailedCodeIsReadFromTheFrontOfAMR(t *testing.T) {
	for _, tc := range []struct {
		amr  []string
		want flow.StageName
	}{
		{[]string{oauth.AMROTP}, flow.StageEmailOTP},
		{[]string{oauth.AMROTP, oauth.AMRHardwareKey}, flow.StageEmailOTP},
		{[]string{oauth.AMRPassword, oauth.AMROTP}, flow.StagePassword},
		{[]string{oauth.AMRUserPresence, oauth.AMRHardwareKey, oauth.AMROTP}, flow.StagePasskey},
		{[]string{"fed", oauth.AMROTP}, flow.StageFederated},
	} {
		if got := primaryProof(tc.amr); got != tc.want {
			t.Errorf("primaryProof(%v) = %q, want %q", tc.amr, got, tc.want)
		}
	}
}
