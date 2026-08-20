package txntoken

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The rules that make a transaction-token chain worth anything.
//
// Each of these is the difference between a chain an investigation can follow
// and a set of unrelated tokens that happen to be nearby.

func base(now time.Time) Claims {
	return Claims{
		Issuer:             "https://id.example",
		IssuedAt:           now.Unix(),
		Expiry:             now.Add(5 * time.Minute).Unix(),
		Audience:           "trust-domain.example",
		Transaction:        "97053963-771d-49cc-a4e3-20aad399c312",
		Subject:            "user-42",
		RequestingWorkload: "gateway.trust-domain.example",
		Scope:              "trade.stocks read.positions",
		TransactionContext: map[string]any{"action": "BUY", "ticker": "MSFT"},
		RequestContext:     map[string]any{"req_ip": "203.0.113.9"},
	}
}

// txn, sub and aud survive every hop. A hop that could change any of them
// severs the trail at exactly the point somebody would follow it.
func TestTheImmutableFieldsSurviveAReplacement(t *testing.T) {
	now := time.Now()
	prev := base(now)

	next, err := Replace(Replacement{
		Previous: prev,
		Workload: "orders.trust-domain.example",
		Scope:    []string{"trade.stocks"},
		// A hop supplying a completely different environment.
		RequestContext: map[string]any{"req_ip": "10.0.0.1"},
	}, "https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatalf("replacing: %v", err)
	}

	if next.Transaction != prev.Transaction {
		t.Fatalf("txn changed: %q -> %q", prev.Transaction, next.Transaction)
	}
	if next.Subject != prev.Subject {
		t.Fatalf("sub changed: %q -> %q", prev.Subject, next.Subject)
	}
	if next.Audience != prev.Audience {
		t.Fatalf("aud changed: %q -> %q", prev.Audience, next.Audience)
	}

	// The one field that SHOULD change.
	if next.RequestingWorkload != "orders.trust-domain.example" {
		t.Fatalf("req_wl = %q, want the replacing workload", next.RequestingWorkload)
	}

	// What is being done does not change because the request moved one service
	// to the right.
	if next.TransactionContext["ticker"] != "MSFT" {
		t.Fatalf("tctx was lost or altered: %v", next.TransactionContext)
	}
	// The environment legitimately does.
	if next.RequestContext["req_ip"] != "10.0.0.1" {
		t.Fatalf("rctx did not update: %v", next.RequestContext)
	}
}

// A service asking for more authority than it was given is the attack this
// format exists to stop.
func TestScopeMayNarrowButNeverWiden(t *testing.T) {
	now := time.Now()
	prev := base(now)

	// Narrowing is fine.
	next, err := Replace(Replacement{
		Previous: prev, Workload: "orders", Scope: []string{"trade.stocks"},
	}, "https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatalf("narrowing was refused: %v", err)
	}
	if next.Scope != "trade.stocks" {
		t.Fatalf("scope = %q, want the narrowed set", next.Scope)
	}

	// Widening is not.
	_, err = Replace(Replacement{
		Previous: prev, Workload: "orders",
		Scope: []string{"trade.stocks", "admin.everything"},
	}, "https://id.example", now, DefaultTTL)
	if err == nil {
		t.Fatal("a replacement widened its own scope")
	}
	if !errors.Is(err, ErrWiden) {
		t.Fatalf("err = %v, want ErrWiden", err)
	}
	if !strings.Contains(err.Error(), "admin.everything") {
		t.Fatalf("err = %q, want it to name the scope that was not held", err)
	}

	// Asking for nothing carries what you have, rather than silently dropping
	// the authority the next hop needs.
	next, err = Replace(Replacement{Previous: prev, Workload: "orders"},
		"https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatalf("an empty scope was refused: %v", err)
	}
	if next.Scope != prev.Scope {
		t.Fatalf("scope = %q, want it carried through as %q", next.Scope, prev.Scope)
	}
}

// A chain must not extend its own life one hop at a time.
func TestAReplacementCannotOutliveWhatItReplaced(t *testing.T) {
	now := time.Now()
	prev := base(now)
	// The previous token has one minute left; the default TTL is five.
	prev.Expiry = now.Add(time.Minute).Unix()

	next, err := Replace(Replacement{Previous: prev, Workload: "orders"},
		"https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatalf("replacing: %v", err)
	}
	if next.Expiry != prev.Expiry {
		t.Fatalf("exp = %d, want it capped at the previous token's %d -- otherwise "+
			"a five-minute token becomes permanent across enough services",
			next.Expiry, prev.Expiry)
	}

	// An already-expired token cannot be replaced at all.
	prev.Expiry = now.Add(-time.Second).Unix()
	if _, err := Replace(Replacement{Previous: prev, Workload: "orders"},
		"https://id.example", now, DefaultTTL); err == nil {
		t.Fatal("an expired token was replaced")
	}
}

// A TTL beyond the ceiling is clamped rather than honoured.
func TestTheLifetimeCeilingHolds(t *testing.T) {
	now := time.Now()
	prev := base(now)
	prev.Expiry = now.Add(time.Hour).Unix() // room to overrun

	next, err := Replace(Replacement{Previous: prev, Workload: "orders"},
		"https://id.example", now, 24*time.Hour)
	if err != nil {
		t.Fatalf("replacing: %v", err)
	}
	if got := time.Unix(next.Expiry, 0).Sub(now); got > MaxTTL {
		t.Fatalf("lifetime %v exceeds the ceiling of %v", got, MaxTTL)
	}
}

// A token with no transaction id is not a transaction token.
func TestAReplacementRefusesAMalformedPredecessor(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name   string
		mutate func(*Claims)
	}{
		{"no txn", func(c *Claims) { c.Transaction = "" }},
		{"no sub", func(c *Claims) { c.Subject = "" }},
	} {
		prev := base(now)
		c.mutate(&prev)
		if _, err := Replace(Replacement{Previous: prev, Workload: "orders"},
			"https://id.example", now, DefaultTTL); err == nil {
			t.Errorf("%s: replaced anyway", c.name)
		}
	}
}

func TestTheWireConstantsMatchTheDraft(t *testing.T) {
	// These are checked because a near-miss is a token every conforming
	// consumer rejects for reasons nobody can see from the outside.
	if TokenType != "urn:ietf:params:oauth:token-type:txn_token" {
		t.Errorf("token type URN is %q", TokenType)
	}
	if Typ != "txntoken+jwt" {
		t.Errorf("typ is %q, want txntoken+jwt", Typ)
	}
	if Header != "Txn-Token" {
		t.Errorf("header is %q; the draft is explicit that it is not Authorization", Header)
	}
	if GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant type is %q", GrantType)
	}
	r := NewResponse("x")
	if r.TokenType != "N_A" {
		t.Errorf("token_type is %q, want the draft's literal N_A", r.TokenType)
	}
	if r.IssuedTokenType != TokenType {
		t.Errorf("issued_token_type is %q", r.IssuedTokenType)
	}
}

func TestValidateNamesWhatIsMissing(t *testing.T) {
	err := Request{}.Validate()
	if err == nil {
		t.Fatal("an empty request validated")
	}
	for _, want := range []string{"audience", "scope", "subject_token", "subject_token_type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to name %q", err, want)
		}
	}
}

// §13.15: "MUST maintain the Call Chain of workloads that requested the
// Txn-Token being replaced in the subsequently issued Txn-Token."
//
// The first implementation failed this. `req_wl` is singular and was
// overwritten at each hop, so the chain was destroyed at the first replacement
// -- losing exactly the audit property the format exists to provide. Found by
// reading draft-11 rather than a summary of it.
func TestTheCallChainSurvivesEveryHop(t *testing.T) {
	now := time.Now()
	cur := base(now)
	// Deliberately nil: a token minted before this claim existed. The chain
	// must still pick the workload up from req_wl rather than losing it.
	cur.CallChain = nil

	for _, hop := range []string{"orders", "ledger", "notifications"} {
		next, err := Replace(Replacement{Previous: cur, Workload: hop},
			"https://id.example", now, DefaultTTL)
		if err != nil {
			t.Fatalf("replacing at %s: %v", hop, err)
		}
		cur = next
	}

	want := []string{"gateway.trust-domain.example", "orders", "ledger", "notifications"}
	if len(cur.CallChain) != len(want) {
		t.Fatalf("chain = %v, want %v -- §13.15 requires the chain of workloads "+
			"that requested the replaced token to be maintained", cur.CallChain, want)
	}
	for i := range want {
		if cur.CallChain[i] != want[i] {
			t.Fatalf("chain = %v, want %v", cur.CallChain, want)
		}
	}
	// req_wl still names the CURRENT workload, per §9.2.
	if cur.RequestingWorkload != "notifications" {
		t.Fatalf("req_wl = %q, want the current workload", cur.RequestingWorkload)
	}
}

// A caller must not be able to write its own history.
func TestTheCallChainComesFromThePreviousTokenNotTheCaller(t *testing.T) {
	now := time.Now()
	prev := base(now)
	// With SPARE CAPACITY on purpose. A literal slice has cap == len, so append
	// always reallocates and an aliasing bug hides. This is the shape a chain
	// actually has after appendChain has grown it, and it is the only shape
	// where sharing the backing array is observable.
	prev.CallChain = make([]string, 0, 8)
	prev.CallChain = append(prev.CallChain, "gateway", "orders")

	next, err := Replace(Replacement{Previous: prev, Workload: "ledger"},
		"https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.CallChain) != 3 || next.CallChain[2] != "ledger" {
		t.Fatalf("chain = %v", next.CallChain)
	}
	// Mutating the result must not reach back into the previous token: append
	// can share a backing array, and two replacements from one token would
	// then scribble over each other.
	next.CallChain[0] = "tampered"
	if prev.CallChain[0] != "gateway" {
		t.Fatal("the replacement shares its backing array with the previous " +
			"token's chain; two replacements from one token would corrupt each other")
	}
	// And the same token replaced twice must produce two independent chains.
	// This is the failure the aliasing causes in practice: one transaction
	// fanning out to two workloads, each overwriting the other's history.
	a, err := Replace(Replacement{Previous: prev, Workload: "left"},
		"https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Replace(Replacement{Previous: prev, Workload: "right"},
		"https://id.example", now, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if a.CallChain[len(a.CallChain)-1] != "left" {
		t.Fatalf("the first branch's chain ends with %q, want left -- the second "+
			"replacement overwrote it", a.CallChain[len(a.CallChain)-1])
	}
	if b.CallChain[len(b.CallChain)-1] != "right" {
		t.Fatalf("the second branch's chain ends with %q, want right",
			b.CallChain[len(b.CallChain)-1])
	}
}

// §13.15 also says a TTS SHOULD limit how many times a token is replaced.
func TestTheCallChainIsBounded(t *testing.T) {
	now := time.Now()
	cur := base(now)
	for i := 0; i < MaxCallChain+10; i++ {
		next, err := Replace(Replacement{Previous: cur, Workload: "w"},
			"https://id.example", now, DefaultTTL)
		if err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
		cur = next
	}
	if len(cur.CallChain) > MaxCallChain {
		t.Fatalf("chain grew to %d, above the bound of %d -- an unbounded chain "+
			"is both a growing token and a sign something is looping",
			len(cur.CallChain), MaxCallChain)
	}
}

// §11.2: the type MAY be any RFC 8693 type EXCEPT refresh_token.
//
// The first implementation defaulted: any unrecognised type fell through to the
// access-token path and was refused only because it failed to parse. An
// exclusion that holds by accident stops holding when the accident changes.
func TestSubjectTokenTypesAreEnumerated(t *testing.T) {
	for _, ok := range []string{
		SubjectAccessToken, SubjectIDToken, SubjectJWT, SubjectTxnToken,
	} {
		if err := CheckSubjectTokenType(ok); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
	for _, c := range []struct{ typ, want string }{
		{SubjectRefreshToken, "excludes refresh tokens"},
		{SubjectSelfSigned, "not\nimplemented"},
		{SubjectUnsignedJSON, "not\nimplemented"},
		{"", "required"},
		{"urn:example:something-invented", "not a type"},
	} {
		err := CheckSubjectTokenType(c.typ)
		if err == nil {
			t.Errorf("%q was accepted", c.typ)
			continue
		}
		if !errors.Is(err, ErrSubjectTokenType) {
			t.Errorf("%q: err = %v, want ErrSubjectTokenType", c.typ, err)
		}
	}
	// The refusal must NAME refresh tokens, because that exclusion is the one
	// with a security reason behind it (§13.3) rather than a missing feature.
	if err := CheckSubjectTokenType(SubjectRefreshToken); err == nil ||
		!strings.Contains(err.Error(), "refresh") {
		t.Fatalf("refresh_token refusal = %v, want it to name refresh tokens", err)
	}
}

// Section 13.4, a MUST NOT written on the TTS:
//
//	"When creating Txn-Tokens, the Txn-Token MUST NOT contain the access token
//	presented to the external endpoint. If an access token is included in a
//	Txn-Token, an attacker may extract the access token from the Txn-Token, and
//	replay it to any Resource Server that can accept that access token."
//
// tctx and rctx are caller-supplied maps that were copied verbatim into the
// signed token. A workload putting its incoming Authorization header into rctx
// is a plausible mistake, and the result is a long-lived bearer credential
// embedded in a short-lived token forwarded to every service in the chain.
func TestTheContextClaimsCannotCarryTheSubjectToken(t *testing.T) {
	const subject = "eyJhbGciOiJFUzI1NiJ9.subject-token-value.sig"

	t.Run("bare", func(t *testing.T) {
		err := CheckContext(subject, map[string]any{"token": subject})
		if err == nil {
			t.Fatal("the subject token was accepted inside rctx; section 13.4 " +
				"forbids the Txn-Token from carrying it")
		}
	})

	t.Run("framed as a header value", func(t *testing.T) {
		// The realistic shape: a workload copying its Authorization header in
		// for tracing. Equality would miss this, which is why the check is a
		// substring one.
		err := CheckContext(subject, map[string]any{
			"headers": map[string]any{"authorization": "Bearer " + subject},
		})
		if err == nil {
			t.Fatal("the subject token was accepted when embedded in a larger " +
				"string; section 13.4 is about the value being extractable, not " +
				"about how it was framed")
		}
	})

	t.Run("nested deep in tctx", func(t *testing.T) {
		err := CheckContext(subject, nil, map[string]any{
			"req": map[string]any{"upstream": map[string]any{"creds": []any{subject}}},
		})
		if err == nil {
			t.Fatal("a nested subject token was accepted")
		}
	})

	t.Run("ordinary context still works", func(t *testing.T) {
		err := CheckContext(subject, map[string]any{
			"ip": "198.51.100.7", "user_agent": "curl/8", "req_id": "abc123",
		}, map[string]any{"action": "transfer", "amount": 100})
		if err != nil {
			t.Fatalf("ordinary context was refused: %v", err)
		}
	})

	t.Run("no subject token to compare against", func(t *testing.T) {
		// A first-hop mint with no presented token must not refuse everything.
		if err := CheckContext("", map[string]any{"ip": "198.51.100.7"}); err != nil {
			t.Fatalf("context was refused when there was no subject token: %v", err)
		}
	})
}

// The context claims are caller-supplied and end up in a token carried on every
// hop of the transaction, so their size is paid for repeatedly.
func TestTheContextClaimsAreBounded(t *testing.T) {
	big := make([]byte, MaxContextBytes)
	for i := range big {
		big[i] = 'a'
	}
	err := CheckContext("", map[string]any{"blob": string(big)})
	if err == nil {
		t.Fatalf("a context of over %d bytes was accepted", MaxContextBytes)
	}

	// The limit is across BOTH maps, not per map -- otherwise it is trivially
	// doubled by splitting the payload.
	half := string(big[:MaxContextBytes*2/3])
	if err := CheckContext("", map[string]any{"a": half}, map[string]any{"b": half}); err == nil {
		t.Fatal("two contexts each under the limit summed past it and were accepted")
	}
}

// TestReplacingATokenWithNoExpiryIsRefused.
//
// §9.2 makes `exp` REQUIRED. The clamp below it — a replacement may not outlive
// the token it came from — was written as
//
//	if r.Previous.Expiry > 0 && exp > r.Previous.Expiry
//
// so a previous token carrying no expiry skipped the clamp entirely and produced
// a successor with a fresh full lifetime. Repeat per hop and a chain never ends,
// which is what §13.15 forbids: "MUST NOT issue a new Txn-Token when the
// Txn-Token being replaced has expired."
//
// This test exists because removing the guard broke nothing. Replace is
// exported, and the reason given for keeping the check is that a future caller
// might not verify first — a reason that only holds if the check is known to
// work.
func TestReplacingATokenWithNoExpiryIsRefused(t *testing.T) {
	now := time.Now()

	_, err := Replace(Replacement{
		Previous: Claims{
			Audience:    "https://trust-domain.example",
			Transaction: "txn-1",
			Subject:     "user-1",
			Scope:       "transfer",
			// No Expiry.
		},
		Workload: "next-hop",
	}, "https://issuer.example", now, DefaultTTL)

	if err == nil {
		t.Fatal("a replacement was issued from a token with no expiry; the successor " +
			"carries a fresh lifetime, so the chain never ends")
	}
	if !strings.Contains(err.Error(), "expiry") {
		t.Errorf("refused, but not as a missing expiry: %v", err)
	}
}

// TestAReplacementNeverOutlivesWhatItCameFrom is the clamp itself, which the
// test above only reaches the edge of.
func TestAReplacementNeverOutlivesWhatItCameFrom(t *testing.T) {
	now := time.Now()
	// Previous expires in 30 seconds; the default TTL is minutes.
	prevExp := now.Add(30 * time.Second).Unix()

	got, err := Replace(Replacement{
		Previous: Claims{
			Audience: "https://trust-domain.example", Transaction: "txn-1",
			Subject: "user-1", Scope: "transfer", Expiry: prevExp,
		},
		Workload: "next-hop",
	}, "https://issuer.example", now, DefaultTTL)
	if err != nil {
		t.Fatalf("a valid replacement was refused: %v", err)
	}
	if got.Expiry != prevExp {
		t.Errorf("replacement expires at %d, previous at %d; a chain that can extend "+
			"its own life one hop at a time makes a five-minute token permanent",
			got.Expiry, prevExp)
	}
}
