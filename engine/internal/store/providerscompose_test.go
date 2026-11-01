package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/provider"
)

// Several providers on one hook (10.06): each may refuse, a claim has one source, and
// the two hooks whose answer is a value keep one.

type composing struct {
	tx    pgx.Tx
	root  *keys.RootKey
	orgID string
	asked []string
	reply map[string]string // URL host to body; absent is unreachable.
}

func newComposing(t *testing.T) *composing {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	c := &composing{tx: tx, reply: map[string]string{}}
	if err := tx.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://compose-' || gen_random_uuid() || '.invalid', 'probe') RETURNING id
		)
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT id, 'compose-' || gen_random_uuid(), 'probe' FROM i RETURNING id::text`).Scan(&c.orgID); err != nil {
		t.Fatal(err)
	}
	if c.root, err = keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *composing) add(t *testing.T, hook provider.Hook, name string, position int, mode provider.Mode) error {
	t.Helper()
	_, _, err := SaveProvider(context.Background(), c.tx, c.root, c.orgID, provider.Provider{Name: name, Hook: hook,
		Position: position, URL: fmt.Sprintf("https://%s.example.test/hook", name), Mode: mode, Timeout: time.Second})
	return err
}

type composeTransport struct{ c *composing }

func (rt composeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	name := strings.Split(r.URL.Host, ".")[0]
	rt.c.asked = append(rt.c.asked, name)
	body, ok := rt.c.reply[name]
	if !ok {
		return nil, errors.New("unreachable")
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body))}, nil
}

func (c *composing) consult(t *testing.T, hook provider.Hook) TokenHookResult {
	t.Helper()
	c.asked = nil
	res, err := ConsultHook(context.Background(), c.tx, c.root,
		func(time.Duration) *http.Client { return &http.Client{Transport: composeTransport{c}} },
		slog.New(slog.NewTextHandler(io.Discard, nil)), c.orgID, hook, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestEveryProviderOnAHookHasToAgree(t *testing.T) {
	ctx := context.Background()
	c := newComposing(t)
	// Asked by position whatever they are called.
	if err := c.add(t, provider.HookTokenIssue, "bravo", 1, provider.FailClosed); err != nil {
		t.Fatal(err)
	}
	if err := c.add(t, provider.HookTokenIssue, "alpha", 2, provider.FailOpen); err != nil {
		t.Fatal(err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookTokenIssue, "bravo", []string{"tier"}); err != nil {
		t.Fatal(err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookTokenIssue, "alpha", []string{"region"}); err != nil {
		t.Fatal(err)
	}

	c.reply["bravo"] = `{"decision":true,"claims":{"tier":"gold","region":"not-yours"}}`
	c.reply["alpha"] = `{"decision":true,"claims":{"region":"eu"}}`
	res := c.consult(t, provider.HookTokenIssue)
	if res.Vetoed || strings.Join(c.asked, ",") != "bravo,alpha" {
		t.Fatalf("vetoed %v, asked %v", res.Vetoed, c.asked)
	}
	if res.Claims["tier"] != "gold" || res.Claims["region"] != "eu" {
		t.Errorf("what each may add was merged into %v", res.Claims)
	}

	c.reply["alpha"] = `{"decision":false,"reason":"not from there"}`
	if res := c.consult(t, provider.HookTokenIssue); !res.Vetoed || res.Reason != "not from there" {
		t.Errorf("the second refusing gave %+v", res)
	}

	c.reply["bravo"] = `{"decision":false,"reason":"not today"}`
	if res := c.consult(t, provider.HookTokenIssue); !res.Vetoed || res.Reason != "not today" ||
		strings.Join(c.asked, ",") != "bravo" {
		t.Errorf("the first refusing gave %+v, and asked %v", res, c.asked)
	}

	// Each by its own mode: alpha goes on without an answer, bravo does not.
	delete(c.reply, "alpha")
	c.reply["bravo"] = `{"decision":true}`
	if res := c.consult(t, provider.HookTokenIssue); res.Vetoed {
		t.Errorf("a fail_open provider going away refused: %+v", res)
	}
	delete(c.reply, "bravo")
	c.reply["alpha"] = `{"decision":true}`
	if res := c.consult(t, provider.HookTokenIssue); !res.Vetoed {
		t.Errorf("a fail_closed provider going away did not refuse: %+v", res)
	}
}

func TestAClaimHasOneSourceOnAHook(t *testing.T) {
	ctx := context.Background()
	c := newComposing(t)
	for _, name := range []string{"one", "two"} {
		if err := c.add(t, provider.HookUserinfo, name, 0, provider.FailOpen); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookUserinfo, "one", []string{"tier", "region"}); err != nil {
		t.Fatal(err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookUserinfo, "two", []string{"region"}); !errors.Is(err, ErrProviderClaim) {
		t.Errorf("a claim another provider may add gave %v", err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookUserinfo, "one", []string{"tier"}); err != nil {
		t.Errorf("a provider restating its own gave %v", err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookUserinfo, "two", []string{"region"}); err != nil {
		t.Errorf("a claim given up gave %v", err)
	}
	// Another hook's list is another question.
	if err := c.add(t, provider.HookTokenIssue, "three", 0, provider.FailOpen); err != nil {
		t.Fatal(err)
	}
	if err := SetProviderClaims(ctx, c.tx, c.orgID, provider.HookTokenIssue, "", []string{"region"}); err != nil {
		t.Errorf("the same claim on another hook gave %v", err)
	}
}

func TestAHookWhoseAnswerIsAValueKeepsOneProvider(t *testing.T) {
	for _, hook := range []provider.Hook{provider.HookPasswordVerify, provider.HookFlowCondition} {
		c := newComposing(t)
		if hook.Composes() {
			t.Errorf("%s says it composes", hook)
		}
		if err := c.add(t, hook, "first", 0, provider.FailClosed); err != nil {
			t.Fatal(err)
		}
		if err := c.add(t, hook, "second", 0, provider.FailClosed); !errors.Is(err, ErrProviderTaken) {
			t.Errorf("a second %s provider gave %v", hook, err)
		}
	}
	// And every other hook is one a second can join, or the schema and Composes differ.
	for _, hook := range provider.AllHooks() {
		if !hook.Composes() {
			continue
		}
		c := newComposing(t)
		for _, name := range []string{"first", "second"} {
			if err := c.add(t, hook, name, 0, provider.FailClosed); err != nil {
				t.Errorf("%s provider %s: %v", hook, name, err)
			}
		}
	}
}

func TestAChangeToAHookWithSeveralSaysWhich(t *testing.T) {
	ctx := context.Background()
	c := newComposing(t)
	for _, name := range []string{"one", "two"} {
		if err := c.add(t, provider.HookAuthorize, name, 0, provider.FailClosed); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RotateProviderSecret(ctx, c.tx, c.root, c.orgID, provider.HookAuthorize, ""); !errors.Is(err, ErrProviderAmbiguous) {
		t.Errorf("rotating with no name gave %v", err)
	}
	if _, err := DeleteProvider(ctx, c.tx, c.orgID, provider.HookAuthorize, ""); !errors.Is(err, ErrProviderAmbiguous) {
		t.Errorf("removing with no name gave %v", err)
	}
	if removed, err := DeleteProvider(ctx, c.tx, c.orgID, provider.HookAuthorize, "nobody"); removed || err != nil {
		t.Errorf("removing nobody gave %v, %v", removed, err)
	}
	if _, err := RotateProviderSecret(ctx, c.tx, c.root, c.orgID, provider.HookAuthorize, "one"); err != nil {
		t.Errorf("rotating by name gave %v", err)
	}
	if removed, err := DeleteProvider(ctx, c.tx, c.orgID, provider.HookAuthorize, "one"); !removed || err != nil {
		t.Fatalf("removing by name gave %v, %v", removed, err)
	}
	left, err := LoadProviders(ctx, c.tx, c.root, c.orgID, provider.HookAuthorize)
	if err != nil || len(left) != 1 || left[0].Name != "two" {
		t.Fatalf("left %v, %v", left, err)
	}
	// One left, so nobody has to say.
	if _, err := RotateProviderSecret(ctx, c.tx, c.root, c.orgID, provider.HookAuthorize, ""); err != nil {
		t.Errorf("rotating the only one gave %v", err)
	}
}
