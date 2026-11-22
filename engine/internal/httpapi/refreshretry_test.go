package httpapi

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"signari.dev/engine/internal/store"
)

// A retry of a refresh whose answer was lost (9.17). The phone that loses signal between
// the server answering and the application hearing it presents the same token again, and
// reuse ending the whole lineage signs that person out. A client that opts in gets one
// retry, in a short window, of the same answer; everything that makes reuse a theft
// signal holds outside that.

func (f *tokenFixture) writeRefreshGrace(grace time.Duration) error {
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{RefreshReuseGrace: &grace}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (f *tokenFixture) setRefreshGrace(t *testing.T, grace time.Duration) {
	t.Helper()
	if err := f.writeRefreshGrace(grace); err != nil {
		t.Fatal(err)
	}
}

func refreshed(t *testing.T, status int, body map[string]any) string {
	t.Helper()
	token, _ := body["refresh_token"].(string)
	if status != http.StatusOK || token == "" {
		t.Fatalf("the refresh answered %d: %v", status, body)
	}
	return token
}

func TestARefreshIsRetriedOnceWithTheSameAnswer(t *testing.T) {
	f := newTokenFixture(t)
	f.setRefreshGrace(t, 10*time.Second)
	first := f.firstRefreshToken(t)

	status, body := f.refreshWith(t, first, "")
	second := refreshed(t, status, body)
	access, _ := body["access_token"].(string)

	// The token at rest opens for nobody who does not hold the one it replaced.
	var sealed []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT successor_sealed FROM core.refresh_tokens
		WHERE token_hash = $1`, store.HashToken(first)).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || strings.Contains(string(sealed), second) {
		t.Fatalf("the successor is held as %q", sealed)
	}
	if _, err := store.OpenSuccessor("not-the-token", sealed); err == nil {
		t.Error("the successor opened for another token")
	}

	status, body = f.refreshWith(t, first, "")
	if again := refreshed(t, status, body); again != second {
		t.Errorf("the retry answered another token: a lineage must stay one line")
	}
	if retried, _ := body["access_token"].(string); retried == "" || retried == access {
		t.Errorf("the retry's access token is %q", retried)
	}
	var live int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.refresh_tokens rt
		JOIN core.refresh_token_families fam ON fam.id = rt.family_id
		WHERE rt.consumed_at IS NULL AND fam.client_id = $1`, f.clientID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("%d live tokens after a retry, want the one", live)
	}
	var kept []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT successor_sealed FROM core.refresh_tokens
		WHERE token_hash = $1`, store.HashToken(first)).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != nil {
		t.Error("a spent retry left the successor sealed in the row")
	}

	// One retry. The next is reuse, and it ends the lineage, the retried token with it.
	if status, _ := f.refreshWith(t, first, ""); status != http.StatusBadRequest {
		t.Errorf("a second retry answered %d", status)
	}
	if status, _ := f.refreshWith(t, second, ""); status != http.StatusBadRequest {
		t.Errorf("the lineage outlived a second retry: %d", status)
	}
}

// The token that came back has been used, so the answer was not lost, and whoever
// presents the old one now is not the application that lost it.
func TestARetryAfterTheSuccessorWasUsedIsTheft(t *testing.T) {
	f := newTokenFixture(t)
	f.setRefreshGrace(t, 10*time.Second)
	first := f.firstRefreshToken(t)
	status, body := f.refreshWith(t, first, "")
	second := refreshed(t, status, body)
	status, body = f.refreshWith(t, second, "")
	third := refreshed(t, status, body)

	if status, _ := f.refreshWith(t, first, ""); status != http.StatusBadRequest {
		t.Fatalf("the old token, its successor spent, answered %d", status)
	}
	if status, _ := f.refreshWith(t, third, ""); status != http.StatusBadRequest {
		t.Errorf("the lineage outlived it: %d", status)
	}
}

func TestARetryPastTheGraceIsTheft(t *testing.T) {
	f := newTokenFixture(t)
	f.setRefreshGrace(t, 10*time.Second)
	first := f.firstRefreshToken(t)
	status, body := f.refreshWith(t, first, "")
	second := refreshed(t, status, body)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.refresh_tokens
		SET consumed_at = now() - interval '11 seconds' WHERE token_hash = $1`, store.HashToken(first)); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.refreshWith(t, first, ""); status != http.StatusBadRequest {
		t.Fatalf("a retry past its grace answered %d", status)
	}
	if status, _ := f.refreshWith(t, second, ""); status != http.StatusBadRequest {
		t.Errorf("the lineage outlived it: %d", status)
	}
}

// Off by default, and then nothing changes: no second answer, nothing held.
func TestARefreshHasNoRetryUntilAClientOptsIn(t *testing.T) {
	f := newTokenFixture(t)
	first := f.firstRefreshToken(t)
	status, body := f.refreshWith(t, first, "")
	second := refreshed(t, status, body)
	var sealed []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT successor_sealed FROM core.refresh_tokens
		WHERE token_hash = $1`, store.HashToken(first)).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if sealed != nil {
		t.Error("a successor was held for a client that did not opt in")
	}
	if status, _ := f.refreshWith(t, first, ""); status != http.StatusBadRequest {
		t.Fatalf("reuse answered %d", status)
	}
	if status, _ := f.refreshWith(t, second, ""); status != http.StatusBadRequest {
		t.Errorf("reuse did not end the lineage: %d", status)
	}
}

// The other way an answer goes missing: the application sent it twice at once. With the
// grace both get the one successor, in whichever order the row lock puts them.
func TestTwoRefreshesAtOnceGetOneSuccessorWithinTheGrace(t *testing.T) {
	f := newTokenFixture(t)
	f.setRefreshGrace(t, 10*time.Second)
	first := f.firstRefreshToken(t)

	var wg sync.WaitGroup
	type answer struct {
		status int
		token  string
	}
	answers := make(chan answer, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body := f.refreshWith(t, first, "")
			token, _ := body["refresh_token"].(string)
			answers <- answer{status, token}
		}()
	}
	wg.Wait()
	close(answers)
	a, b := <-answers, <-answers
	if a.status != http.StatusOK || b.status != http.StatusOK || a.token == "" || a.token != b.token {
		t.Errorf("two at once answered %+v and %+v, want one successor", a, b)
	}
}

func TestARefreshGraceIsBounded(t *testing.T) {
	f := newTokenFixture(t)
	for _, grace := range []time.Duration{-time.Second, 31 * time.Second, 1500 * time.Millisecond} {
		if err := f.writeRefreshGrace(grace); err == nil {
			t.Errorf("a grace of %s was accepted", grace)
		}
	}
}
