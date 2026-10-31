package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fixtureTarget behaves as a target does that needs one of these: it refuses
// what such a target refuses, with the refusal it gives, so a test passes only by
// sending what it would accept.
type fixtureTarget struct {
	*httptest.Server
	mu sync.Mutex
	// user and group are the resources as they stand, attributes this client has
	// no field for among them.
	user, group map[string]any
	filtered    int
	listed      int
	puts        int
}

func newFixtureTarget(t *testing.T, refusesPatch, refusesFilter, wantsTypedMembers bool) *fixtureTarget {
	t.Helper()
	f := &fixtureTarget{
		user: map[string]any{"id": "u-1", "userName": "ada", "active": true, "title": "Countess",
			"meta": map[string]any{"resourceType": "User"}},
		group: map[string]any{"id": "g-1", "displayName": "Team", "description": "kept here",
			"members": []any{map[string]any{"value": "by-hand", "display": "Added at the target"},
				map[string]any{"value": "leaving"}}},
	}
	answer := func(w http.ResponseWriter, status int, body any) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	refusePatch := func(w http.ResponseWriter, r *http.Request) bool {
		if refusesPatch {
			answer(w, http.StatusMethodNotAllowed, map[string]string{"detail": "PATCH is not supported"})
			return true
		}
		return false
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /Users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Query().Get("filter") != "" {
			f.filtered++
			if refusesFilter {
				answer(w, http.StatusBadRequest, map[string]string{"detail": "filtering is not supported"})
				return
			}
		}
		f.listed++
		answer(w, http.StatusOK, map[string]any{"totalResults": 1, "Resources": []any{f.user}})
	})
	mux.HandleFunc("GET /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		answer(w, http.StatusOK, f.user)
	})
	mux.HandleFunc("PATCH /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !refusePatch(w, r) {
			answer(w, http.StatusOK, f.user)
		}
	})
	mux.HandleFunc("PUT /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var sent map[string]any
		_ = json.NewDecoder(r.Body).Decode(&sent)
		f.user = sent
		f.puts++
		answer(w, http.StatusOK, sent)
	})
	mux.HandleFunc("GET /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		answer(w, http.StatusOK, f.group)
	})
	mux.HandleFunc("PATCH /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if refusePatch(w, r) {
			return
		}
		var p struct {
			Operations []struct {
				Value []map[string]any `json:"value"`
			} `json:"Operations"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		for _, op := range p.Operations {
			for _, m := range op.Value {
				if wantsTypedMembers && m["type"] == nil {
					answer(w, http.StatusBadRequest, map[string]string{"detail": "a member has no type"})
					return
				}
			}
		}
		answer(w, http.StatusOK, nil)
	})
	mux.HandleFunc("PUT /Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var sent map[string]any
		_ = json.NewDecoder(r.Body).Decode(&sent)
		f.group = sent
		f.puts++
		answer(w, http.StatusOK, sent)
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fixtureTarget) client(compatibility ...string) *Client {
	return NewClient(Target{BaseURL: f.URL, Token: "t", Compatibility: compatibility}, f.Client())
}

func members(group map[string]any) []string {
	raw, _ := group["members"].([]any)
	out := []string{}
	for _, m := range raw {
		out = append(out, memberValue(m))
	}
	slices.Sort(out)
	return out
}

// A target that refuses PATCH is the one this could not turn anybody off at: the
// deactivation failed on every sync, and somebody who left kept their account.
func TestATargetThatRefusesPatchIsStillDeprovisioned(t *testing.T) {
	f := newFixtureTarget(t, true, false, false)
	ctx := context.Background()
	if err := f.client().SetActive(ctx, "u-1", false); err == nil {
		t.Fatal("the fixture did not refuse PATCH, so this proves nothing")
	}
	if err := f.client(CompatNoPatch).SetActive(ctx, "u-1", false); err != nil {
		t.Fatal(err)
	}
	if f.user["active"] != false {
		t.Errorf("active is %v", f.user["active"])
	}
	// What a plain PUT would have erased.
	if f.user["title"] != "Countess" || f.user["userName"] != "ada" {
		t.Errorf("the resource went back as %v", f.user)
	}
}

// A group is an access list. Exactly who moved changes, and somebody added at the
// target by hand stays, as they do with PATCH.
func TestAGroupIsChangedOnlyWhereItHasTo(t *testing.T) {
	f := newFixtureTarget(t, true, false, false)
	c := f.client(CompatNoPatch)
	ctx := context.Background()
	if err := c.AddMembers(ctx, "g-1", []string{"joining", "by-hand"}); err != nil {
		t.Fatal(err)
	}
	if got := members(f.group); !slices.Equal(got, []string{"by-hand", "joining", "leaving"}) {
		t.Errorf("after adding: %v", got)
	}
	if err := c.RemoveMembers(ctx, "g-1", []string{"leaving"}); err != nil {
		t.Fatal(err)
	}
	if got := members(f.group); !slices.Equal(got, []string{"by-hand", "joining"}) {
		t.Errorf("after removing: %v", got)
	}
	if f.group["description"] != "kept here" {
		t.Errorf("the group went back as %v", f.group)
	}
	// Who was there is kept as they were, and not rebuilt from an id.
	first, _ := f.group["members"].([]any)
	if m, _ := first[0].(map[string]any); m["display"] != "Added at the target" {
		t.Errorf("a member went back as %v", first[0])
	}
	// No request at all for nobody, which a PUT of a read would have been.
	before := f.puts
	if err := c.AddMembers(ctx, "g-1", nil); err != nil || f.puts != before {
		t.Errorf("nobody moved and it answered %v, %d puts", err, f.puts-before)
	}
}

func TestADryRunSendsNothingEitherWay(t *testing.T) {
	f := newFixtureTarget(t, true, false, false)
	c := NewClient(Target{BaseURL: f.URL, Token: "t", DryRun: true, Compatibility: []string{CompatNoPatch}}, f.Client())
	ctx := context.Background()
	if err := c.SetActive(ctx, "u-1", false); err != nil {
		t.Fatal(err)
	}
	if err := c.AddMembers(ctx, "g-1", []string{"joining"}); err != nil {
		t.Fatal(err)
	}
	if f.puts != 0 || f.user["active"] != true {
		t.Errorf("%d puts, active %v", f.puts, f.user["active"])
	}
}

// After a 409, the only time this looks anybody up: refused a filter, the account
// that already exists could not be found, and nobody was ever linked to it.
func TestAnAccountIsFoundAtATargetThatRefusesAFilter(t *testing.T) {
	f := newFixtureTarget(t, false, true, false)
	ctx := context.Background()
	if _, err := f.client().FindByUserName(ctx, "ada"); err == nil {
		t.Fatal("the fixture did not refuse a filter, so this proves nothing")
	}
	c := f.client(CompatNoFilter)
	got, err := c.FindByUserName(ctx, "ADA")
	if err != nil || got == nil || got.ID != "u-1" {
		t.Fatalf("found %+v, %v", got, err)
	}
	if none, err := c.FindByUserName(ctx, "nobody"); err != nil || none != nil {
		t.Errorf("found %+v, %v", none, err)
	}
	before := f.filtered
	if _, err := c.FindByUserName(ctx, "ada"); err != nil {
		t.Fatal(err)
	}
	if f.filtered != before {
		t.Error("a filter was sent to a target known to refuse one")
	}
}

func TestATargetThatWantsATypedMemberIsGivenOne(t *testing.T) {
	f := newFixtureTarget(t, false, false, true)
	ctx := context.Background()
	if err := f.client().AddMembers(ctx, "g-1", []string{"joining"}); err == nil {
		t.Fatal("the fixture did not refuse an untyped member, so this proves nothing")
	}
	if err := f.client(CompatTypedMembers).AddMembers(ctx, "g-1", []string{"joining"}); err != nil {
		t.Fatal(err)
	}

	// And by PUT, when it is both.
	g := newFixtureTarget(t, true, false, true)
	if err := g.client(CompatNoPatch, CompatTypedMembers).AddMembers(ctx, "g-1", []string{"joining"}); err != nil {
		t.Fatal(err)
	}
	all, _ := g.group["members"].([]any)
	if m, _ := all[len(all)-1].(map[string]any); m["type"] != "user" {
		t.Errorf("the new member went as %v", all[len(all)-1])
	}
}

// With none set, what goes out is what always did: nothing here is a change to a
// target that speaks the protocol.
func TestAPlainTargetIsSpokenToAsItWas(t *testing.T) {
	f := newFixtureTarget(t, false, false, false)
	c := f.client()
	ctx := context.Background()
	if err := c.SetActive(ctx, "u-1", false); err != nil {
		t.Fatal(err)
	}
	if err := c.AddMembers(ctx, "g-1", []string{"joining"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FindByUserName(ctx, "ada"); err != nil {
		t.Fatal(err)
	}
	if f.puts != 0 || f.filtered != 1 {
		t.Errorf("%d puts and %d filters", f.puts, f.filtered)
	}
}

func TestCompatibilityIsOneOfWhatThereIs(t *testing.T) {
	if err := CheckCompatibility(Compatibilities); err != nil {
		t.Error(err)
	}
	err := CheckCompatibility([]string{CompatNoPatch, "no-patches"})
	if err == nil || !strings.Contains(err.Error(), "no-patches") {
		t.Errorf("a misspelling answered %v: a setting that quietly does nothing", err)
	}
}
