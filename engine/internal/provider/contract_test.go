package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var contractsOut = flag.String("hook-contracts-out", "", "write the published hook contracts here")

// The published contracts are the ones this package states. Regenerate them with
// `go test ./internal/provider -run TheHookContractsAreCurrent -hook-contracts-out <file>`.
func TestTheHookContractsAreCurrent(t *testing.T) {
	got, err := json.MarshalIndent(map[string]any{"version": ContractVersion, "hooks": Contracts()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *contractsOut != "" {
		if err := os.WriteFile(*contractsOut, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "hook-contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, published) {
		t.Error("docs/hook-contracts.json is not what this package states; regenerate it with -hook-contracts-out")
	}
}

// Every hook has a contract, and what `provider test` sends is a request the
// contract allows: a sample that broke it would fail a provider that is right.
func TestEveryHookHasAContractItsSampleKeeps(t *testing.T) {
	for _, h := range allHooks {
		c, ok := ContractFor(h)
		if !ok {
			t.Fatalf("%s has no contract", h)
		}
		required, _ := c.Request["required"].([]string)
		properties, _ := c.Request["properties"].(map[string]any)
		for _, member := range required {
			if _, ok := c.Sample[member]; !ok {
				t.Errorf("%s: the sample has no %s, which the contract requires", h, member)
			}
		}
		for member := range c.Sample {
			if _, ok := properties[member]; !ok {
				t.Errorf("%s: the sample sends %s, which the contract does not name", h, member)
			}
		}
		if answer, _ := c.Response["required"].([]string); c.Verdict == "" || !slices.Contains(answer, c.Verdict) {
			t.Errorf("%s: an answer need not carry the verdict %q `provider test` reads", h, c.Verdict)
		}
	}
}

// Each call says which contract it was made under, so a provider written against
// another can tell before it answers, and a test call says it is one.
func TestACallCarriesItsContractVersion(t *testing.T) {
	var version, test string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version, test = r.Header.Get(VersionHeader), r.Header.Get(TestHeader)
		_, _ = w.Write([]byte(`{"decision":true}`))
	}))
	t.Cleanup(srv.Close)
	p := Provider{Name: "x", Hook: HookAuthorize, URL: srv.URL, Mode: FailClosed, Timeout: time.Second}
	var out map[string]any
	if err := p.Call(context.Background(), srv.Client(), map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if version != ContractVersion || test != "" {
		t.Errorf("a call said version %q, test %q", version, test)
	}
	p.Test = true
	if err := p.Call(context.Background(), srv.Client(), map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if test != "1" {
		t.Errorf("a test call said %q", test)
	}
}
