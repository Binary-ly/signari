package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Where a provider resolves the artifacts it sends requests by is declared like its
// other endpoints (8.08): applied, planned as a change, quiet when the file already
// says what the deployment holds, and gone when the file stops naming it.
func TestArtifactResolutionIsDeclared(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	entity := fmt.Sprintf("https://sp-%d.example.test", time.Now().UnixNano())
	plain := SAMLProvider{EntityID: entity, ACSURLs: []string{"https://sp.example.test/acs"}}
	resolving := plain
	resolving.ArtifactResolution = []ArtifactResolutionService{{Index: 1, URL: "https://sp.example.test/ars"}}
	apply := func(p SAMLProvider) string {
		t.Helper()
		f := &File{SAMLProviders: []SAMLProvider{p}}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan.String()
	}
	held := func() string {
		t.Helper()
		var got string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(string_agg(a.endpoint_index || '=' || a.url, ' '), '')
			FROM core.saml_artifact_resolution a JOIN core.saml_providers p ON p.id = a.provider_id
			WHERE p.entity_id = $1`, entity).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	apply(plain)
	if got := held(); got != "" {
		t.Errorf("a file that names none gave it %q", got)
	}
	if plan := apply(resolving); !strings.Contains(plan, "artifact_resolution") {
		t.Errorf("adding one was planned as\n%s", plan)
	}
	if got := held(); got != "1=https://sp.example.test/ars" {
		t.Errorf("the provider holds %q", got)
	}
	if plan := apply(resolving); strings.Contains(plan, entity) {
		t.Errorf("applied again it plans\n%s", plan)
	}
	if plan := apply(plain); !strings.Contains(plan, "artifact_resolution") {
		t.Errorf("dropping it was planned as\n%s", plan)
	}
	if got := held(); got != "" {
		t.Errorf("a file that stopped naming it left %q", got)
	}
}
