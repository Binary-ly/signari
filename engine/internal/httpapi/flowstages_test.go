package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/flow"
)

// Parse lets a flow name only the stages its journey runs (flow.Drivable), and
// the drivers are the switch statements over `stage` in advanceSignIn and
// handleSignupPost, plus recoveryDrivableStages. The two must name the same
// set. A stage listed there and run by nothing here is walked past in a
// sign-in -- `password, kerberos, session` was a password sign-in -- or stops
// a sign-up or recovery with a 501. One run here and missing there is refused
// at parse for no reason.
func TestEveryStageAFlowCanUseIsDriven(t *testing.T) {
	values := stageConstants(t)

	signIn := switchStages(t, "flowdrive.go", "advanceSignIn", values)
	for st := range signInSettledStages {
		signIn[st] = true
	}
	compareStages(t, flow.Authentication, signIn)

	compareStages(t, flow.Enrolment, switchStages(t, "signup.go", "handleSignupPost", values))

	recovery := map[flow.StageName]bool{flow.StageDeny: true} // handled apart; see recoveryPlan
	for st := range recoveryDrivableStages {
		recovery[st] = true
	}
	compareStages(t, flow.Recovery, recovery)
}

// stageConstants maps each flow.StageX identifier to its value, read from the
// flow package's source so a renamed or added stage cannot be missed here.
func stageConstants(t *testing.T) map[string]flow.StageName {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../flow/stages.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]flow.StageName{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "StageName" || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			out[vs.Names[0].Name] = flow.StageName(v)
		}
	}
	if len(out) < 15 {
		t.Fatalf("read %d stage constants from flow/stages.go; this test is no longer reading them", len(out))
	}
	return out
}

// switchStages collects the `case flow.StageX:` labels of the switch over
// `stage` in function fn of file.
func switchStages(t *testing.T, file, fn string, values map[string]flow.StageName) map[flow.StageName]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[flow.StageName]bool{}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if tag, ok := sw.Tag.(*ast.Ident); !ok || tag.Name != "stage" {
				return true
			}
			found = true
			for _, c := range sw.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					sel, ok := e.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					v, ok := values[sel.Sel.Name]
					if !ok {
						t.Errorf("%s: case %s is not a stage constant", fn, sel.Sel.Name)
						continue
					}
					out[v] = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("no `switch stage` in %s in %s; this test is no longer reading the driver", fn, file)
	}
	return out
}

// placeUnparsedFlow puts a flow straight into the cache, as one that bypassed
// Parse would arrive. Since Parse refuses a stage its journey cannot run, this
// is the only way left to reach a driver's own refusal, which stays as the
// last line should flow.drivable ever widen ahead of a driver. The test is
// told, by failing, if the flow it places would in fact parse.
func placeUnparsedFlow(t *testing.T, srv *Server, orgID string, on flow.Designation, stages ...flow.StageName) {
	t.Helper()
	steps := make([]flow.Step, len(stages))
	names := make([]string, len(stages))
	for i, st := range stages {
		steps[i] = flow.Step{Stage: st}
		names[i] = string(st)
	}
	doc := "version: 1\nflows:\n  - name: unparsed\n    on: " + string(on) +
		"\n    stages: [" + strings.Join(names, ", ") + "]\n    tests: [{name: t, given: {}, expect: [" +
		strings.Join(names, ", ") + "]}]\n"
	if _, err := flow.Parse([]byte(doc)); err == nil {
		t.Fatalf("%s parses, so it needs no bypass; apply it the ordinary way", doc)
	}

	file := &flow.File{Version: 1, Flows: []flow.Flow{{Name: "unparsed", On: on, Stages: steps}}}
	srv.flows.mu.Lock()
	prev, prevAt, prevEver := srv.flows.byOrg, srv.flows.loadedAt, srv.flows.everLoaded
	byOrg := map[string]*flow.File{orgID: file}
	for k, v := range prev {
		if k != orgID {
			byOrg[k] = v
		}
	}
	srv.flows.byOrg, srv.flows.loadedAt, srv.flows.everLoaded = byOrg, time.Now(), true
	srv.flows.mu.Unlock()
	t.Cleanup(func() {
		srv.flows.mu.Lock()
		srv.flows.byOrg, srv.flows.loadedAt, srv.flows.everLoaded = prev, prevAt, prevEver
		srv.flows.mu.Unlock()
	})
}

func compareStages(t *testing.T, on flow.Designation, driven map[flow.StageName]bool) {
	t.Helper()
	listed := map[flow.StageName]bool{}
	for _, st := range flow.Drivable(on) {
		listed[st] = true
		if !driven[st] {
			t.Errorf("on %s, flow.Drivable lets a flow name %s and nothing here runs it", on, st)
		}
	}
	var extra []string
	for st := range driven {
		if !listed[st] {
			extra = append(extra, string(st))
		}
	}
	sort.Strings(extra)
	for _, st := range extra {
		t.Errorf("on %s, %s is run here and refused at parse; add it to flow.drivable", on, st)
	}
}
