package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/store"
)

// An organisation's access policy and sign-in flows (6.07), as `signari
// policy apply` and `signari flow apply` install them: a document, parsed and
// its own test cases run before it is stored, so one that will not load
// never reaches the table an operator believes is deployed.

type appliedDocumentView struct {
	OrgID     string     `json:"org_id"`
	Document  string     `json:"document"`
	AppliedAt *time.Time `json:"applied_at"`
}

// putDocumentRequest carries the document as the file holds it.
type putDocumentRequest struct {
	Document string `json:"document"`
}

const documentRefusal = "change how everybody in the organisation signs in"

func (s *Server) getAccessPolicy(w http.ResponseWriter, r *http.Request) {
	s.getDocument(w, r, "policy")
}

func (s *Server) getSignInFlow(w http.ResponseWriter, r *http.Request) {
	s.getDocument(w, r, "flow")
}

// flowPathView is one way through a flow and the situation that takes it.
type flowPathView struct {
	Stages []string `json:"stages"`
	When   []string `json:"when"`
}

type flowView struct {
	Name  string         `json:"name"`
	On    string         `json:"on"`
	Paths []flowPathView `json:"paths"`
}

// getSignInFlowPaths is every journey the flow in force can take, as
// `signari flow paths` prints them, or the built-in flows' when none is applied.
func (s *Server) getSignInFlowPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.SignInFlowOf(ctx, s.db, orgID)
	var file *flow.File
	if err == nil {
		if got.Document == "" {
			file, err = flow.Default()
		} else {
			file, err = flow.Parse([]byte(got.Document))
		}
	}
	if err != nil {
		s.log.Error("reading a sign-in flow's paths", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	flows := make([]flowView, 0, len(file.Flows))
	for i := range file.Flows {
		fl := &file.Flows[i]
		paths, err := fl.Paths()
		if err != nil {
			s.log.Error("walking a sign-in flow", "org_id", orgID, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		view := flowView{Name: fl.Name, On: string(fl.On), Paths: make([]flowPathView, 0, len(paths))}
		for _, p := range paths {
			one := flowPathView{Stages: make([]string, 0, len(p.Stages)), When: []string{}}
			for _, st := range p.Stages {
				one.Stages = append(one.Stages, string(st))
			}
			for _, c := range fl.Conditions() {
				if p.Given[c] {
					one.When = append(one.When, c)
				}
			}
			view.Paths = append(view.Paths, one)
		}
		flows = append(flows, view)
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "applied": got.Document != "", "flows": flows})
}

// getDocument answers the document in force, empty with no applied_at when
// there is none: then everything is allowed, or the built-in flows run.
func (s *Server) getDocument(w http.ResponseWriter, r *http.Request, kind string) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	read := store.AccessPolicyOf
	if kind == "flow" {
		read = store.SignInFlowOf
	}
	got, err := read(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("reading a declarative document", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	s.writeList(w, r, appliedDocumentView{OrgID: orgID, Document: got.Document, AppliedAt: got.AppliedAt})
}

func (s *Server) putAccessPolicy(w http.ResponseWriter, r *http.Request) {
	s.putDocument(w, r, "policy")
}

func (s *Server) putSignInFlow(w http.ResponseWriter, r *http.Request) {
	s.putDocument(w, r, "flow")
}

// putDocument installs a policy or flow document, as the apply commands do.
func (s *Server) putDocument(w http.ResponseWriter, r *http.Request, kind string) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putDocumentRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if narrowedTokenRefused(w, r, documentRefusal) {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	sum := sha256.Sum256([]byte(req.Document))
	digest := hex.EncodeToString(sum[:])
	out := map[string]any{"org_id": orgID}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if kind == "policy" {
			f, err := store.ApplyAccessPolicy(ctx, tx, orgID, []byte(req.Document))
			if err != nil {
				return err
			}
			out["summary"] = f.Summary()
			// The digest, not the document: the trail says which version was
			// put in force, and the document says what it is.
			return audit.Write(ctx, tx, audit.Event{Type: "admin.access_policy_applied",
				AdminTokenID: TokenIDFrom(ctx), OrgID: orgID,
				Detail: map[string]any{"sha256": digest, "summary": f.Summary()}})
		}
		f, err := store.ApplySignInFlow(ctx, tx, orgID, []byte(req.Document))
		if err != nil {
			return err
		}
		out["summary"], out["not_executed"] = f.Summary(), undriven(f)
		return audit.Write(ctx, tx, audit.Event{Type: "admin.sign_in_flow_applied", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"sha256": digest, "summary": f.Summary()}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrInvalidDocument):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_" + kind, "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("applying a declarative document", "org_id", orgID, "kind", kind, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	out["config_version"] = version
	writeJSON(w, http.StatusOK, out)
}

// undriven names the flows a file declares for a journey this engine does not
// walk: stored and checked, with no endpoint to govern.
func undriven(f *flow.File) []string {
	out := []string{}
	for i := range f.Flows {
		if !f.Flows[i].On.Driven() {
			out = append(out, f.Flows[i].Name)
		}
	}
	return out
}
