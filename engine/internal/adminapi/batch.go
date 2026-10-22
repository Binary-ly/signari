package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
)

// POST /admin/batch (6.08): up to a hundred writes in one transaction, all or
// none, with one configuration bump. A provisioning run that made a hundred
// users in a hundred requests left the first forty if the forty-first was
// refused, and moved the version a hundred times, refusing every conditional
// write made while it ran.
//
// # How
//
// Each operation is dispatched through the router as a request of its own,
// with the caller's token, so it is authenticated and held to its own scope,
// organisation, object and privileged-target checks exactly as when sent
// alone; nothing about a batch widens what a token may do. Its context carries
// the batch's transaction, and mutateIf, through which every write in this
// package goes, writes into that transaction instead of opening and committing
// its own. The first operation refused ends the batch, and the transaction is
// rolled back, so nothing any operation wrote is kept.
//
// An operation sees the configuration as it was when the batch began plus
// what earlier operations wrote only where its handler reads inside the write:
// a handler's checks before it read committed state, so an operation that
// needs an earlier one's result (a member added to a group the same batch
// creates) is refused, and is sent in a second batch.

const maxBatchOperations = 100

// batchRun is a batch in progress: the transaction its operations write into,
// the version it will commit, and whether the current operation wrote.
type batchRun struct {
	tx      pgx.Tx
	version int64
	wrote   bool
}

type batchKey struct{}

// batchOperation is one write in a batch.
type batchOperation struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

type batchRequest struct {
	Operations []batchOperation `json:"operations"`
}

type batchResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// recorder captures an operation's answer.
type recorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (c *recorder) Header() http.Header         { return c.header }
func (c *recorder) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *recorder) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, nested := ctx.Value(batchKey{}).(*batchRun); nested {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_batch",
			"detail": "a batch cannot contain a batch"})
		return
	}
	var req batchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if n := len(req.Operations); n == 0 || n > maxBatchOperations {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_batch",
			"detail": fmt.Sprintf("a batch is 1 to %d operations, not %d", maxBatchOperations, n)})
		return
	}
	for i, op := range req.Operations {
		path := strings.Replace(op.Path, "/admin/v1/", "/admin/", 1)
		switch {
		case op.Method != http.MethodPost && op.Method != http.MethodPut &&
			op.Method != http.MethodPatch && op.Method != http.MethodDelete:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_batch",
				"detail": fmt.Sprintf("operation %d is %q; a batch is writes: POST, PUT, PATCH or DELETE", i, op.Method)})
			return
		case !strings.HasPrefix(path, "/admin/") || strings.HasPrefix(path, "/admin/batch"):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_batch",
				"detail": fmt.Sprintf("operation %d's path %q is not an Admin API write", i, op.Path)})
			return
		}
		req.Operations[i].Path = path
	}
	mux := s.mux.Load()
	if mux == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.LockConfigVersion(ctx, tx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := checkPrecondition(ctx, tx, pre); err != nil {
		if writePreconditionFailure(w, err) {
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	run := &batchRun{tx: tx}
	if err := tx.QueryRow(ctx, `SELECT version + 1 FROM core.config_version`).Scan(&run.version); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	bctx := withBatch(ctx, run)

	results := make([]batchResult, 0, len(req.Operations))
	for i, op := range req.Operations {
		body := []byte(op.Body)
		if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
			body = nil
		}
		sub, err := http.NewRequestWithContext(bctx, op.Method, op.Path, bytes.NewReader(body))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_batch",
				"detail": fmt.Sprintf("operation %d: %v", i, err)})
			return
		}
		sub.Header.Set("Authorization", r.Header.Get("Authorization"))
		if op := r.Header.Get(OperatorHeader); op != "" {
			sub.Header.Set(OperatorHeader, op)
		}
		if body != nil {
			sub.Header.Set("Content-Type", "application/json")
			sub.ContentLength = int64(len(body))
		}
		rec := &recorder{header: http.Header{}}
		run.wrote = false
		mux.ServeHTTP(rec, sub)
		if rec.code == 0 {
			rec.code = http.StatusOK
		}
		if rec.code >= 300 || !run.wrote {
			// Nothing kept: the deferred rollback undoes every operation.
			detail := fmt.Sprintf("operation %d (%s %s) was refused with %d; nothing in the batch was written",
				i, op.Method, op.Path, rec.code)
			code := rec.code
			if rec.code < 300 {
				detail = fmt.Sprintf("operation %d (%s %s) wrote nothing a batch can hold to its transaction; "+
					"nothing in the batch was written", i, op.Method, op.Path)
				code = http.StatusBadRequest
			}
			writeJSON(w, code, map[string]any{"error": "batch_failed", "detail": detail,
				"failed_index": i, "status": rec.code, "response": json.RawMessage(nonEmptyJSON(rec.body.Bytes()))})
			return
		}
		results = append(results, batchResult{Status: rec.code, Body: nonEmptyJSON(rec.body.Bytes())})
	}

	var version int64
	if err := tx.QueryRow(ctx, `UPDATE core.config_version SET version = version + 1, bumped_at = now()
		WHERE id = true RETURNING version`).Scan(&version); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Info("admin batch applied", "operations", len(results), "config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{"config_version": version, "results": results})
}

// withBatch carries a batch to the operations it dispatches.
func withBatch(ctx context.Context, run *batchRun) context.Context {
	return context.WithValue(ctx, batchKey{}, run)
}

// inBatch is the batch a request is part of, if any.
func inBatch(ctx context.Context) (*batchRun, bool) {
	b, ok := ctx.Value(batchKey{}).(*batchRun)
	return b, ok
}

// nonEmptyJSON is b, or null for an operation that answered nothing (a 204).
func nonEmptyJSON(b []byte) json.RawMessage {
	if len(bytes.TrimSpace(b)) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(bytes.TrimSpace(b))
}
