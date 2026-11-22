package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"signari.dev/engine/internal/store"
)

// SCIM Bulk, RFC 7644 §3.7.
//
// An operation goes through the handler its single request would have reached,
// with the same validation, the same audit and the same refusals, so there is
// nothing here for a rule to be missing from: Bulk's own work is the order, the
// references and the report. A failure is the operation's and the rest carry on,
// which the RFC requires (specs/rfc7644.txt:2781), so this is not a transaction:
// what committed stays committed, and the answer says which those were.

const (
	scimBulkRequest  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	scimBulkResponse = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

	// scimMaxBulkOperations and scimMaxBulkPayload are the limits the RFC has a
	// server define (specs/rfc7644.txt:3495), published in ServiceProviderConfig.
	// The payload is the largest single body, a group's, so that whatever can be
	// sent alone can be sent here.
	scimMaxBulkOperations = 1000
	scimMaxBulkPayload    = scimGroupBodyLimit

	scimBulkPrefix = "bulkId:"
)

type scimBulkOperation struct {
	Method string          `json:"method"`
	BulkID string          `json:"bulkId"`
	Path   string          `json:"path"`
	Data   json.RawMessage `json:"data"`
}

// scimBulkResult is one operation's line in the answer. A status is a string
// there (specs/rfc7644.txt:3210), and the body comes only with a failure, which
// the RFC requires, since a success's is optional and a thousand of them are
// what a bulk request is for avoiding.
type scimBulkResult struct {
	Location string          `json:"location,omitempty"`
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

func (s *Server) handleSCIMBulk(w http.ResponseWriter, r *http.Request) {
	src, err := s.scimAuth(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if r.Method != http.MethodPost {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, scimMaxBulkPayload))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		// A 413 that names the limit (specs/rfc7644.txt:3498).
		writeSCIMError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("the size of the bulk operation exceeds the maxPayloadSize (%d)", scimMaxBulkPayload))
		return
	}
	var req struct {
		Schemas      []string            `json:"schemas"`
		FailOnErrors *int                `json:"failOnErrors"`
		Operations   []scimBulkOperation `json:"Operations"`
	}
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidSyntax", "body is not SCIM JSON")
		return
	}
	switch {
	case !slices.Contains(req.Schemas, scimBulkRequest):
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidSyntax", "a bulk request names "+scimBulkRequest)
		return
	case len(req.Operations) == 0:
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", "a bulk request has at least one operation")
		return
	case len(req.Operations) > scimMaxBulkOperations:
		writeSCIMError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("the bulk operation has %d operations, over the maxOperations (%d)",
				len(req.Operations), scimMaxBulkOperations))
		return
	case req.FailOnErrors != nil && *req.FailOnErrors < 1:
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", "failOnErrors is at least 1")
		return
	}

	b := &scimBulk{s: s, src: src, ops: req.Operations, ids: map[string]string{}, creates: map[string]int{},
		failed: map[string]bool{}, results: make([]*scimBulkResult, len(req.Operations)), limit: req.FailOnErrors}
	b.run(r.Context())

	out := make([]*scimBulkResult, 0, len(b.results))
	for _, result := range b.results {
		if result != nil {
			out = append(out, result)
		}
	}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scimBulkResponse}, "Operations": out})
}

// scimBulk is one request in progress.
type scimBulk struct {
	s   *Server
	src *store.SCIMSource
	ops []scimBulkOperation
	// ids are the resources made so far, by bulkId, creates says which operation
	// makes each, and failed which of them did not.
	ids     map[string]string
	creates map[string]int
	failed  map[string]bool
	results []*scimBulkResult
	errors  int
	limit   *int
}

// run answers the operations in the order given, except that one naming a
// bulkId not yet made waits for the POST that makes it: the RFC lets a server
// reorder so long as the client's intent stands, and gives the example of a user
// that must exist before a group can have them (specs/rfc7644.txt:2803). What
// still cannot run after a pass made no progress is a cycle, which it lets a
// server refuse with a 409 (specs/rfc7644.txt:2815).
func (b *scimBulk) run(ctx context.Context) {
	pending := make([]int, 0, len(b.ops))
	for i, op := range b.ops {
		id := op.BulkID
		switch {
		case op.Method != http.MethodPost:
			pending = append(pending, i)
		case id == "":
			b.report(i, http.StatusBadRequest, "", scimBulkError("invalidValue", http.StatusBadRequest,
				"a POST needs a bulkId"))
		case b.isCreating(id):
			b.report(i, http.StatusBadRequest, "", scimBulkError("uniqueness", http.StatusBadRequest,
				"bulkId "+id+" is used twice"))
		default:
			b.creates[id] = i
			pending = append(pending, i)
		}
	}

	for len(pending) > 0 && !b.stopped() {
		var waiting []int
		progress := false
		for _, i := range pending {
			if b.stopped() {
				return
			}
			refs := scimBulkReferences(b.ops[i])
			if b.waits(refs) {
				waiting = append(waiting, i)
				continue
			}
			b.one(ctx, i, refs)
			progress = true
		}
		if !progress {
			for _, i := range waiting {
				b.report(i, http.StatusConflict, "", scimBulkError("", http.StatusConflict,
					"this operation's references to other operations in the request form a cycle"))
				if b.stopped() {
					return
				}
			}
			return
		}
		pending = waiting
	}
}

func (b *scimBulk) isCreating(id string) bool {
	_, ok := b.creates[id]
	return ok
}

// waits says a reference names a POST that has not yet run. One that names no
// POST here, or one that failed, is the operation's own failure, reported by one.
func (b *scimBulk) waits(refs []string) bool {
	for _, ref := range refs {
		if _, made := b.ids[ref]; !made && b.isCreating(ref) && !b.failed[ref] {
			return true
		}
	}
	return false
}

func (b *scimBulk) stopped() bool {
	return b.limit != nil && b.errors >= *b.limit
}

func (b *scimBulk) report(i, status int, location string, response json.RawMessage) {
	op := b.ops[i]
	result := &scimBulkResult{Location: location, Method: op.Method, BulkID: op.BulkID, Status: strconv.Itoa(status)}
	if status >= http.StatusBadRequest {
		result.Response = response
		b.errors++
		if op.BulkID != "" {
			b.failed[op.BulkID] = true
		}
	}
	b.results[i] = result
}

func scimBulkError(scimType string, status int, detail string) json.RawMessage {
	var rec scimBulkWriter
	if scimType == "" {
		writeSCIMError(&rec, status, detail)
	} else {
		writeSCIMErrorType(&rec, status, scimType, detail)
	}
	return bytes.TrimSpace(rec.body.Bytes())
}

// one runs an operation whose references are settled, one way or the other.
func (b *scimBulk) one(ctx context.Context, i int, refs []string) {
	op := b.ops[i]
	for _, ref := range refs {
		if _, made := b.ids[ref]; made {
			continue
		}
		if b.failed[ref] {
			// Nothing to refer to, and a member quietly left out would be a group
			// the client believes is complete.
			b.report(i, http.StatusConflict, "", scimBulkError("", http.StatusConflict,
				"bulkId "+ref+" was not created"))
			return
		}
		b.report(i, http.StatusBadRequest, "", scimBulkError("invalidValue", http.StatusBadRequest,
			"no operation in this request creates bulkId "+ref))
		return
	}

	path, data, err := b.resolved(op)
	if err != nil {
		b.report(i, http.StatusBadRequest, "", scimBulkError("invalidSyntax", http.StatusBadRequest, err.Error()))
		return
	}
	var rec scimBulkWriter
	if !b.dispatch(ctx, &rec, op.Method, path, data) {
		b.report(i, http.StatusBadRequest, "", scimBulkError("invalidSyntax", http.StatusBadRequest,
			"a bulk operation is a POST to /Users or /Groups, or a PUT, PATCH or DELETE of one of them by id"))
		return
	}
	status := rec.statusCode()
	if status >= http.StatusBadRequest {
		// A failed POST has no location, which the RFC says of it, and one that
		// names a resource keeps it (specs/rfc7644.txt:3202).
		location := ""
		if op.Method != http.MethodPost {
			location = "/scim/v2" + path
		}
		b.report(i, status, location, bytes.TrimSpace(rec.body.Bytes()))
		return
	}

	location := "/scim/v2" + path
	if op.Method == http.MethodPost {
		var made struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.body.Bytes(), &made); err != nil || made.ID == "" {
			b.report(i, http.StatusInternalServerError, "", scimBulkError("", http.StatusInternalServerError, "unavailable"))
			return
		}
		b.ids[op.BulkID] = made.ID
		location += "/" + made.ID
	}
	b.report(i, status, location, nil)
}

// dispatch reaches the handler the operation's single request would have, and
// says false for a method or path that has none.
func (b *scimBulk) dispatch(ctx context.Context, rec *scimBulkWriter, method, path string, data []byte) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || len(parts) > 2 || (parts[0] != "Users" && parts[0] != "Groups") {
		return false
	}
	var id string
	if len(parts) == 2 {
		id = parts[1]
	}
	switch {
	case id == "" && method != http.MethodPost, id == "" && len(parts) == 2:
		return false
	case id != "" && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete:
		return false
	}
	req, err := http.NewRequestWithContext(ctx, method, "/scim/v2"+path, bytes.NewReader(data))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", scimContentType)
	switch {
	case parts[0] == "Users" && id == "":
		b.s.scimCreateUser(rec, req, b.src)
	case parts[0] == "Users":
		b.s.scimServeUser(rec, req, b.src, id)
	case id == "":
		b.s.scimCreateGroup(rec, req, b.src)
	default:
		b.s.scimServeGroup(rec, req, b.src, id)
	}
	return true
}

// scimBulkReferences lists the bulkIds an operation names, in its path and as
// whole strings of its data: "bulkId:qwerty" is replaced, the RFC's word
// (specs/rfc7644.txt:2960), and a value that merely contains those letters is not
// a reference. An extension's reference is one too (specs/rfc7644.txt:3144), which
// reading the data whole gets without knowing any attribute.
func scimBulkReferences(op scimBulkOperation) []string {
	var refs []string
	add := func(s string) {
		if id, ok := strings.CutPrefix(s, scimBulkPrefix); ok && !slices.Contains(refs, id) {
			refs = append(refs, id)
		}
	}
	for part := range strings.SplitSeq(op.Path, "/") {
		add(part)
	}
	var data any
	if err := decodeBulkData(op.Data, &data); err == nil {
		walkBulkStrings(data, func(s string) string {
			add(s)
			return s
		})
	}
	return refs
}

func decodeBulkData(raw json.RawMessage, into *any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A number stays the number that was sent.
	dec.UseNumber()
	return dec.Decode(into)
}

// walkBulkStrings rewrites every string in a decoded value, keys left alone.
func walkBulkStrings(v any, f func(string) string) any {
	switch value := v.(type) {
	case string:
		return f(value)
	case []any:
		for i := range value {
			value[i] = walkBulkStrings(value[i], f)
		}
	case map[string]any:
		for k := range value {
			value[k] = walkBulkStrings(value[k], f)
		}
	}
	return v
}

// resolved is the operation's path and data with its references replaced.
func (b *scimBulk) resolved(op scimBulkOperation) (string, []byte, error) {
	replace := func(s string) string {
		if id, ok := strings.CutPrefix(s, scimBulkPrefix); ok {
			if made, ok := b.ids[id]; ok {
				return made
			}
		}
		return s
	}
	parts := strings.Split(op.Path, "/")
	for i := range parts {
		parts[i] = replace(parts[i])
	}
	path := strings.Join(parts, "/")
	if len(op.Data) == 0 {
		return path, nil, nil
	}
	var data any
	if err := decodeBulkData(op.Data, &data); err != nil {
		return "", nil, errors.New("the operation's data is not JSON")
	}
	out, err := json.Marshal(walkBulkStrings(data, replace))
	if err != nil {
		return "", nil, err
	}
	return path, out, nil
}

// scimBulkWriter takes what a handler answers.
type scimBulkWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *scimBulkWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *scimBulkWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *scimBulkWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func (w *scimBulkWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
