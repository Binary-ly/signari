package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Conditional writes: RFC 7232 preconditions on the administrative API.
//
// # The failure this exists to stop
//
// Two administrators open the same client. The first disables it. The second,
// working from a page rendered before that, saves an unrelated change -- and the
// client is enabled again. Nobody is told. The audit trail records two successful
// updates, because both were. That is a lost update, and it is the ordinary
// outcome of a last-write-wins API whenever two people, or two automation runs,
// touch one object.
//
// It is worth stating plainly that this is not a hypothetical gap in the field.
// Read on 25 August 2026, against current upstream source:
//
//   - Keycloak's admin client update (`ClientResource.java:157` `update()`)
//     applies the representation unconditionally. Its documented 409 is
//     `ModelDuplicateException` -- a name collision, not a concurrency conflict.
//   - Zitadel's `management.proto` (14,427 lines) has no precondition field on
//     any write. Its `ObjectDetails.sequence` is documented for reads: "on read:
//     the sequence of the last event reduced by the projection".
//   - authentik and Ory Hydra have no `If-Match` handling at all.
//
// So every one of them silently loses the first writer's change. This engine can
// do better for a structural reason rather than a clever one: ADR-008 already
// requires every mutation to bump `core.config_version` in the same transaction,
// so a monotonic number identifying the exact configuration state already exists
// and is already transactional. Preconditions are that number, used.
//
// # Why the check is inside the transaction, and why it costs nothing
//
// Checking the version before opening the transaction would be a race with a
// longer window than the bug it fixes: read version, another writer commits,
// write anyway. So `SELECT ... FOR UPDATE` takes the row lock first, and the
// comparison happens while holding it.
//
// That serialises administrative mutations against one row -- which is not a new
// cost, because `mutate` already ends every transaction with an `UPDATE` of that
// same row. The lock was always taken; this only takes it earlier. Administration
// is low-volume and bursty by nature, and the alternative to serialising is the
// lost update above.
//
// # Semantics
//
//	If-Match: "42"    proceed only if the configuration is still at version 42
//	If-Match: *       proceed if any configuration exists (RFC 7232 section 3.1)
//	absent            unconditional, exactly as before
//
// Absent means unconditional deliberately. A precondition that were mandatory
// would break every existing caller and would be ignored by the first person in a
// hurry; one that is available and honoured is used by the callers that care.

// ErrPreconditionFailed is returned when the configuration moved between the
// caller's read and its write.
//
// Carries both versions because "someone else changed it" is not actionable and
// "you expected 42, it is now 47" tells an operator how far behind they were.
type ErrPreconditionFailed struct {
	Expected int64
	Actual   int64
}

func (e *ErrPreconditionFailed) Error() string {
	return fmt.Sprintf("the configuration was at version %d, not the expected %d",
		e.Actual, e.Expected)
}

// errMalformedIfMatch is a syntactically invalid If-Match.
//
// Refused rather than ignored, and that distinction is the whole value of the
// header. A caller that sends `If-Match: 42` (unquoted, which RFC 7232 does not
// permit) believes it has protection. Ignoring the header would hand it a
// last-write-wins update wearing the appearance of a conditional one, which is
// worse than not offering the feature.
var errMalformedIfMatch = errors.New("malformed If-Match")

// precondition is a parsed If-Match.
type precondition struct {
	// any is `If-Match: *`.
	any bool
	// version is the expected config version when any is false.
	version int64
	// present distinguishes "no header" from a parsed one.
	present bool
}

// parseIfMatch reads the header.
//
// Only the shapes this API can actually honour are accepted. RFC 7232 permits a
// comma-separated list of entity tags; that is meaningful when a resource has
// several representations, and here there is exactly one version counter, so a
// list would have no coherent meaning. A caller sending one gets a refusal rather
// than having the first element silently used.
func parseIfMatch(h http.Header) (precondition, error) {
	raw := strings.TrimSpace(h.Get("If-Match"))
	if raw == "" {
		return precondition{}, nil
	}
	if raw == "*" {
		return precondition{any: true, present: true}, nil
	}
	if strings.Contains(raw, ",") {
		return precondition{}, fmt.Errorf(
			"%w: a list of entity tags has no meaning here, because this API has one "+
				"version counter. Send a single tag", errMalformedIfMatch)
	}
	// A weak validator cannot be used for a conditional write: RFC 7232 section
	// 3.1 requires a strong comparison for If-Match, and W/ marks the tag as
	// explicitly not usable for one.
	if strings.HasPrefix(raw, "W/") {
		return precondition{}, fmt.Errorf(
			"%w: a weak entity tag cannot be used for a conditional write "+
				"(RFC 7232 section 3.1 requires the strong comparison function)",
			errMalformedIfMatch)
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return precondition{}, fmt.Errorf(
			"%w: an entity tag must be quoted, as `If-Match: \"42\"`", errMalformedIfMatch)
	}
	v, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil {
		return precondition{}, fmt.Errorf(
			"%w: %q is not a version this API issued; use the ETag from the last "+
				"response, or GET /admin/config-version", errMalformedIfMatch, raw)
	}
	return precondition{version: v, present: true}, nil
}

// readPrecondition parses If-Match and answers a malformed one.
//
// Returns false when it has already written the response, so a handler's first
// line can be `p, ok := s.readPrecondition(w, r); if !ok { return }`.
func (s *Server) readPrecondition(w http.ResponseWriter, r *http.Request) (precondition, bool) {
	p, err := parseIfMatch(r.Header)
	if err != nil {
		writePreconditionFailure(w, err)
		return precondition{}, false
	}
	return p, true
}

// checkPrecondition compares the caller's expectation against the live version,
// holding the row lock.
//
// Returns the current version so the caller can report both sides.
func checkPrecondition(ctx context.Context, tx pgx.Tx, p precondition) error {
	if !p.present {
		return nil
	}
	var current int64
	if err := tx.QueryRow(ctx,
		`SELECT version FROM core.config_version WHERE id = true FOR UPDATE`).Scan(&current); err != nil {
		return fmt.Errorf("reading the configuration version: %w", err)
	}
	if p.any {
		// `*` asks whether any representation exists. The row is a singleton
		// created by migration 0002, so reaching here answers yes.
		return nil
	}
	if current != p.version {
		return &ErrPreconditionFailed{Expected: p.version, Actual: current}
	}
	return nil
}

// etag renders a config version as a strong entity tag.
func etag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

// setETag puts the resulting version on a response.
//
// Every mutation sets it, so a caller that reads its own write has the value it
// needs for the NEXT conditional request without a second round trip. That is
// what makes preconditions usable in a loop rather than only for a single
// careful edit.
func setETag(w http.ResponseWriter, version int64) {
	if version > 0 {
		w.Header().Set("ETag", etag(version))
	}
}

// writePreconditionFailure answers a failed or malformed precondition.
//
// 412 for a version mismatch and 400 for a malformed header, which are genuinely
// different: the first says "retry after re-reading", the second says "your
// request was never conditional".
func writePreconditionFailure(w http.ResponseWriter, err error) bool {
	var pf *ErrPreconditionFailed
	if errors.As(err, &pf) {
		// The current version travels back as an ETag as well as in the body, so a
		// caller retrying can use the response directly rather than parsing prose.
		setETag(w, pf.Actual)
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{
			"error":            "precondition_failed",
			"detail":           pf.Error(),
			"expected_version": pf.Expected,
			"current_version":  pf.Actual,
		})
		return true
	}
	if errors.Is(err, errMalformedIfMatch) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_if_match", "detail": err.Error(),
		})
		return true
	}
	return false
}
