package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Archiving the oldest of the trail (3.18).
//
// # What was wrong
//
// Audit rows were never removed: the trail grew for the life of the
// deployment, and the only way to shrink it was a DELETE that broke the chain
// at the first row left, after which nothing could ever be verified again.
//
// # What an archive is
//
// The oldest part of the chain, a prefix, written to a file that carries every
// column the hash covers, so the file verifies on its own; then removed, with
// an entry in the chain recording what went where: the last archived entry's
// hash, how many, and the file's SHA-256. Verification of the trail that
// remains starts from that hash, so the first row left must still link to the
// last row archived. Unlike a checkpoint this disclaims nothing: the archived
// part is in the file, verifiable, and the remainder is anchored to it.
//
// Each archive record is itself archived by the next archive, inside its
// file, so a sequence of files chains: each file's first entry links to the
// last of the file before, and names that file's hash.
//
// Archiving needs the whole chain to verify. A chain that verifies only since a
// checkpoint has a disclaimed part that no file can make verify, and
// archiving it would turn "not asserted" into "removed".

// ArchiveEvent is the event an archive is recorded under.
const ArchiveEvent = "audit.archived"

// archiveHeader is the archive file's first line: every column the hash
// covers, the links among them.
var archiveHeader = []string{
	"id", "occurred_at", "event_type", "org_id", "subject_id", "actor_id",
	"client_id", "admin_token_id", "correlation_id", "retention_class",
	"detail", "prev_hash", "entry_hash", "hash_version",
}

// Archive describes one archived prefix of the chain.
type Archive struct {
	// FirstID and ThroughID are the first and last entries archived.
	FirstID, ThroughID int64
	Entries            int64
	// FirstPrev is the first entry's link: empty for the start of the trail,
	// otherwise the last hash of the archive before.
	FirstPrev []byte
	LastHash  []byte
	// SHA256 is the file's, hex.
	SHA256 string
	Before time.Time
}

// WriteArchive writes every entry of the chain before the first one at or
// after before to w, in one snapshot that has verified the whole chain, and
// says what it wrote. It writes nothing to the database; CommitArchive does.
func WriteArchive(ctx context.Context, tx pgx.Tx, w io.Writer, before time.Time) (*Archive, error) {
	state, err := JudgeChain(ctx, tx)
	if err != nil {
		return nil, err
	}
	switch {
	case !state.Verified:
		return nil, fmt.Errorf("the audit chain is broken at entry %d; an archive of a broken "+
			"chain would remove the evidence of the break", state.BrokenAt)
	case state.Checkpoint != nil:
		return nil, fmt.Errorf("the audit chain verifies only since the checkpoint at entry %d; "+
			"the part before it cannot be archived as verified", state.Checkpoint.EntryID)
	}

	var through int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(id), 0) FROM core.audit_events
		 WHERE id < COALESCE((SELECT min(id) FROM core.audit_events WHERE occurred_at >= $1),
		                     9223372036854775807)`, before).Scan(&through); err != nil {
		return nil, err
	}
	if through == 0 {
		return nil, fmt.Errorf("no audit entry is older than %s", before.UTC().Format(time.RFC3339))
	}

	a := &Archive{ThroughID: through, Before: before}
	sum := sha256.New()
	cw := csv.NewWriter(io.MultiWriter(w, sum))
	if err := cw.Write(archiveHeader); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, occurred_at, event_type, COALESCE(org_id::text,''),
		       COALESCE(subject_id::text,''), COALESCE(actor_id::text,''),
		       COALESCE(client_id,''), COALESCE(admin_token_id::text,''),
		       COALESCE(correlation_id::text,''), retention_class,
		       detail::text, prev_hash, entry_hash, hash_version
		  FROM core.audit_events WHERE id <= $1 ORDER BY id`, through)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var e Event
		var detail string
		var prev, entry []byte
		var version int
		if err := rows.Scan(&id, &e.OccurredAt, &e.Type, &e.OrgID, &e.SubjectID, &e.ActorID,
			&e.ClientID, &e.AdminTokenID, &e.CorrelationID, &e.Retention, &detail,
			&prev, &entry, &version); err != nil {
			return nil, err
		}
		if a.Entries == 0 {
			a.FirstID, a.FirstPrev = id, prev
		}
		a.Entries++
		a.LastHash = entry
		if err := cw.Write([]string{
			strconv.FormatInt(id, 10), e.OccurredAt.UTC().Format(time.RFC3339Nano),
			e.Type, e.OrgID, e.SubjectID, e.ActorID, e.ClientID, e.AdminTokenID,
			e.CorrelationID, e.Retention, detail,
			hex.EncodeToString(prev), hex.EncodeToString(entry), strconv.Itoa(version),
		}); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return nil, err
	}
	a.SHA256 = hex.EncodeToString(sum.Sum(nil))
	return a, nil
}

// CommitArchive records an archive in the chain and removes what it holds, in
// tx, which must not be the snapshot WriteArchive read: the record is linked to
// the head of the chain as it is now. It refuses when the chain since the
// archive was written no longer starts where the archive ends, or when the
// rows to remove are not exactly the ones archived.
func CommitArchive(ctx context.Context, tx pgx.Tx, a *Archive, declaredBy string) error {
	if strings.TrimSpace(declaredBy) == "" {
		return fmt.Errorf("an archive needs to name who made it")
	}
	var next []byte
	err := tx.QueryRow(ctx, `SELECT prev_hash FROM core.audit_events WHERE id > $1 ORDER BY id LIMIT 1`,
		a.ThroughID).Scan(&next)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && !bytes.Equal(next, a.LastHash) {
		return fmt.Errorf("the entry after %d no longer links to the last one archived; the chain "+
			"changed since the archive was written, and nothing has been removed", a.ThroughID)
	}
	if err := Write(ctx, tx, Event{Type: ArchiveEvent, Detail: map[string]any{
		"declared_by": declaredBy,
		"before":      a.Before.UTC().Format(time.RFC3339),
		"first_id":    a.FirstID,
		"through_id":  a.ThroughID,
		"entries":     a.Entries,
		"first_prev":  hex.EncodeToString(a.FirstPrev),
		"last_hash":   hex.EncodeToString(a.LastHash),
		"sha256":      a.SHA256,
	}}); err != nil {
		return fmt.Errorf("recording the archive: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM core.audit_events WHERE id <= $1`, a.ThroughID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != a.Entries {
		return fmt.Errorf("%d entries up to %d are in the trail now and %d were archived; nothing "+
			"has been removed", tag.RowsAffected(), a.ThroughID, a.Entries)
	}
	return nil
}

// archiveAnchor is where the trail left in the database starts: the latest
// archive's last hash and last entry, or nothing when none has been made.
func archiveAnchor(ctx context.Context, tx pgx.Tx) (lastHash []byte, through int64, err error) {
	var detail map[string]any
	err = tx.QueryRow(ctx, `SELECT detail FROM core.audit_events WHERE event_type = $1
		ORDER BY id DESC LIMIT 1`, ArchiveEvent).Scan(&detail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	h, _ := detail["last_hash"].(string)
	lastHash, err = hex.DecodeString(h)
	if err != nil {
		return nil, 0, fmt.Errorf("the archive record's last hash is not hex: %w", err)
	}
	n, _ := detail["through_id"].(float64)
	return lastHash, int64(n), nil
}

// FileVerification is what an archive file proves on its own.
type FileVerification struct {
	Entries            int64
	FirstID, LastID    int64
	FirstPrev          []byte
	LastHash           []byte
	SHA256             string
	BrokenAt           int64
	PreviousArchiveSum string
}

// VerifyArchiveFile checks an archive file with nothing but the file: every
// entry's hash from its columns, and every link to the entry before it. It
// also reports the SHA-256 of the archive before, when the file holds that
// archive's record.
func VerifyArchiveFile(r io.Reader) (*FileVerification, error) {
	sum := sha256.New()
	cr := csv.NewReader(io.TeeReader(r, sum))
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading the header: %w", err)
	}
	if strings.Join(head, ",") != strings.Join(archiveHeader, ",") {
		return nil, fmt.Errorf("this is not an archive file: its header is %q", strings.Join(head, ","))
	}
	v := &FileVerification{}
	var expectedPrev []byte
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		id, err := strconv.ParseInt(rec[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("an id is not a number: %q", rec[0])
		}
		at, err := time.Parse(time.RFC3339Nano, rec[1])
		if err != nil {
			return nil, fmt.Errorf("entry %d: occurred_at %q: %w", id, rec[1], err)
		}
		prev, perr := hex.DecodeString(rec[11])
		entry, eerr := hex.DecodeString(rec[12])
		version, verr := strconv.Atoi(rec[13])
		if perr != nil || eerr != nil || verr != nil {
			return nil, fmt.Errorf("entry %d: a hash or the hash version does not parse", id)
		}
		// Read back to be hashed, never written: filled as Verify's Scan fills it.
		var e Event
		e.OccurredAt, e.OrgID, e.SubjectID, e.ActorID = at, rec[3], rec[4], rec[5]
		e.ClientID, e.AdminTokenID, e.CorrelationID, e.Retention = rec[6], rec[7], rec[8], rec[9]
		e.Type = rec[2]
		if v.Entries == 0 {
			v.FirstID, v.FirstPrev, expectedPrev = id, prev, prev
		}
		v.Entries++
		v.LastID, v.LastHash = id, entry
		if v.BrokenAt == 0 && (!bytes.Equal(prev, expectedPrev) || !bytes.Equal(hashFor(version, prev, e, rec[10]), entry)) {
			v.BrokenAt = id
		}
		expectedPrev = entry
		if e.Type == ArchiveEvent {
			if s, ok := archiveSum(rec[10]); ok {
				v.PreviousArchiveSum = s
			}
		}
	}
	v.SHA256 = hex.EncodeToString(sum.Sum(nil))
	return v, nil
}

// archiveSum is the file hash an archive record names.
func archiveSum(detail string) (string, bool) {
	var d struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal([]byte(detail), &d) != nil || d.SHA256 == "" {
		return "", false
	}
	return d.SHA256, true
}
