package audit

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is what a detached record is written through: anything that begins a transaction and
// answers a query outside one, as a pool does.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Detached writes records that are not part of another transaction, each committed before
// its Write returns, as a transaction of its own would have it. The records that arrive
// while one group is being appended wait for it, as they would have waited on the chain's
// lock, and are then appended together: one transaction, one lock, one statement, one
// commit (E.32).
//
// The chain's lock is held across the commit, so one record a transaction let through one
// commit's worth at a time, whatever the number of writers: 2,190 a second at sixteen, on
// the machine whose plain inserts reached 17,670, and a revocation, an exchange or a
// backchannel request each waited on it. The chain is the chain it was. Its records are
// appended in the order they joined, each hashed after the one before it, by the same
// function under the same lock, and a record is no more committed when it is answered than
// it was: its Write returns once its group's commit has.
//
// A record whose group cannot be written is written again on its own, so one that would
// fail fails alone and takes no other request's record with it.
type Detached struct {
	mu sync.Mutex
	// last is the group nobody has started after, while any is waiting or in flight.
	last *detachedGroup
}

// detachedGroup is records appended by one statement.
type detachedGroup struct {
	records []record
	open    bool          // taking records; closed when its appending begins
	turn    chan struct{} // closed when the group before it is written
	done    chan struct{} // closed when this one is
	after   *detachedGroup
	errs    []error
}

// maxDetachedGroup bounds a group, so no one statement holds the chain's lock over an
// unbounded number of rows; arrivals past it wait in the group after.
const maxDetachedGroup = 64

// detachedTimeout bounds a group's transaction, which no single request owns.
const detachedTimeout = 10 * time.Second

// NewDetached returns a writer with nothing in flight.
func NewDetached() *Detached { return &Detached{} }

// Write appends e in a transaction of its own through db, and returns once it is committed.
// What e takes from its request (who acted, when) is taken here, from ctx, before it waits.
// Every caller passes the same database; the group's first record's is the one written
// through. A nil Detached writes each record alone.
func (d *Detached) Write(ctx context.Context, db DB, e Event) error {
	if d == nil {
		return writeAlone(ctx, db, e)
	}
	e, err := prepare(ctx, e)
	if err != nil {
		return err
	}
	r, err := canonical(ctx, db, e)
	if err != nil {
		return err
	}

	d.mu.Lock()
	g, sends := d.last, false
	switch {
	case g == nil:
		g = &detachedGroup{open: true, turn: nobodyAhead, done: make(chan struct{})}
		d.last = g
		sends = true
	case !g.open || len(g.records) >= maxDetachedGroup:
		next := &detachedGroup{open: true, turn: make(chan struct{}), done: make(chan struct{})}
		g.after = next
		d.last = next
		g = next
		sends = true
	}
	mine := len(g.records)
	g.records = append(g.records, r)
	d.mu.Unlock()

	if sends {
		d.send(ctx, db, g)
	} else {
		<-g.done
	}
	return g.errs[mine]
}

var nobodyAhead = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// send waits for the group ahead, closes g to newcomers and writes it. Whoever arrives
// meanwhile joins the group after, which this hands its turn to.
func (d *Detached) send(ctx context.Context, db DB, g *detachedGroup) {
	<-g.turn
	d.mu.Lock()
	g.open = false
	rs := g.records
	d.mu.Unlock()

	g.errs = make([]error, len(rs))
	defer func() {
		close(g.done)
		d.mu.Lock()
		if g.after != nil {
			close(g.after.turn)
		} else {
			d.last = nil
		}
		d.mu.Unlock()
	}()
	// Its own request going away does not take the others' records with it, and a
	// transaction that does not answer is given up on, as every request's is.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	defer cancel()
	atCommit, err := commitRecords(wctx, db, rs)
	// Again one by one only when nothing was committed. A commit that failed may have
	// committed all the same, and writing its records again would record each twice.
	if err == nil || atCommit || len(rs) == 1 {
		for i := range g.errs {
			g.errs[i] = err
		}
		return
	}
	for i := range rs {
		_, g.errs[i] = commitRecords(wctx, db, rs[i:i+1])
	}
}

// commitRecords appends rs in a transaction of their own and commits it, saying whether
// what failed was the commit.
func commitRecords(ctx context.Context, db DB, rs []record) (atCommit bool, err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, r := range rs {
		fanOut(ctx, tx, r)
	}
	if err := appendRecords(ctx, tx, rs, hashVersion); err != nil {
		return false, err
	}
	if observe != nil {
		for _, r := range rs {
			observe(r.e)
		}
	}
	return true, tx.Commit(ctx)
}

// writeAlone is a record in a transaction of its own, written by nobody else's.
func writeAlone(ctx context.Context, db DB, e Event) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := Write(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// waiting is how many records have joined the last group while it waits its turn, for a
// test.
func (d *Detached) waiting() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if g := d.last; g != nil && g.open {
		return len(g.records)
	}
	return 0
}
