package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// RateCombiner counts requests against a keyed limit as AllowRate does, in fewer
// statements: the requests that arrive on a key while its statement is in flight wait
// for it, as they would have waited on the row's lock, and are then counted by one
// statement together, which adds their number and returns the count after them (E.23).
// The i-th of n is answered from the count the row had after the i-th, which is the
// answer it would have had alone, so the limit is as exact as it was: every request is
// counted in the shared table before it is answered, the table's count is every request
// made, and nothing is kept here once a key has nothing in flight.
//
// One busy key's tokens took a statement each, one after another on its row, and the
// statement was more than half of what a token cost.
type RateCombiner struct {
	mu   sync.Mutex
	keys map[string]*combinedKey
}

// combinedKey is a key with a statement in flight, and the group waiting for it.
type combinedKey struct {
	next *chargeGroup
}

// chargeGroup is requests counted by one statement.
type chargeGroup struct {
	n    int
	turn chan struct{} // closed when the statement before it has its answer
	done chan struct{} // closed when this one has

	count int
	left  time.Duration
	err   error
}

// NewRateCombiner returns a combiner with nothing in flight.
func NewRateCombiner() *RateCombiner {
	return &RateCombiner{keys: map[string]*combinedKey{}}
}

var nobodyAhead = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// Allow is AllowRate. q is read only by the request whose statement it is, so every
// caller of one key passes the same database. A nil combiner counts each request alone.
func (rc *RateCombiner) Allow(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string, limit int, window time.Duration) (RateResult, error) {
	if rc == nil {
		return AllowRate(ctx, q, key, limit, window)
	}
	if err := usableRate(key, limit, window); err != nil {
		return RateResult{}, err
	}

	rc.mu.Lock()
	k, busy := rc.keys[key]
	var g *chargeGroup
	sends := false
	switch {
	case !busy:
		k = &combinedKey{}
		rc.keys[key] = k
		g = &chargeGroup{turn: nobodyAhead, done: make(chan struct{})}
		sends = true
	case k.next == nil:
		g = &chargeGroup{turn: make(chan struct{}), done: make(chan struct{})}
		k.next = g
		sends = true
	default:
		g = k.next
	}
	g.n++
	mine := g.n
	rc.mu.Unlock()

	if sends {
		rc.send(ctx, q, key, k, g, window)
	} else {
		<-g.done
	}

	res := RateResult{Limit: limit}
	if g.err != nil {
		return res, g.err
	}
	res.Count = g.count - g.n + mine
	res.RetryAfter = g.left
	res.Allowed = res.Count <= limit
	return res, nil
}

// send waits for the statement ahead, closes g to newcomers and counts it. Whoever
// arrives meanwhile forms the next group, which this hands the key to.
func (rc *RateCombiner) send(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string, k *combinedKey, g *chargeGroup, window time.Duration) {
	<-g.turn
	rc.mu.Lock()
	if k.next == g {
		k.next = nil
	}
	n := g.n
	rc.mu.Unlock()

	defer func() {
		close(g.done)
		rc.mu.Lock()
		if k.next != nil {
			close(k.next.turn)
		} else {
			delete(rc.keys, key)
		}
		rc.mu.Unlock()
	}()
	// Its own request going away does not take the others' answer with it, and a
	// statement that does not answer is given up on, as every request's is.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), combinedStatementTimeout)
	defer cancel()
	// Refused unless the statement answers: a group that was never counted is not room.
	g.err = errGroupNotCounted
	g.count, g.left, g.err = chargeRate(sctx, q, key, n, window)
}

// combinedStatementTimeout bounds a statement no single request owns.
const combinedStatementTimeout = 10 * time.Second

var errGroupNotCounted = errors.New("the requests waiting on a rate limit were not counted")
