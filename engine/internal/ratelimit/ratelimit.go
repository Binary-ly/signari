// Package ratelimit is the token bucket this engine throttles with.
//
// It lived as an unexported type inside internal/httpapi, which was fine while
// the protocol server was the only thing that needed one. The admin write API
// needed the same thing, and the choice was to copy fifteen lines or to move
// them. This codebase has been bitten enough times by two implementations of one
// rule -- three copies of JWT header hardening, three of the "aud is a string or
// an array" decoder -- that copying a limiter to a second package was not
// tempting.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket is a token bucket. Safe for concurrent use.
type Bucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
	// now is injectable so tests can advance time rather than sleep through it.
	now func() time.Time
}

// New builds a bucket that refills at ratePerSec and holds at most capacity.
//
// It starts FULL. A server that restarts under load should serve the burst it
// was built to serve rather than throttle everybody for the first few seconds
// because its buckets began empty.
func New(ratePerSec, capacity float64) *Bucket {
	b := &Bucket{tokens: capacity, capacity: capacity, rate: ratePerSec}
	b.last = b.clock()
	return b
}

func (b *Bucket) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// Allow consumes one token and reports whether there was one to consume.
func (b *Bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Keyed limits each caller separately.
//
// # Why a global bucket is not enough on its own
//
// One bucket shared by every caller means the noisiest one decides what everybody
// else gets. That is already a known problem elsewhere in this engine: the login
// limiter is a single global bucket, so one attacker can lock out every user at
// once. It is the wrong shape wherever callers are distinguishable, and on an
// administrative API they are -- each request arrives with an authenticated token.
//
// # Why eviction is safe here, which is not generally true
//
// Evicting an entry resets that key to a full bucket, which is MORE permissive.
// Anywhere the key is attacker-chosen, that is an attack: flood with fresh keys
// until your own throttled entry is evicted, then continue. It is safe in this
// use because the key is an authenticated identity -- a token that had to exist,
// be unrevoked and be unexpired before the limiter is ever consulted. Key
// cardinality is therefore bounded by how many credentials an operator issued,
// not by how many an attacker can invent.
//
// A caller keying this on anything unauthenticated must not rely on that.
type Keyed struct {
	mu       sync.Mutex
	buckets  map[string]*Bucket
	rate     float64
	capacity float64
	max      int
	now      func() time.Time
}

// NewKeyed builds a per-key limiter holding at most max distinct keys.
func NewKeyed(ratePerSec, capacity float64, max int) *Keyed {
	if max < 1 {
		max = 1
	}
	return &Keyed{
		buckets:  make(map[string]*Bucket),
		rate:     ratePerSec,
		capacity: capacity,
		max:      max,
	}
}

// Allow consumes one of this key's tokens.
func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	b := k.buckets[key]
	if b == nil {
		if len(k.buckets) >= k.max {
			k.evictOneLocked()
		}
		b = New(k.rate, k.capacity)
		b.now = k.now
		if k.now != nil {
			b.last = k.now()
		}
		k.buckets[key] = b
	}
	k.mu.Unlock()
	// Outside the map lock: Allow takes the bucket's own lock, and holding both
	// would serialise every caller behind whichever one is being throttled.
	return b.Allow()
}

// evictOneLocked drops the entry closest to full. Caller holds k.mu.
//
// Deliberately not the oldest or a random one. The fullest bucket is the one that
// has consumed least, so it is both the least informative to keep and the least
// valuable to an attacker to displace -- evicting a throttled entry would hand
// its key a fresh allowance, which is the one outcome eviction must not favour.
func (k *Keyed) evictOneLocked() {
	var worst string
	var most float64 = -1
	for key, b := range k.buckets {
		b.mu.Lock()
		t := b.tokens
		b.mu.Unlock()
		if t > most {
			worst, most = key, t
		}
	}
	if worst != "" {
		delete(k.buckets, worst)
	}
}

// Len reports how many keys are held. For tests and diagnostics.
func (k *Keyed) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}
