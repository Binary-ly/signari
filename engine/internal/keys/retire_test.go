package keys

import (
	"testing"
	"time"
)

// Retirement is the step the state machine documented from the first commit and
// nobody implemented: `next -> active -> passive -> removed`, with
// MinPassiveBeforeRetire declared and never read. These tests pin the parts that
// decide whether a key leaves the published set, because every mistake available
// here is silent -- a key retired early breaks tokens at a verifier we do not
// run, and a key never retired just grows the JWKS until somebody notices.

func passiveKey(t *testing.T, demotedAt time.Time) Key {
	t.Helper()
	k, err := Generate("k-passive", ES256)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := WithState(k, StatePassive)
	if err != nil {
		t.Fatal(err)
	}
	return withDemotedAt(moved, demotedAt)
}

func setAt(t *testing.T, now time.Time, ks ...Key) *Set {
	t.Helper()
	s, err := NewSet(ks...)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	return s
}

func TestAKeyRetiresOnceItsDwellHasPassed(t *testing.T) {
	now := time.Now().UTC()
	k := passiveKey(t, now.Add(-25*time.Hour))
	s := setAt(t, now, k)

	ok, wait := s.CanRetire(k, MinPassiveBeforeRetire)
	if !ok {
		t.Fatalf("a key demoted 25 hours ago is not retirable with a 24h dwell (wait %s)", wait)
	}
}

// The boundary is inclusive, and it is inclusive for a reason the doctor already
// wrote down: a demoted key never signs again, so anything it signed at T <= D
// has expired by D+dwell. At exactly D+dwell the key was published at every
// instant one of its tokens was valid.
func TestTheDwellBoundaryIsInclusive(t *testing.T) {
	now := time.Now().UTC()
	k := passiveKey(t, now.Add(-MinPassiveBeforeRetire))
	if ok, _ := setAt(t, now, k).CanRetire(k, MinPassiveBeforeRetire); !ok {
		t.Error("a key demoted exactly one dwell ago was refused; the boundary is exclusive")
	}

	just := passiveKey(t, now.Add(-MinPassiveBeforeRetire+time.Second))
	ok, wait := setAt(t, now, just).CanRetire(just, MinPassiveBeforeRetire)
	if ok {
		t.Error("a key one second short of its dwell was retired")
	}
	if wait != time.Second {
		t.Errorf("remaining wait = %s, want 1s", wait)
	}
}

// The property that turns a missing timestamp into a deleted key if it is got
// wrong. A zero time is 1 January year 1; treated as a demotion instant it is
// always more than any dwell ago, so the naive comparison retires the key
// immediately -- and it does so for exactly the rows where the history is
// unknown, which are the ones least safe to act on.
func TestAPassiveKeyWithNoDemotionTimeIsNeverRetired(t *testing.T) {
	now := time.Now().UTC()
	k := passiveKey(t, time.Time{})
	if ok, _ := setAt(t, now, k).CanRetire(k, MinPassiveBeforeRetire); ok {
		t.Fatal("a passive key with no demotion time was judged retirable; " +
			"a zero timestamp must not read as 'demoted long ago'")
	}
}

// Only passive keys retire. An active key leaving the JWKS takes every token it
// is currently signing with it.
func TestOnlyPassiveKeysRetire(t *testing.T) {
	now := time.Now().UTC()
	long := now.Add(-1000 * time.Hour)
	for _, st := range []State{StateNext, StateActive} {
		k, err := Generate("k-"+string(st), ES256)
		if err != nil {
			t.Fatal(err)
		}
		moved, err := WithState(k, st)
		if err != nil {
			t.Fatal(err)
		}
		moved = withDemotedAt(moved, long)
		if ok, _ := setAt(t, now, moved).CanRetire(moved, MinPassiveBeforeRetire); ok {
			t.Errorf("a %s key was judged retirable", st)
		}
	}
}

// A longer dwell must actually hold the key back. Without this the whole
// credential-lifetime calculation could be computed correctly and then ignored.
func TestALongerDwellHoldsTheKey(t *testing.T) {
	now := time.Now().UTC()
	k := passiveKey(t, now.Add(-48*time.Hour))
	s := setAt(t, now, k)

	if ok, _ := s.CanRetire(k, MinPassiveBeforeRetire); !ok {
		t.Fatal("48 hours passed a 24h dwell check; this test is not measuring what it thinks")
	}
	ok, wait := s.CanRetire(k, 90*24*time.Hour)
	if ok {
		t.Fatal("a key demoted 48 hours ago was retired under a 90-day dwell")
	}
	if want := 88 * 24 * time.Hour; wait != want {
		t.Errorf("remaining wait = %s, want %s", wait, want)
	}
}

// WithState must carry the demotion stamp across a transition. If it drops it,
// the key reads as never-demoted, CanRetire refuses forever, and nothing fails
// loudly -- keys simply accumulate.
func TestATransitionKeepsTheDemotionStamp(t *testing.T) {
	at := time.Now().UTC().Add(-30 * time.Hour)
	k := passiveKey(t, at)

	back, err := WithState(k, StateActive)
	if err != nil {
		t.Fatal(err)
	}
	if !back.DemotedAt().Equal(at) {
		t.Errorf("demotion stamp after transition = %v, want %v", back.DemotedAt(), at)
	}
}

// Retirement is not a Set transition: a retired key is never a member of a Set,
// so producing one would only make a value whose only correct use is not to use it.
func TestWithStateRefusesRetirement(t *testing.T) {
	k := passiveKey(t, time.Now().UTC())
	if _, err := WithState(k, StateRetired); err == nil {
		t.Fatal("WithState produced a retired key")
	}
}
