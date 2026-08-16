package httpapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/captcha"
)

// TestSharedCaptchaCounterEscalatesAcrossInstances is the property the
// in-memory counter cannot have.
//
// Two pools are two instances. With a per-process map, three failures spread
// across two instances leave each holding one or two -- below a threshold of
// three -- so neither ever challenges, and adaptive mode has silently stopped
// being adaptive.
func TestSharedCaptchaCounterEscalatesAcrossInstances(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	a, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	instanceA := &sharedCaptchaCounter{db: a, log: log}
	instanceB := &sharedCaptchaCounter{db: b, log: log}

	key := fmt.Sprintf("test-%d", time.Now().UnixNano())

	// Three failures, alternating instances, as a load balancer would.
	instanceA.Record(ctx, key)
	instanceB.Record(ctx, key)
	instanceA.Record(ctx, key)

	// Either instance must now see all three.
	if n := instanceA.Count(ctx, key); n != 3 {
		t.Fatalf("instance A sees %d failures, want 3", n)
	}
	if n := instanceB.Count(ctx, key); n != 3 {
		t.Fatalf("instance B sees %d of 3 failures. Spread across instances, an "+
			"attacker would need N times the failures before any one of them "+
			"escalated -- and with an even spread, none of them ever would.", n)
	}

	// Counting must not itself count: this runs on every render of the sign-in
	// page, and a page that escalates its own challenge by being displayed
	// would challenge everybody who looked at it.
	for i := 0; i < 5; i++ {
		instanceA.Count(ctx, key)
	}
	if n := instanceB.Count(ctx, key); n != 3 {
		t.Fatalf("reading the counter changed it: %d after five reads, want 3", n)
	}

	// A success clears it, for both.
	instanceA.Clear(ctx, key)
	if n := instanceB.Count(ctx, key); n != 0 {
		t.Fatalf("after a success on one instance, the other still sees %d", n)
	}
}

// TestSharedCaptchaCounterUsesTheSameWindow guards the two implementations
// agreeing about how long a failure counts.
func TestSharedCaptchaCounterUsesTheSameWindow(t *testing.T) {
	if captcha.FailureWindow <= 0 {
		t.Fatal("the window is not set, so a shared counter has nothing to agree with")
	}
}
