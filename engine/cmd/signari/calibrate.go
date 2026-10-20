package main

import (
	"fmt"
	"io"
	"time"

	"signari.dev/engine/internal/passwords"
)

// passwordsCalibrate measures Argon2id on this host and says what
// SIGNARI_ARGON2_* to set so one hash takes about target (4.08).
//
// The cost was the OWASP minimum on every host. On a fast server that is a few
// milliseconds a guess, far cheaper than the hardware could afford; the right
// numbers depend on the machine, so they are measured here, on it.
//
// Memory is preferred over iterations, since memory is what guessing hardware
// is short of: for each size the fewest iterations reaching target are found,
// and the largest size that lands within half as much again, and still leaves
// the shared 512 MiB budget room for four at once, is recommended.
func passwordsCalibrate(out io.Writer, target time.Duration) error {
	if target < 10*time.Millisecond || target > 5*time.Second {
		return fmt.Errorf("-target from 10ms to 5s")
	}
	floor, ceiling := passwords.Bounds()
	fmt.Fprintf(out, "Argon2id on this host, aiming at %s a hash:\n\n", target)
	fmt.Fprintf(out, "  %8s  %10s  %9s  %s\n", "memory", "iterations", "time", "at once in 512 MiB")

	var best *passwords.Params
	for _, mib := range []uint32{19, 32, 46, 64, 128, 256} {
		if mib*1024 < floor.MemoryKiB || mib*1024 > ceiling.MemoryKiB {
			continue
		}
		p := passwords.Params{MemoryKiB: mib * 1024, Time: floor.Time, Threads: floor.Threads}
		took := passwords.Measure(p)
		for took < target && p.Time < ceiling.Time {
			p.Time++
			took = passwords.Measure(p)
		}
		atOnce := passwords.MemoryBudgetMiB / int(mib)
		fmt.Fprintf(out, "  %5d MiB  %10d  %9s  %d\n", mib, p.Time, took.Round(time.Millisecond), atOnce)
		if took >= target && took <= target*3/2 && atOnce >= 4 {
			chosen := p
			best = &chosen
		}
	}
	if best == nil {
		fmt.Fprintf(out, "\nNo size reached %s within %d iterations and four at once; the "+
			"defaults stand. A shorter -target, or a slower host, gives a recommendation.\n",
			target, ceiling.Time)
		return nil
	}
	fmt.Fprintf(out, "\nSet:\n\n  SIGNARI_ARGON2_MEMORY_MIB=%d\n  SIGNARI_ARGON2_ITERATIONS=%d\n",
		best.MemoryKiB/1024, best.Time)
	fmt.Fprintln(out, "\nEach password moves to it at its next sign-in. A sign-in costs the person")
	fmt.Fprintln(out, "this long once, and a guesser this long per guess, per core.")
	return nil
}
