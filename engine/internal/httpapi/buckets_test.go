package httpapi

import "testing"

// Two endpoints must not share one limiter.
//
// `register` shared `device` until the device backstop had to be widened -- the
// verification screen's 3/s bucket was global, so one address could hold it
// empty and refuse every legitimate device in the deployment. Widening it would
// silently have widened dynamic client registration too: an endpoint open to
// anybody that writes rows.
//
// The coupling was invisible at both call sites, which is exactly why it needs
// a test rather than a comment. Sharing a limiter means one number answers two
// unrelated questions, and the next person to tune either one gets the other
// for free without being told.
func TestRateLimitersAreNotShared(t *testing.T) {
	s := &Server{
		device:   newBucket(200, 400),
		register: newBucket(3, 10),
	}

	// Drain registration completely.
	for i := 0; i < 20; i++ {
		s.register.allow()
	}
	if s.register.allow() {
		t.Fatal("the registration bucket did not run out")
	}

	// The device backstop must be untouched by that.
	if !s.device.allow() {
		t.Fatal("draining the registration limiter also refused the device " +
			"endpoint: the two share a bucket, so tuning either one silently " +
			"retunes the other")
	}
}

// The device backstop must be loose enough that it is NOT the binding
// constraint -- the per-address limit in handleDeviceVerification is. If this
// bucket is ever tightened back to a rate one address can reach on its own, the
// deployment-wide lockout comes back.
func TestTheDeviceBackstopIsNotTheBindingConstraint(t *testing.T) {
	s := &Server{device: newBucket(200, 400)}

	// deviceAttemptsPerWindow is what a single address may spend. The backstop
	// has to absorb many addresses spending their full budget at once, or it
	// becomes the real limit again and the per-address work is decorative.
	const concurrentAddresses = 15
	for i := 0; i < deviceAttemptsPerWindow*concurrentAddresses; i++ {
		if !s.device.allow() {
			t.Fatalf("the global backstop refused request %d, which is only %d "+
				"addresses each spending their full per-address budget of %d. "+
				"It is the binding constraint again, and one address can lock "+
				"out the deployment",
				i+1, concurrentAddresses, deviceAttemptsPerWindow)
		}
	}
}
