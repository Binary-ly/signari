package posture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func chromeAgainst(t *testing.T, reply map[string]any, customerID string) *Chrome {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "challenge:generate") {
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "c-123"})
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return &Chrome{
		BaseURL:    srv.URL,
		CustomerID: customerID,
		Token:      func(context.Context) (string, error) { return "t", nil },
	}
}

func TestAManagedCompliantDevice(t *testing.T) {
	c := chromeAgainst(t, map[string]any{
		"customerId":    "C01abc",
		"keyTrustLevel": "CHROME_BROWSER_HW_KEY",
		"deviceSignal": map[string]any{
			"deviceEnrollmentDomain": "acme.com",
			"diskEncrypted":          "ENCRYPTED",
			"screenLockSecured":      "SECURED",
		},
	}, "C01abc")

	st, err := c.Verify(context.Background(), "signed-response")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Managed || !st.Compliant {
		t.Errorf("managed=%v compliant=%v, want both true", st.Managed, st.Compliant)
	}
	if st.Source != "chrome" {
		t.Errorf("source = %q", st.Source)
	}
}

// TestUnknownSignalsAreNotCompliance is the one that matters.
//
// Google reports posture as strings, and "UNKNOWN" means the device did not
// say — usually because the policy has not reached it. Reading silence as
// compliance is how an unencrypted laptop passes a disk-encryption requirement.
func TestUnknownSignalsAreNotCompliance(t *testing.T) {
	c := chromeAgainst(t, map[string]any{
		"customerId":    "C01abc",
		"keyTrustLevel": "CHROME_BROWSER_HW_KEY",
		"deviceSignal": map[string]any{
			"deviceEnrollmentDomain": "acme.com",
			"diskEncrypted":          "UNKNOWN",
			"screenLockSecured":      "SECURED",
		},
	}, "C01abc")

	st, err := c.Verify(context.Background(), "signed-response")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Managed {
		t.Error("the device is enrolled, so it is managed")
	}
	if st.Compliant {
		t.Error("a device that did not report disk encryption was treated as " +
			"compliant; silence is not compliance")
	}
}

// A device managed by a DIFFERENT Workspace customer is not our device.
// Without this "managed" means "managed by somebody", which is not a property.
func TestAnotherCustomersDeviceIsRefused(t *testing.T) {
	c := chromeAgainst(t, map[string]any{
		"customerId":    "C09other",
		"keyTrustLevel": "CHROME_BROWSER_HW_KEY",
		"deviceSignal":  map[string]any{"deviceEnrollmentDomain": "other.com"},
	}, "C01abc")

	st, err := c.Verify(context.Background(), "signed-response")
	if err == nil {
		t.Fatal("a device from another Workspace customer was accepted")
	}
	if st.Managed {
		t.Error("it must not be reported as managed")
	}
}

// A software key proves a browser profile, not a device.
func TestASoftwareKeyIsNotADevice(t *testing.T) {
	c := chromeAgainst(t, map[string]any{
		"customerId":    "C01abc",
		"keyTrustLevel": "CHROME_BROWSER_OS_KEY",
		"deviceSignal": map[string]any{
			"deviceEnrollmentDomain": "acme.com",
			"diskEncrypted":          "ENCRYPTED",
			"screenLockSecured":      "SECURED",
		},
	}, "C01abc")

	st, err := c.Verify(context.Background(), "signed-response")
	if err != nil {
		t.Fatal(err)
	}
	if st.Managed || st.Compliant {
		t.Error("a key that is not hardware-attested proves a browser profile " +
			"rather than a device")
	}
	if st.Source != "chrome:software-key" {
		t.Errorf("the source should say why: %q", st.Source)
	}
}

// No response at all is "we had no way to tell", not "unmanaged".
func TestNoResponseIsNotAVerdict(t *testing.T) {
	c := chromeAgainst(t, map[string]any{}, "C01abc")
	st, err := c.Verify(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "none" {
		t.Errorf("source = %q, want \"none\": we looked at nothing", st.Source)
	}
}

func TestChallengeComesFromGoogle(t *testing.T) {
	c := chromeAgainst(t, map[string]any{}, "C01abc")
	ch, err := c.Challenge(context.Background())
	if err != nil || ch != "c-123" {
		t.Fatalf("challenge = %q, %v", ch, err)
	}
}

// `osFirewall` was decoded from Google's response and left out of the verdict,
// under a comment claiming compliance meant "the posture signals Google reports
// are all satisfied". It did not: a device with its host firewall off was
// reported compliant by a rule that said it checked everything reported.
//
// Adding it unconditionally would have been the wrong fix. Disk encryption and
// screen lock are near-universal on managed fleets; the host firewall is not,
// and plenty of managed estates run with it off deliberately behind a network
// the operator already controls. Turning it on for everyone would lock those
// users out of an identity provider to enforce a policy their own
// administrators never set.
//
// So it is opt-in — and the point of these two tests is that both answers are
// now reachable. Before, only one was, and not by choice.
func TestTheFirewallSignalIsIgnoredUnlessRequired(t *testing.T) {
	reply := map[string]any{
		"customerId":    "C01abc",
		"keyTrustLevel": "CHROME_BROWSER_HW_KEY",
		"deviceSignal": map[string]any{
			"deviceEnrollmentDomain": "acme.com",
			"diskEncrypted":          "ENCRYPTED",
			"screenLockSecured":      "SECURED",
			"osFirewall":             "DISABLED",
		},
	}
	c := chromeAgainst(t, reply, "C01abc")
	st, err := c.Verify(context.Background(), "signed-response")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Compliant {
		t.Errorf("a device with the firewall off was reported non-compliant on a "+
			"deployment that never asked for the firewall signal; that is a lockout "+
			"nobody configured: %+v", st)
	}
}

func TestARequiredFirewallIsEnforced(t *testing.T) {
	base := map[string]any{
		"deviceEnrollmentDomain": "acme.com",
		"diskEncrypted":          "ENCRYPTED",
		"screenLockSecured":      "SECURED",
	}
	for _, tc := range []struct {
		name     string
		firewall any
		want     bool
	}{
		{"enabled", "ENABLED", true},
		{"disabled", "DISABLED", false},
		// Absent is NOT satisfied — the same rule the other signals follow. A
		// policy that has not reached a device reports nothing, and reading
		// silence as compliance is how the requirement quietly stops applying.
		{"absent", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := map[string]any{}
			for k, v := range base {
				signal[k] = v
			}
			if tc.firewall != nil {
				signal["osFirewall"] = tc.firewall
			}
			c := chromeAgainst(t, map[string]any{
				"customerId":    "C01abc",
				"keyTrustLevel": "CHROME_BROWSER_HW_KEY",
				"deviceSignal":  signal,
			}, "C01abc")
			c.RequireOSFirewall = true

			st, err := c.Verify(context.Background(), "signed-response")
			if err != nil {
				t.Fatal(err)
			}
			if st.Compliant != tc.want {
				t.Errorf("firewall=%v: compliant=%v, want %v", tc.firewall, st.Compliant, tc.want)
			}
			if !st.Managed {
				t.Errorf("the device stopped being MANAGED, not just non-compliant; "+
					"the firewall is a compliance signal, not an enrollment one: %+v", st)
			}
		})
	}
}
