// Package provision writes users OUT to a downstream directory.
//
// # One interface, three implementations
//
// SCIM is the standard and covers most targets. Google Workspace and Microsoft
// Entra ID do not accept SCIM as servers -- you provision into them through
// their own APIs -- so each gets an implementation of the same interface, and
// everything above it (the plan, the dry run, the link table, the deactivation
// policy) is shared.
//
// The alternative is a second sync engine per target, which is how the
// deactivation rule ends up meaning something slightly different for Google
// than it does for everything else.
//
// # Free
//
// The comparable connectors elsewhere in this field are the paid tier. There is
// no technical reason for that and no reason for us to copy it: the hard part
// is the reconciliation, which is written once and shared.
package provision

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"signari.dev/engine/internal/directory"
	"signari.dev/engine/internal/scim"
)

// User is a person as a downstream directory sees them.
type User struct {
	// RemoteID is the target's OWN identifier for the record. It is what every
	// update and deactivation addresses.
	//
	// Distinct from ExternalID, and the distinction is worth the extra field:
	// conflating them means a deactivation addressed by our id, which the far
	// end does not recognise, so the call succeeds against nothing.
	RemoteID string
	// ExternalID is Signari's user id, stored on the remote record where the
	// target supports it. It is what makes a re-link possible after somebody
	// renames an account at the far end.
	ExternalID  string
	UserName    string
	DisplayName string
	Email       string
	GivenName   string
	FamilyName  string
	Active      bool
}

// Provisioner is what every target must be able to do.
//
// Deliberately small. Every method here is one a reconciliation loop needs, and
// nothing here is a convenience: a wider interface would be one more thing each
// new target has to get right before it can be used at all.
type Provisioner interface {
	// CreateUser returns the remote identifier.
	CreateUser(ctx context.Context, u User) (string, error)
	// SetActive enables or disables. Never deletes -- see the deactivation
	// policy, which is the caller's decision and not this layer's.
	SetActive(ctx context.Context, remoteID string, active bool) error
	// DeleteUser removes the record, for targets and policies that want it.
	DeleteUser(ctx context.Context, remoteID string) error
	// FindByUserName locates an existing record, so a first sync adopts what is
	// already there instead of creating duplicates.
	FindByUserName(ctx context.Context, userName string) (*User, error)
	// ListUsers reads the far end, for drift detection.
	ListUsers(ctx context.Context, pageSize int) ([]User, error)
}

// Drift is what a reconciliation found.
//
// Two directions, because push-only sync is how a bad filter deprovisions a
// company: it reports what it would change and never what is already wrong at
// the far end.
type Drift struct {
	// ToCreate exist here and not there.
	ToCreate []User
	// ToActivate and ToDeactivate differ in state.
	ToActivate   []User
	ToDeactivate []User
	// Unmanaged exist THERE and not here.
	//
	// Never touched automatically. A directory almost always contains accounts
	// this system did not create -- service accounts, contractors, the founder's
	// original login -- and a sync that removes what it does not recognise is a
	// sync that removes those.
	Unmanaged []User
}

// Summary renders the drift for an operator.
func (d Drift) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  create      %d\n", len(d.ToCreate))
	fmt.Fprintf(&b, "  activate    %d\n", len(d.ToActivate))
	fmt.Fprintf(&b, "  deactivate  %d\n", len(d.ToDeactivate))
	fmt.Fprintf(&b, "  unmanaged   %d  (present at the target, not managed here — untouched)\n",
		len(d.Unmanaged))
	return b.String()
}

// Empty reports whether anything would change.
func (d Drift) Empty() bool {
	return len(d.ToCreate) == 0 && len(d.ToActivate) == 0 && len(d.ToDeactivate) == 0
}

// SafetyLimit refuses a run that would deactivate an implausible share.
//
// A filter that accidentally matches nothing produces a plan to deactivate the
// entire company, and the plan looks exactly like a correct plan for a company
// that has genuinely all left. The limit is what stands between a typo and an
// outage, and it is deliberately not configurable to zero.
const SafetyLimit = 0.25

// CheckSafety refuses a drift that deactivates too much at once.
func CheckSafety(d Drift, managed int) error {
	if managed == 0 || len(d.ToDeactivate) == 0 {
		return nil
	}
	share := float64(len(d.ToDeactivate)) / float64(managed)
	if share <= SafetyLimit {
		return nil
	}
	return fmt.Errorf("this would deactivate %d of %d managed accounts (%.0f%%), "+
		"over the %.0f%% limit. That is what a filter matching nothing looks "+
		"like, and it is indistinguishable from a company that has genuinely "+
		"all left. Re-run with -force if it is really what you want",
		len(d.ToDeactivate), managed, share*100, SafetyLimit*100)
}

// ForTarget returns the provisioner a target needs.
//
// One place decides which API a target speaks, so the sync above it never has
// to know. A target whose kind the engine does not recognise is refused rather
// than defaulted to SCIM: defaulting would send a service account JSON file to
// a SCIM endpoint that does not exist and report a connection error.
func ForTarget(t scim.Target, hc *http.Client) (Provisioner, error) {
	switch t.Kind {
	case "", "scim":
		return SCIM{Client: scim.NewClient(t, hc)}, nil

	case "google":
		creds, err := directory.ParseGoogleCredentials(t.Credentials)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t.Slug, err)
		}
		if t.Impersonate == "" {
			return nil, fmt.Errorf("target %q needs an administrator to impersonate: "+
				"a Google service account with domain-wide delegation does nothing "+
				"without a subject", t.Slug)
		}
		if t.TargetDomain == "" {
			return nil, fmt.Errorf("target %q needs a domain, so new accounts are "+
				"created somewhere rather than nowhere", t.Slug)
		}
		return &Google{
			Creds: creds, Impersonate: t.Impersonate,
			Domain: t.TargetDomain, HTTP: hc,
		}, nil

	case "entra":
		creds, err := directory.ParseEntraCredentials(t.Credentials)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t.Slug, err)
		}
		return &Entra{
			TenantID: creds.TenantID, ClientID: creds.ClientID,
			ClientSecret: creds.ClientSecret, Domain: t.TargetDomain, HTTP: hc,
		}, nil

	default:
		return nil, fmt.Errorf("target %q has kind %q, which this engine does not "+
			"know how to write to", t.Slug, t.Kind)
	}
}
