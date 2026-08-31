package federation

import "fmt"

// Outcome is what should happen with an external identity.
type Outcome int

const (
	// SignIn: we have seen this external subject before and know whose it is.
	SignIn Outcome = iota
	// CreateUser: unknown subject, and this provider may create accounts.
	CreateUser
	// LinkToCurrentUser: unknown subject, and a user is signed in locally and
	// asked for this link. The only path that ever attaches an external account
	// to an existing local one.
	LinkToCurrentUser
	// RequireLocalSignIn: unknown subject, an existing local account looks like
	// the same person, and they have not proved they control it.
	RequireLocalSignIn
	// Refuse: nothing may be done.
	Refuse
)

func (o Outcome) String() string {
	switch o {
	case SignIn:
		return "sign in"
	case CreateUser:
		return "create user"
	case LinkToCurrentUser:
		return "link to the signed-in user"
	case RequireLocalSignIn:
		return "require a local sign-in first"
	default:
		return "refuse"
	}
}

// ExternalIdentity is what the provider told us about the person.
type ExternalIdentity struct {
	// Subject is the provider's stable identifier. The ONLY value matched on.
	Subject string
	Email   string
	// EmailVerified is the provider's claim, believed only as far as the
	// provider's policy allows -- see Policy.RequireVerifiedEmail.
	EmailVerified bool
	Name          string

	// RawClaims is the verified upstream payload, for operator-configured
	// attribute mapping only.
	//
	// Deliberately NOT a decoded map. A map invites `ext.Claims["role"]` at some
	// future call site, and the moment a decision reads an upstream claim
	// directly, the provider is deciding local authorization. Keeping it as
	// bytes means the only way to reach a claim is to ask for one by name
	// through the mapping, which is where the operator's consent to trust it
	// lives.
	//
	// Nil for providers that supply no id_token payload, which is not an error:
	// an attribute mapping over a provider that returns nothing simply maps
	// nothing.
	RawClaims []byte
}

// Policy is the provider's configuration.
//
// Note what is absent: there is no "match by email" switch. It is not
// configurable because no setting of it is safe.
type Policy struct {
	AllowSignup          bool
	AllowLinking         bool
	RequireVerifiedEmail bool
	// TrustsEmailVerification records whether this provider's verified flag is
	// worth anything. GitHub will return an address the user never confirmed
	// unless you ask specifically for verified ones.
	TrustsEmailVerification bool
}

// Context is what we already know locally.
type Context struct {
	// ExistingLinkUserID is the local user already linked to this external
	// subject, if any. Set from a lookup on (provider, subject) alone.
	ExistingLinkUserID string
	// LocalUserWithSameEmail is a local account whose address matches. Present
	// ONLY so the decision can refuse helpfully -- it is never a reason to link.
	LocalUserWithSameEmail string
	// CurrentUserID is whoever is signed in locally right now, if anybody.
	CurrentUserID string
	// LinkRequested is true when this flow was started from an account page by a
	// signed-in user asking to add this provider. Read from server-side state
	// created when the flow began, never from a request parameter.
	LinkRequested bool
}

// Decision is the outcome plus the reason, which is shown to the user.
type Decision struct {
	Outcome Outcome
	UserID  string
	// Reason is written for the person reading it on a sign-in page, not for a
	// log. Somebody stuck here needs to know what to do next.
	Reason string
}

// Decide works out what to do with an external identity.
//
// Pure: no database, no clock, no network. Every takeover scenario is therefore
// a table entry in the tests rather than an integration test nobody writes.
func Decide(ext ExternalIdentity, p Policy, c Context) (Decision, error) {
	if ext.Subject == "" {
		// Without a stable subject there is nothing to match on, and matching on
		// what is left -- the email -- is the bug this package exists to avoid.
		return Decision{Outcome: Refuse}, fmt.Errorf("the provider returned no subject " +
			"identifier, so this account cannot be identified safely")
	}

	// 1. Known external account. The only automatic sign-in path.
	if c.ExistingLinkUserID != "" {
		return Decision{Outcome: SignIn, UserID: c.ExistingLinkUserID}, nil
	}

	// 2. A signed-in user explicitly asked to add this provider. This is the
	//    only way an external account is ever attached to an existing local one,
	//    and it works because they have already proved they control it.
	if c.LinkRequested && c.CurrentUserID != "" {
		if !p.AllowLinking {
			return Decision{Outcome: Refuse,
				Reason: "This provider is not configured to be linked to existing accounts."}, nil
		}
		return Decision{Outcome: LinkToCurrentUser, UserID: c.CurrentUserID}, nil
	}

	// 3. Unknown external account, and a local account shares the address.
	//
	//    THE decision. The tempting move is to link them -- same email, surely
	//    the same person. It is exactly the takeover. We refuse and tell the
	//    user how to do it safely, which costs them one sign-in.
	if c.LocalUserWithSameEmail != "" {
		if !p.AllowLinking {
			return Decision{Outcome: Refuse,
				Reason: "An account already exists with this email address, and this " +
					"provider cannot be linked to existing accounts."}, nil
		}
		return Decision{
			Outcome: RequireLocalSignIn,
			Reason: "An account already exists with this email address. Sign in to it " +
				"first, then add this provider from your account settings. We do not " +
				"link accounts on a matching email alone, because anyone able to " +
				"create an account elsewhere with your address could otherwise take " +
				"over yours.",
		}, nil
	}

	// 4. Genuinely new person.
	if !p.AllowSignup {
		return Decision{Outcome: Refuse,
			Reason: "This provider cannot be used to create new accounts. Ask an " +
				"administrator for an account first, then add this provider from your " +
				"account settings."}, nil
	}
	if p.RequireVerifiedEmail && !usableEmail(ext, p) {
		return Decision{Outcome: Refuse,
			Reason: "This provider did not confirm that your email address is verified. " +
				"Verify it with the provider and try again."}, nil
	}
	return Decision{Outcome: CreateUser}, nil
}

// usableEmail reports whether the address may be recorded as verified.
//
// Two conditions, not one. The provider must SAY it is verified, and the
// provider must be one whose saying so means anything -- some hand back an
// address the user never confirmed, and taking that at face value reintroduces
// the whole problem one level down.
func usableEmail(ext ExternalIdentity, p Policy) bool {
	if ext.Email == "" {
		return false
	}
	if !p.TrustsEmailVerification {
		return false
	}
	return ext.EmailVerified
}

// EmailToRecord returns the address to store, and whether to mark it verified.
//
// An address we are not sure about is still worth keeping for display and
// support -- it is simply never recorded as verified, and never used to find an
// account.
func EmailToRecord(ext ExternalIdentity, p Policy) (email string, verified bool) {
	return ext.Email, usableEmail(ext, p)
}
