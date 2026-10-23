package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
)

// `signari trust-mark ...` -- OpenID Federation 1.0 §7 and §8.4 to §8.6.
//
// Two roles live here and they should not be confused:
//
//   - ISSUING. This entity is an accreditation authority. `issue`, `revoke`,
//     `list` and `delegate` operate on marks we mint and are accountable for.
//   - HOLDING. Somebody else accredited us. `accept` and `drop` control what
//     appears in the `trust_marks` claim of our own Entity Configuration.
//
// The verbs are separate rather than one `add` with a direction flag, because
// the operations differ in what they mean: we can revoke what we issued, and we
// can only stop republishing what we hold.

// trustMarkIssue mints and records a Trust Mark.
func trustMarkIssue(ctx context.Context, conn *pgx.Conn, markType, subject, logoURI,
	ref, delegationFile string, lifetime time.Duration) error {

	root, err := rootKey()
	if err != nil {
		return err
	}
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}

	var delegation string
	if delegationFile != "" {
		b, err := os.ReadFile(delegationFile)
		if err != nil {
			return fmt.Errorf("reading the delegation: %w", err)
		}
		delegation = strings.TrimSpace(string(b))
	}

	// Signed with a federation key (store.SignAsFederationEntity), never the
	// OIDC one.
	signed, tm, err := store.IssueSignedTrustMark(ctx, conn, root, instanceID, issuer, oidfed.TrustMarkParams{
		Subject:    subject,
		Type:       markType,
		Lifetime:   lifetime,
		LogoURI:    logoURI,
		Ref:        ref,
		Delegation: delegation,
	}, time.Now())
	if errors.Is(err, store.ErrNoFederationKey) {
		return fmt.Errorf("%w -- run `signari federation enable` first", err)
	}
	if err != nil {
		return err
	}
	var expires time.Time
	if tm.Expiry != 0 {
		expires = time.Unix(tm.Expiry, 0)
	}

	fmt.Printf("issued %s\n  to     %s\n  by     %s\n", tm.Type, tm.Subject, tm.Issuer)
	if expires.IsZero() {
		// §7.1 permits a mark with no `exp`, and §7.3's expiry step then does
		// nothing -- so the only way anybody learns this was withdrawn is to ask
		// the status endpoint. Worth saying out loud at the moment of issuance,
		// because it is a commitment about how this mark can be undone and it is
		// made by omitting a flag.
		fmt.Println("  expiry none -- readers cannot tell a withdrawn mark from a live " +
			"one without querying the status endpoint (section 7.3)")
	} else {
		fmt.Printf("  expiry %s\n", expires.UTC().Format(time.RFC3339))
	}
	fmt.Printf("\n%s\n", signed)
	return nil
}

// trustMarkRevoke withdraws a Trust Mark.
func trustMarkRevoke(ctx context.Context, conn *pgx.Conn, markType, subject, reason string) error {
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if reason == "" {
		reason = "revoked by an operator"
	}
	if err := store.RevokeTrustMark(ctx, conn, instanceID, markType, subject, reason); err != nil {
		return err
	}
	fmt.Printf("revoked %s for %s\n", markType, subject)
	// The subject is still publishing the mark in its own Entity Configuration
	// and will keep doing so: nothing in the protocol tells it. Saying so is the
	// difference between an operator who follows up and one who believes the
	// revocation took effect everywhere the moment it was recorded.
	fmt.Println("\nThe subject's Entity Configuration still carries this mark, and " +
		"nothing in the protocol tells it otherwise. Readers learn of the " +
		"revocation by querying the trust mark status endpoint (section 8.4); " +
		"those that do not, and that hold an unexpired copy, will keep honouring it.")
	return nil
}

// trustMarkList prints what this entity has issued and what it holds.
func trustMarkList(ctx context.Context, conn *pgx.Conn) error {
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	now := time.Now()

	issued, err := store.ListIssuedTrustMarks(ctx, conn, instanceID)
	if err != nil {
		return err
	}
	fmt.Printf("%s issues:\n", issuer)
	if len(issued) == 0 {
		fmt.Println("  (nothing)")
	}
	for _, m := range issued {
		state := m.StatusAt(now)
		line := fmt.Sprintf("  %-8s %s\n           to %s", state, m.Type, m.Subject)
		if m.Status == "revoked" {
			line += fmt.Sprintf("\n           revoked %s: %s",
				m.RevokedAt.UTC().Format(time.RFC3339), m.Reason)
		} else if !m.ExpiresAt.IsZero() {
			line += fmt.Sprintf("\n           expires %s", m.ExpiresAt.UTC().Format(time.RFC3339))
		}
		fmt.Println(line)
	}

	held, err := store.ListHeldTrustMarks(ctx, conn, instanceID)
	if err != nil {
		return err
	}
	fmt.Printf("\n%s holds:\n", issuer)
	if len(held) == 0 {
		fmt.Println("  (nothing)")
	}
	for _, m := range held {
		state := "published"
		if !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(now) {
			// Kept in the table and excluded from the Entity Configuration, so an
			// operator can see that an accreditation lapsed rather than watching
			// it silently vanish from the published document.
			state = "EXPIRED"
		}
		fmt.Printf("  %-9s %s\n            from %s\n", state, m.Type, m.Issuer)
	}
	return nil
}

// trustMarkAccept records a Trust Mark somebody granted this entity.
//
// # What is checked here, and what is somebody else's job
//
// §7.3's validation is performed by READERS -- a relying party deciding whether
// to believe our accreditation. We are the subject, so running the full
// procedure on ourselves would prove nothing we do not already know.
//
// What is worth checking is everything whose failure would damage our own Entity
// Configuration: a mark issued to a different entity, an expired one, or one
// whose outer and inner type identifiers disagree all cause a conformant reader
// to reject the mark, and depending on the reader, the whole document -- so one
// bad row costs us every relying party in the federation.
func trustMarkAccept(ctx context.Context, conn *pgx.Conn, file string) error {
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading the trust mark: %w", err)
	}
	raw := strings.TrimSpace(string(b))

	// Parsed without verifying, deliberately and by name: we have no key for
	// the issuer here, and the checks are about the mark's fit with our own
	// document (store.AcceptTrustMark).
	tm, err := store.AcceptTrustMark(ctx, conn, instanceID, issuer, raw, time.Now())
	if err != nil {
		return err
	}
	var expires time.Time
	if tm.Expiry != 0 {
		expires = time.Unix(tm.Expiry, 0)
	}
	fmt.Printf("now publishing %s\n  from %s\n", tm.Type, tm.Issuer)
	if expires.IsZero() {
		fmt.Println("  expiry none")
	} else {
		fmt.Printf("  expiry %s\n", expires.UTC().Format(time.RFC3339))
	}
	fmt.Println("\nThe signature is NOT checked here: we hold no key for the issuer, " +
		"and section 7.3 puts that check on the reader. What was checked is that " +
		"the mark names this entity and has not expired -- the two failures that " +
		"would make readers reject our Entity Configuration.")
	return nil
}

// trustMarkDrop stops publishing a Trust Mark.
func trustMarkDrop(ctx context.Context, conn *pgx.Conn, markType, issuer string) error {
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if err := store.RemoveHeldTrustMark(ctx, conn, instanceID, markType, issuer); err != nil {
		return err
	}
	fmt.Printf("no longer publishing %s from %s\n", markType, issuer)
	return nil
}

// trustMarkDelegate mints a Trust Mark Delegation JWT, §7.2.1.
//
// This entity is the OWNER of a type identifier and is authorising somebody else
// to issue marks of that type. The delegate then passes the JWT to
// `trust-mark issue -trust-mark-delegation`, and readers validate it against the
// owner keys the Trust Anchor publishes in `trust_mark_owners`.
func trustMarkDelegate(ctx context.Context, conn *pgx.Conn, markType, delegate, ref string,
	lifetime time.Duration) error {

	root, err := rootKey()
	if err != nil {
		return err
	}
	instanceID, issuer, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	signed, err := store.SignDelegation(ctx, conn, root, instanceID, issuer, oidfed.DelegationParams{
		Delegate: delegate, Type: markType, Lifetime: lifetime, Ref: ref,
	}, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", signed)
	fmt.Fprintf(os.Stderr, "\n%s may now issue %s.\n\nFor this to validate, the "+
		"Trust Anchor must publish %s as the owner of that type in its "+
		"trust_mark_owners claim, WITH this entity's federation keys -- section "+
		"7.2.2 verifies the delegation against the owner keys the anchor "+
		"publishes, not against anything the delegation carries.\n",
		delegate, markType, issuer)
	return nil
}

// errNoTrustAnchor refuses a claim only a Trust Anchor may publish. A Trust
// Anchor MUST publish a federation_fetch_endpoint (specs/oidfed.html:3451-3462)
// and this engine serves none, so it cannot be one, and a claim set for it
// would only stop the Entity Configuration being built. Clearing still works.
func errNoTrustAnchor(claim string) error {
	return fmt.Errorf("%s is a Trust Anchor claim, and this engine cannot be a Trust Anchor "+
		"until it serves the federation_fetch_endpoint every Trust Anchor MUST publish. "+
		"Pass a file containing `{}` to clear it", claim)
}

// trustMarkIssuers writes §3.1.2's trust_mark_issuers claim from a JSON file.
func trustMarkIssuers(ctx context.Context, conn *pgx.Conn, file string) error {
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if file == "" {
		return fmt.Errorf("a JSON file is required: an object whose members are " +
			"Trust Mark type identifiers and whose values are arrays of Entity " +
			"Identifiers. Pass a file containing `{}` to clear the claim")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var issuers oidfed.TrustMarkIssuers
	if err := json.Unmarshal(b, &issuers); err != nil {
		return fmt.Errorf("this file is not a trust_mark_issuers object: %w", err)
	}
	for id, list := range issuers {
		if err := oidfed.ValidateTrustMarkType(id); err != nil {
			return err
		}
		for _, e := range list {
			if err := oidfed.ValidateEntityID(e); err != nil {
				return fmt.Errorf("a trusted issuer of %q: %w", id, err)
			}
		}
	}
	if len(issuers) == 0 {
		issuers = nil
	}
	if issuers != nil {
		return errNoTrustAnchor("trust_mark_issuers")
	}
	if err := store.SetTrustMarkIssuers(ctx, conn, instanceID, issuers); err != nil {
		return err
	}
	if issuers == nil {
		fmt.Println("trust_mark_issuers cleared")
		return nil
	}
	fmt.Printf("trust_mark_issuers set for %d Trust Mark type(s)\n", len(issuers))
	for id, list := range issuers {
		if len(list) == 0 {
			// The specification's own rule, and the opposite of how an empty list
			// reads everywhere else in this product. Printed at the moment it is
			// set, because it is the difference between "nobody" and "anybody" and
			// the file being loaded looks identical either way.
			fmt.Printf("  %s\n    ANYONE may issue this: section 3.1.2 says an empty "+
				"array means exactly that\n", id)
			continue
		}
		fmt.Printf("  %s\n    %s\n", id, strings.Join(list, "\n    "))
	}
	return nil
}

// trustMarkOwners writes §3.1.2's trust_mark_owners claim from a JSON file.
func trustMarkOwners(ctx context.Context, conn *pgx.Conn, file string) error {
	instanceID, _, err := selectInstance(ctx, conn, "")
	if err != nil {
		return err
	}
	if file == "" {
		return fmt.Errorf("a JSON file is required: an object whose members are " +
			"Trust Mark type identifiers and whose values are {sub, jwks}. Pass a " +
			"file containing `{}` to clear the claim")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var owners oidfed.TrustMarkOwners
	if err := json.Unmarshal(b, &owners); err != nil {
		return fmt.Errorf("this file is not a trust_mark_owners object: %w", err)
	}
	for id, o := range owners {
		if err := oidfed.ValidateTrustMarkType(id); err != nil {
			return err
		}
		if err := oidfed.ValidateEntityID(o.Subject); err != nil {
			return fmt.Errorf("the owner of %q: %w", id, err)
		}
		if len(o.JWKS) == 0 {
			return fmt.Errorf("the owner of %q has no jwks; without it section "+
				"7.2.2 has no key to validate a delegation against", id)
		}
		if err := refuseNonPublicJWKS(o.JWKS); err != nil {
			return fmt.Errorf("the owner of %q: %w", id, err)
		}
	}
	if len(owners) == 0 {
		owners = nil
	}
	if owners != nil {
		return errNoTrustAnchor("trust_mark_owners")
	}
	if err := store.SetTrustMarkOwners(ctx, conn, instanceID, owners); err != nil {
		return err
	}
	if owners == nil {
		fmt.Println("trust_mark_owners cleared")
		return nil
	}
	fmt.Printf("trust_mark_owners set for %d Trust Mark type(s)\n", len(owners))
	for id, o := range owners {
		fmt.Printf("  %s\n    owned by %s\n", id, o.Subject)
	}
	return nil
}

// refuseNonPublicJWKS rejects private key material in a key set that is about to
// be published.
//
// The same rule `attester add` applies to a Trusted Client Attester's keys: this
// claim goes into a signed document served to the whole federation, and a private
// key pasted in by mistake would be published to it. That is unrecoverable in the
// way that matters -- the key is out, and the operator's only signal would have
// been that nothing complained.
func refuseNonPublicJWKS(raw json.RawMessage) error {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("the jwks did not parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("the jwks contains no keys")
	}
	// The private members of every key type JWA defines: RSA, EC, OKP and oct.
	private := []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
	for i, k := range set.Keys {
		for _, m := range private {
			if _, ok := k[m]; ok {
				return fmt.Errorf("key %d carries the private member %q; this key "+
					"set is published in our Entity Configuration to the whole "+
					"federation", i, m)
			}
		}
	}
	return nil
}
