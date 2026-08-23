package pages

import (
	"fmt"
	"html/template"
	"regexp"
	"sort"
	"strings"
	"sync"

	"signari.dev/engine/internal/i18n"
)

// Validating an override.
//
// # The problem an override creates
//
// A themed page is arbitrary markup rendered into a security-critical response.
// The failure that matters is not an ugly page: it is a page that renders,
// looks right, and has quietly lost something.
//
//	the CSRF token          login-CSRF works again
//	the authz parameter     the flow loses the request it was answering
//	the form action         the credential posts somewhere else
//	SAMLResponse            single sign-on stops, silently, for one relying party
//
// Every one of those is invisible to the person who wrote the theme, because the
// page looks finished.
//
// # Why the requirements are derived rather than listed
//
// A hand-written list of "things a login page must contain" falls behind the
// login page. So the requirement is taken FROM THE BUILT-IN: render it with
// sentinel values, see which of the critical fields come out, and demand that an
// override produce the same ones.
//
// A new field added to a built-in page is therefore protected the moment it is
// added, with nothing to remember. The cost is that the list of what counts as
// critical still has to be maintained -- see criticalFields, and the test that
// refuses to let it fall behind.
//
// # What is deliberately NOT required
//
// Everything else. Headings, wording, the order of paragraphs, whether there is
// a logo, whether errors appear as a banner or inline. Validation that objected
// to those would be a theming feature nobody could use, and an operator who
// cannot change a heading will go back to forking the repository, which is the
// thing this package exists to stop.

// criticalFields are the values whose loss breaks security or the protocol.
//
// Named explicitly rather than "every field", because requiring every field
// would make a theme that drops an optional support link fail, and a rule that
// fires on cosmetic changes is one people route around.
//
// TestCriticalFieldsCoversEveryHiddenInput keeps this honest: any field the
// built-in pages put in a hidden input and that is missing here fails the suite.
// Six of these were missing from the first version of this list, and
// TestCriticalFieldsCoversEveryHiddenInput found every one: a theme could have
// dropped the password-reset token, the client being consented to, or the CIBA
// request being approved, and the override would have been accepted.
var criticalFields = []string{
	// Cross-site request forgery.
	"CSRF", "CSRFField",
	// The parked authorization request. Losing it strands the flow.
	"Authz",
	// UMA claims gathering: the handle IS the interaction.
	"Handle",
	// SAML and WS-Federation. These post to a RELYING PARTY, so losing one
	// breaks single sign-on for that application and nothing else -- which is
	// exactly the kind of failure nobody attributes to a theme change.
	"Response", "RelayState", "SAMLRequest", "WResult", "WCtx",
	// Where a flow resumes.
	"ContinueTo",
	// WHICH thing is being acted on. Every one of these identifies the subject
	// of a form, and a form that posts without it either fails or -- worse --
	// succeeds against something else:
	//
	//	Token      which password reset
	//	ClientID   which application the consent is for
	//	ID         which backchannel request is being approved
	//	Slug       which interstitial prompt is being answered
	//	Address    which address the emailed code was sent to
	//	Invite     which invitation a signup is redeeming
	//	UserCode   which device authorization is being approved
	"Token", "ClientID", "ID", "Slug", "Address", "Invite", "UserCode",
}

// sentinel is what a critical field is set to while probing.
//
// Alphanumeric on purpose: html/template escapes contextually, and a value
// containing a quote or an angle bracket would come out differently depending on
// where the template put it, so a comparison would be testing the escaper rather
// than the theme.
func sentinel(field string) string { return "SIGNARIPROBE" + strings.ToUpper(field) }

// formAction finds the action of every form in a rendered page.
var formAction = regexp.MustCompile(`(?i)<form[^>]*\baction="([^"]*)"`)

// The keys a page can branch on, and the keys it can iterate.
//
// Kept apart because a probe has to supply the right KIND: `{{if .Done}}` wants
// a boolean and `{{range .Open}}` wants a slice, and a page that gets the wrong
// one does not render at all -- which validation would then report as a broken
// theme when the fault is here.
var (
	probeBools = []string{
		"Captcha", "Ready", "Done", "Denied", "Confirm", "Empty", "Configured",
		"EmailFixed", "Unlaunchable", "Granted", "Required", "Verified",
	}
	probeLists = []string{
		"Scopes", "Providers", "Fields", "Codes", "Apps", "Rows", "Connections",
		"Requests", "Targets", "Details", "Domains", "Asks", "ActiveTokens",
		"Open", "Blocked", "Pending", "Linked",
	}
)

// probeElem is one element of every collection, carrying every sub-field any
// built-in page reads from inside a `{{range}}`.
func probeElem() map[string]any {
	e := map[string]any{
		"Name": "probe", "Slug": "probe", "Description": "probe", "Label": "probe",
		"Value": "probe", "Field": "probe", "Type": "probe", "ID": "probe",
		"Required": true, "Help": "probe", "Client": "probe", "URL": "probe",
		"Scope": "probe", "Expires": "probe", "Protocol": "probe",
		"Hostname": "probe", "LaunchURL": "probe", "DisplayName": "probe",
		"Resource": "probe", "BindingMessage": "probe",
		"ClientName": "probe", "When": "probe", "Rows": []any{},
		// The two that gate markup INSIDE a range -- the account page puts an
		// unlink form, CSRF token and all, behind `{{if .Linked}}`.
		"Linked": true, "Verified": true, "Email": "probe@example.test",
		// A SLICE, though one page prints it directly.
		//
		// `Scopes` is ranged on a connected-app element and printed on a UMA one.
		// A slice printed renders as `[probe]`, which is untidy and harmless; a
		// string ranged is a template error, and an error here would be reported
		// as a broken theme when the fault is the probe. When two pages disagree
		// about a type, the probe takes the one that cannot fail.
		"Scopes": []any{"probe"},
		// Compared numerically: `{{if gt .ActiveTokens 0}}`. Absent, it is nil,
		// and `gt` on nil is an error rather than false.
		"ActiveTokens": 1,
		"Granted":      "probe",
	}
	// Critical fields carry their sentinel INSIDE a range too.
	//
	// The backchannel approval page reads `{{.ID}}` from the element, not from
	// the top level -- so without this the sentinel never reaches the output, no
	// requirement is derived, and adding "ID" to criticalFields would have
	// achieved exactly nothing while looking like it had.
	for _, f := range criticalFields {
		e[f] = sentinel(f)
	}
	return e
}

// probeVariants are the datasets a page is rendered against.
//
// # Why more than one
//
// A page is a set of branches and only one of them renders at a time. The device
// page opens `{{if .Done}}` with a "you can put this away" notice and hides two
// forms in later arms; probed once with everything true, it produces no form at
// all, and a requirement derived from that render would demand nothing — so a
// theme could drop the code-entry form entirely and pass.
//
// So: once with every branch off, once with every branch on, and once per
// boolean with only that one on. The requirement is the UNION, which reaches
// every arm of an if/else-if chain rather than only its first.
//
// The page must render under all of them. A theme that only works when an error
// is present is a theme that breaks on the happy path.
func probeVariants() []map[string]any {
	base := func() map[string]any {
		d := map[string]any{}
		for _, f := range criticalFields {
			d[f] = sentinel(f)
		}
		for _, k := range []string{
			"Error", "Reason", "Reference", "CorrelationID", "Message", "Title",
			"Body", "Help", "Label", "Value", "Field", "Name", "Email", "Address",
			"Client", "ClientID", "ClientName", "LogoURI", "Scope", "Secret",
			"URL", "LaunchURL", "Code", "UserCode", "Number", "Nonce", "Type",
			"Protocol", "Hostname", "ID", "Slug", "DisplayName", "Detail", "Token",
			"ACS", "ResourceServer", "BindingMessage", "When", "Expires", "Action",
			"BrandName", "BrandLogo", "BrandSupport", "CaptchaSiteKey",
			"CaptchaProvider", "Description", "Invite", "WaitSeconds", "Wait",
		} {
			if _, taken := d[k]; !taken {
				d[k] = "probe-" + strings.ToLower(k)
			}
		}
		// Read as raw markup because this server generates them itself.
		d["QR"] = template.HTML("<svg></svg>")
		d["URI"] = template.URL("otpauth://probe")
		return d
	}
	fill := func(d map[string]any, bools bool, lists bool) map[string]any {
		for _, k := range probeBools {
			d[k] = bools
		}
		for _, k := range probeLists {
			if lists {
				d[k] = []any{probeElem()}
			} else {
				d[k] = []any{}
			}
		}
		return d
	}

	var out []map[string]any
	out = append(out, fill(base(), false, false))
	out = append(out, fill(base(), true, true))
	for _, k := range probeBools {
		d := fill(base(), false, true)
		d[k] = true
		out = append(out, d)
	}
	return out
}

// hiddenInput counts the hidden fields a render produced.
//
// Needed because some pages build their hidden inputs FROM DATA: the form_post
// response mode, the SAML POST binding and WS-Federation all loop over a list
// and emit `<input type="hidden" name="{{.Name}}" value="{{.Value}}">`. There is
// no fixed name to look for, so the only thing that can be required is that the
// loop is still there — and a theme that dropped it would render a form that
// posts nothing, which is single sign-on failing silently for one application.
var hiddenInput = regexp.MustCompile(`(?i)<input[^>]*\btype="hidden"`)

// Requirements is what a page must still produce after being themed.
type Requirements struct {
	// Fields are the critical values the built-in rendered.
	Fields []string
	// Actions are every form action the built-in posted to.
	Actions []string
	// Hidden is the most hidden inputs any single render produced.
	Hidden int
}

// Empty reports whether a page demands nothing -- a static notice with no form.
func (r Requirements) Empty() bool {
	return len(r.Fields) == 0 && len(r.Actions) == 0 && r.Hidden == 0
}

// validationBundle is the built-in catalogue, loaded once.
//
// Validation runs in ONE language on purpose. What it checks — that a CSRF
// token, a form target and a hidden input survived — is a property of the
// markup, and markup does not change between translations. Rendering an
// override once per language would multiply the work by the number of
// languages to re-derive the same answer.
//
// The built-in catalogue rather than the operator's, because a theme that
// reworded a message must still be judged against what the page structurally
// contains.
func validationBundle() *i18n.Bundle {
	validationBundleOnce.Do(func() {
		// Only the embedded catalogues, so this cannot fail on anything an
		// operator wrote. An error here would mean the binary itself is broken,
		// and every caller already reports the parse failure that follows.
		validationBundleValue, _, _ = i18n.Load("")
	})
	return validationBundleValue
}

var (
	validationBundleOnce  sync.Once
	validationBundleValue *i18n.Bundle
)

// requirementsOf renders a page against every probe variant and unions what a
// theme must not lose.
func requirementsOf(src map[string]string, name string) (Requirements, error) {
	set, err := build(src, validationBundle())
	if err != nil {
		return Requirements{}, err
	}
	fields := map[string]bool{}
	actions := map[string]bool{}
	var req Requirements

	for i, data := range probeVariants() {
		var sb strings.Builder
		if err := set.Execute(&sb, name, data); err != nil {
			return Requirements{}, fmt.Errorf(
				"the page did not render under probe %d of %d: %w",
				i+1, len(probeVariants()), err)
		}
		out := sb.String()

		for _, f := range criticalFields {
			if strings.Contains(out, sentinel(f)) {
				fields[f] = true
			}
		}
		for _, m := range formAction.FindAllStringSubmatch(out, -1) {
			// An action containing a probe value is data, not a fixed route;
			// requiring the literal would demand the theme hard-code something
			// that changes per request.
			if strings.Contains(m[1], "SIGNARIPROBE") || strings.Contains(m[1], "probe-") {
				continue
			}
			actions[m[1]] = true
		}
		if n := len(hiddenInput.FindAllString(out, -1)); n > req.Hidden {
			req.Hidden = n
		}
	}

	for f := range fields {
		req.Fields = append(req.Fields, f)
	}
	for a := range actions {
		req.Actions = append(req.Actions, a)
	}
	sort.Strings(req.Fields)
	sort.Strings(req.Actions)
	return req, nil
}

// validateOne checks an override against what the built-in produced.
//
// Both sides are rendered from the SAME source map with only this page swapped,
// so a partial the operator also overrode is in force for both -- otherwise
// replacing the layout would look like every page had lost its fields.
func validateOne(candidate map[string]string, name string) error {
	if partials[name] {
		// A partial has no page of its own. Its effect is checked through every
		// page that uses it, which happens below because those pages are rendered
		// from the candidate source.
		return validateAllAgainst(candidate)
	}
	builtinSrc, err := builtinSources()
	if err != nil {
		return err
	}
	// The built-in requirement is computed with the operator's OTHER overrides in
	// place, so only this page's change is being judged.
	base := clone(candidate)
	base[name] = builtinSrc[name]
	want, err := requirementsOf(base, name)
	if err != nil {
		return fmt.Errorf("the built-in page could not be rendered for comparison: %w", err)
	}
	got, err := requirementsOf(candidate, name)
	if err != nil {
		return err
	}
	return compare(name, want, got)
}

// validateAllAgainst checks every page still meets its requirements.
//
// Used when a PARTIAL is overridden: a layout is not a page, so the only way to
// judge it is by what happens to the pages that use it.
func validateAllAgainst(candidate map[string]string) error {
	builtinSrc, err := builtinSources()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(candidate))
	for n := range candidate {
		if !partials[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		want, err := requirementsOf(builtinSrc, n)
		if err != nil {
			return err
		}
		got, err := requirementsOf(candidate, n)
		if err != nil {
			return fmt.Errorf("page %s: %w", n, err)
		}
		if err := compare(n, want, got); err != nil {
			return err
		}
	}
	return nil
}

func compare(name string, want, got Requirements) error {
	var lost []string
	for _, f := range want.Fields {
		if !contains(got.Fields, f) {
			lost = append(lost, "the "+f+" value")
		}
	}
	for _, a := range want.Actions {
		if !contains(got.Actions, a) {
			lost = append(lost, `a form posting to "`+a+`"`)
		}
	}
	if got.Hidden < want.Hidden {
		lost = append(lost, fmt.Sprintf(
			"%d of its %d hidden inputs", want.Hidden-got.Hidden, want.Hidden))
	}
	if len(lost) == 0 {
		return nil
	}
	return fmt.Errorf("the %s page no longer renders %s. The built-in page does, "+
		"and losing it breaks the page in a way that still looks correct on screen",
		name, strings.Join(lost, ", "))
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Check validates a whole theme directory without loading it into a server.
//
// This is what `signari theme check` runs, and what a pipeline should run:
// finding a broken theme here is free, and finding it at startup means either a
// server that will not start or a deployment quietly serving the built-in pages.
func Check(dir string) ([]string, []error) {
	src, err := builtinSources()
	if err != nil {
		return nil, []error{err}
	}
	over, err := overrideSources(dir)
	if err != nil {
		return nil, []error{err}
	}
	if len(over) == 0 {
		return nil, []error{fmt.Errorf("%s contains no .html files, so nothing "+
			"would be overridden", dir)}
	}
	names := make([]string, 0, len(over))
	for n := range over {
		names = append(names, n)
	}
	sort.Strings(names)

	var ok []string
	var problems []error
	for _, n := range names {
		if !partials[n] {
			if _, known := src[n]; !known {
				problems = append(problems, fmt.Errorf(
					"%s.html does not correspond to any page this server renders, so "+
						"it would be ignored", n))
				continue
			}
		}
		candidate := clone(src)
		candidate[n] = over[n]
		if err := validateOne(candidate, n); err != nil {
			problems = append(problems, err)
			continue
		}
		ok = append(ok, n)
	}
	return ok, problems
}
