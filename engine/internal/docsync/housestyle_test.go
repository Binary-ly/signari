package docsync

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The documentation is written in one voice, and docs/writing-docs.md is the
// record of it. Its last section, "Rules a test could check", lists the rules a
// program can hold a page to. This test holds every published page to each of
// them.
//
// # Why a test, and why now
//
// The pages are rewritten by several people at once, some of them helped by
// coding agents. A voice that lives only in the heads of whoever wrote the last
// page is lost by the next one. A rule a person forgets is a rule this test
// names, with the page, the line and what to do.
//
// # The ratchet
//
// Most pages were written before the house style was. Each rule a page still
// breaks is a line of testdata/house-style-pending.txt. A fault on a line the
// list does not hold fails the test, and so does a line whose page now passes
// its rule, so the list can only shrink: fixing a page means deleting its line.
//
// # Kept in step
//
// A writer checks a page with a Python copy of these rules that is not
// committed. When this file changes, that copy changes with it. When the two
// disagree, this file decides.

const (
	styleSidebar     = "docs/documentation.md"
	styleWritingDocs = "docs/writing-docs.md"
	styleGlossary    = "docs/glossary.md"
	stylePending     = "engine/internal/docsync/testdata/house-style-pending.txt"
	styleMaxWords    = 25
)

// styleRules are the rows of "Rules a test could check", in its order.
var styleRules = []string{
	"One title",
	"Introduction first",
	"Introduced code",
	"No stacked code",
	"Two callouts",
	"No minimisers",
	"One word per idea",
	"Short sentences",
	"Abbreviations",
	"Titles as link text",
	"Every page listed",
}

// styleGenerated are the pages a program writes. Their words come from code,
// so a fault in them is fixed in the generator, not in the page, and the next
// run would undo a fix made by hand. Each names the file that writes it, and
// the test fails if that file stops mentioning the page, so an exemption
// cannot outlive its generator.
var styleGenerated = map[string]string{
	// TestTheSchemaVersionNotesAreCurrent writes it from each migration's
	// header, with -schema-notes-out.
	"docs/schema-versions.md": "engine/internal/migrate/notes_test.go",
	// TestTheClientsAreCurrent writes it from docs/admin-openapi.json, with
	// -sdk-out.
	"docs/admin-api-reference.md": "engine/internal/sdkgen/sdkgen_test.go",
}

// The sidebar is data for the site: a title and a nested list of links. It
// is not read as prose, so the rules about prose do not apply to it.
var styleNotProse = map[string]bool{styleSidebar: true}

// The pages the sidebar does not list, as writing-docs.md says.
var styleUnlisted = map[string]bool{"docs/README.md": true, styleSidebar: true}

// The rules a page is excused from, each with its reason.
var styleExcused = map[[2]string]bool{
	// The glossary spells out every abbreviation in the entry that defines
	// it, as that entry's first words. A reader arrives at an entry, not at
	// the top of the page, so "the first use on the page" means nothing there.
	{styleGlossary, "Abbreviations"}: true,
}

// The sidebar groups whose pages are tutorials or explanations. Only those
// pages are held to the 25-word sentence. A reference page lists options, and
// a sentence that names three flags runs long without being hard to read.
var styleTeachingGroups = []string{"Getting started", "Core concepts"}

// styleFault is one place a page breaks one rule.
type styleFault struct {
	page    string
	line    int
	rule    string
	message string
}

func (f styleFault) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.page, f.line, f.rule, f.message)
}

func styleRuleIndex(rule string) int {
	for i, r := range styleRules {
		if r == rule {
			return i
		}
	}
	return -1
}

func sortStyleFaults(faults []styleFault) {
	sort.SliceStable(faults, func(i, j int) bool {
		a, b := faults[i], faults[j]
		if a.page != b.page {
			return a.page < b.page
		}
		if ra, rb := styleRuleIndex(a.rule), styleRuleIndex(b.rule); ra != rb {
			return ra < rb
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.message < b.message
	})
}

// ---------------------------------------------------------------------------
// Reading a page

type styleLine int

const (
	styleBlank styleLine = iota
	styleProse
	styleHeading
	styleTable
	styleOpen
	styleCode
	styleClose
	styleComment
	// styleQuote is never a line's kind, only a segment's: see styleSegments.
	styleQuote
)

var (
	styleFenceOpen   = regexp.MustCompile("^(`{3,}|~{3,})")
	styleFenceClose  = regexp.MustCompile("^(`{3,}|~{3,})[ \t]*$")
	styleHeadingLine = regexp.MustCompile(`^#{1,6}([ \t]|$)`)
)

// classifyStyleLines says what each line is: code, a heading, a table row,
// prose and so on.
func classifyStyleLines(lines []string) []styleLine {
	kinds := make([]styleLine, 0, len(lines))
	var fenceChar byte
	fenceLen := 0
	comment := false
	for _, ln := range lines {
		s := strings.TrimLeft(ln, " \t")
		if fenceLen > 0 {
			if m := styleFenceClose.FindStringSubmatch(s); m != nil && m[1][0] == fenceChar && len(m[1]) >= fenceLen {
				kinds = append(kinds, styleClose)
				fenceLen = 0
			} else {
				kinds = append(kinds, styleCode)
			}
			continue
		}
		if comment {
			kinds = append(kinds, styleComment)
			if strings.Contains(ln, "-->") {
				comment = false
			}
			continue
		}
		if m := styleFenceOpen.FindStringSubmatch(s); m != nil {
			fenceChar, fenceLen = m[1][0], len(m[1])
			kinds = append(kinds, styleOpen)
			continue
		}
		if strings.HasPrefix(s, "<!--") {
			kinds = append(kinds, styleComment)
			if !strings.Contains(s[4:], "-->") {
				comment = true
			}
			continue
		}
		switch {
		case strings.Trim(s, " \t\r") == "":
			kinds = append(kinds, styleBlank)
		case styleHeadingLine.MatchString(ln):
			kinds = append(kinds, styleHeading)
		case strings.HasPrefix(s, "|"):
			kinds = append(kinds, styleTable)
		default:
			kinds = append(kinds, styleProse)
		}
	}
	return kinds
}

// styleSegment is a run of text the word rules read: a paragraph, a list, a
// quotation, a table row or a heading. masked has code, link targets, paths,
// names and flags replaced byte for byte, so an offset means the same place
// in both; codeless has only the code spans replaced.
type styleSegment struct {
	first    int // index of its first line
	text     string
	kind     styleLine
	masked   string
	codeless string
}

func newStyleSegment(first int, text string, kind styleLine) styleSegment {
	b := []byte(text)
	maskCodeSpans(b)
	return styleSegment{first: first, text: text, kind: kind, masked: styleMask(text), codeless: string(b)}
}

func (s styleSegment) lineOf(offset int) int {
	return s.first + strings.Count(s.text[:offset], "\n") + 1
}

// styleSegments cuts a page into segments. A blockquote is a segment of its
// own. One that opens with a GitHub alert marker is a callout, written here,
// and is prose. Any other is a quotation: the words of a specification, an RFC
// or a message, given exactly. Changing a quotation's words to suit the house
// style would misquote it, so the rules about words (minimisers, one word per
// idea, sentence length, abbreviations) do not read quotations. Titles as
// link text still does: a link's text is ours, even inside one.
func styleSegments(lines []string, kinds []styleLine) []styleSegment {
	var out []styleSegment
	for i := 0; i < len(lines); {
		switch kinds[i] {
		case styleProse:
			quoted := styleQuotePrefix.MatchString(lines[i])
			j := i
			for j < len(lines) && kinds[j] == styleProse && styleQuotePrefix.MatchString(lines[j]) == quoted {
				j++
			}
			kind := styleProse
			if quoted && !strings.HasPrefix(lines[i][styleQuotePrefix.FindStringIndex(lines[i])[1]:], "[!") {
				kind = styleQuote
			}
			out = append(out, newStyleSegment(i, strings.Join(lines[i:j], "\n"), kind))
			i = j
			continue
		case styleTable, styleHeading:
			out = append(out, newStyleSegment(i, lines[i], kinds[i]))
		}
		i++
	}
	return out
}

// ---------------------------------------------------------------------------
// What the word rules never read
//
// Words inside code, link targets, URLs, file paths, command names, flags and
// field names are names, not prose. A rule about how prose reads cannot ask a
// page to rename `/login` or `signari user create`. Each is replaced by a
// placeholder, so that a phrase cannot match across one and a word inside one
// is never counted.

const stylePlaceholder = 0x00

func blankStyleBytes(b []byte, from, to int) {
	for i := from; i < to; i++ {
		if b[i] != '\n' {
			b[i] = stylePlaceholder
		}
	}
}

// maskCodeSpans replaces every inline code span, as CommonMark finds them: a
// run of backticks up to the next run of the same length.
func maskCodeSpans(b []byte) {
	n := len(b)
	for i := 0; i < n; {
		if b[i] != '`' {
			i++
			continue
		}
		j := i
		for j < n && b[j] == '`' {
			j++
		}
		run := j - i
		closeAt := -1
		for k := j; k < n; {
			if b[k] != '`' {
				k++
				continue
			}
			e := k
			for e < n && b[e] == '`' {
				e++
			}
			if e-k == run {
				closeAt = e
				break
			}
			k = e
		}
		if closeAt < 0 {
			i = j
			continue
		}
		blankStyleBytes(b, i, closeAt)
		i = closeAt
	}
}

var (
	styleLinkTarget = regexp.MustCompile(`\]\([^)]*\)`)
	styleHTMLTag    = regexp.MustCompile(`<[A-Za-z/!][^>\n]*>`)
	styleCalloutTag = regexp.MustCompile(`\[![A-Za-z]+\]`)
	styleURL        = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^ \t\n)\]>"”]*`)
	styleAbsPath    = regexp.MustCompile(`(^|[ \t\n(\["'“])(\.{0,2}/[A-Za-z0-9_.~{}<>:/*-]*)`)
	styleRelPath    = regexp.MustCompile(`[A-Za-z0-9_.-]+(/[A-Za-z0-9_.{}<>*-]+)+/?`)
	styleDotted     = regexp.MustCompile(`[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+`)
	styleFlag       = regexp.MustCompile(`(^|[ \t\n(\["'“/])(--?[A-Za-z][A-Za-z0-9_-]*)`)
	styleIdent      = regexp.MustCompile(`[A-Za-z0-9]+(_[A-Za-z0-9]+)+`)
	styleCommand    = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(signari([ \t\n]+[a-z][a-z0-9-]*){1,2})`)
)

func styleMask(text string) string {
	b := []byte(text)
	maskCodeSpans(b)
	apply := func(re *regexp.Regexp, group int, trim bool, keep func(string) bool) {
		cur := string(b)
		for _, m := range re.FindAllStringSubmatchIndex(cur, -1) {
			from, to := m[2*group], m[2*group+1]
			if keep != nil && !keep(cur[from:to]) {
				continue
			}
			if trim {
				// A path at the end of a sentence keeps its full stop out of
				// the mask, so that the sentence still ends.
				for to > from && strings.ContainsRune(".:,", rune(cur[to-1])) {
					to--
				}
			}
			if re == styleLinkTarget {
				from++ // keep the "]" of the link text
			}
			blankStyleBytes(b, from, to)
		}
	}
	apply(styleLinkTarget, 0, false, nil)
	apply(styleHTMLTag, 0, false, nil)
	apply(styleCalloutTag, 0, false, nil)
	apply(styleURL, 0, true, nil)
	apply(styleAbsPath, 2, true, nil)
	// A relative path is masked only when it looks like one: a file name, an
	// identifier, three segments or a trailing slash. "and/or" and
	// "login/logout" stay prose.
	apply(styleRelPath, 0, true, func(s string) bool {
		return strings.ContainsAny(s, "._") || strings.Count(s, "/") >= 2 || strings.HasSuffix(s, "/")
	})
	apply(styleDotted, 0, false, nil)
	apply(styleFlag, 2, false, nil)
	apply(styleIdent, 0, false, nil)
	apply(styleCommand, 2, false, nil)
	return string(b)
}

// ---------------------------------------------------------------------------
// The vocabulary, read from the pages that state it, so that a word added to
// writing-docs.md or to the glossary is checked from then on.

// styleSection is the lines under a ## heading, up to the next one.
func styleSection(lines []string, heading string) []string {
	var out []string
	inside := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "## ") {
			if inside {
				break
			}
			inside = strings.Trim(ln, " \t\r\n") == heading
			continue
		}
		if inside {
			out = append(out, ln)
		}
	}
	return out
}

type styleRejected struct {
	phrase  string
	write   string
	pattern *regexp.Regexp
}

var styleWordSplit = regexp.MustCompile(`[ -]+`)

func newStyleRejected(phrase, write string) styleRejected {
	var words []string
	for _, w := range styleWordSplit.Split(phrase, -1) {
		if w != "" {
			words = append(words, w)
		}
	}
	parts := make([]string, len(words))
	for i, w := range words {
		q := regexp.QuoteMeta(w)
		if i == 0 && strings.ToLower(w) == "log" && len(words) > 1 {
			// "logged in" is the same word as "log in".
			q = "log(?:s|ged|ging)?"
		}
		if i == len(words)-1 {
			if strings.HasSuffix(w, "y") {
				q = regexp.QuoteMeta(w[:len(w)-1]) + "(?:y|ies)"
			} else {
				q += "s?"
			}
		}
		parts[i] = q
	}
	return styleRejected{phrase: phrase, write: write,
		pattern: regexp.MustCompile(`(?i)\b` + strings.Join(parts, `(?:[ \t\n]+|-)`) + `\b`)}
}

var (
	styleNeverWrite = regexp.MustCompile(`(?s)Never write (.*?)\.[ \t\n]`)
	styleBackticked = regexp.MustCompile("`([^`]+)`")
)

// styleVocabulary reads the rejected words from the second column of "One
// word for each idea", and the minimisers from the backticked words after
// "Never write" under "Sentences".
func styleVocabulary(writingDocs string) (rejected []styleRejected, minimisers []string) {
	lines := strings.Split(writingDocs, "\n")
	var rows []string
	for _, ln := range styleSection(lines, "## One word for each idea") {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), "|") {
			rows = append(rows, ln)
		}
	}
	for i, row := range rows {
		if i < 2 {
			continue // the header and its separator
		}
		cells := strings.Split(strings.Trim(strings.Trim(row, " \t\r\n"), "|"), "|")
		for k := range cells {
			cells[k] = strings.Trim(cells[k], " \t\r\n")
		}
		if len(cells) < 2 {
			continue
		}
		for _, phrase := range strings.Split(cells[1], ",") {
			phrase = strings.Trim(strings.Trim(strings.Trim(phrase, " \t\r\n"), "`"), " \t\r\n")
			if phrase != "" {
				rejected = append(rejected, newStyleRejected(phrase, cells[0]))
			}
		}
	}
	sentences := strings.Join(styleSection(lines, "## Sentences"), "\n")
	if m := styleNeverWrite.FindStringSubmatch(sentences); m != nil {
		for _, w := range styleBackticked.FindAllStringSubmatch(m[1], -1) {
			minimisers = append(minimisers, w[1])
		}
	}
	return rejected, minimisers
}

var (
	styleTermVersion = regexp.MustCompile(`[ \t]+[0-9]+(\.[0-9]+)*$`)
	styleTermMarker  = regexp.MustCompile(`^\*\*[^*]+\*\*[ \t]*`)
	styleArticle     = regexp.MustCompile(`^(A|An|The)[ \t]`)
)

// styleAbbreviations reads every glossary entry whose term is an
// abbreviation, with what it stands for.
//
// An entry is an abbreviation when its term is one word with two or more
// capital letters, ignoring a version such as "2.0", and its definition opens
// with the words it stands for: a phrase that does not begin with "A", "An" or
// "The", ends at the first colon or full stop, and holds the term's capitals
// in order. "### OIDC" with "OpenID Connect: the layer..." is one. "### ES256"
// with "The signature algorithm..." is a name, not an abbreviation, and is
// left alone.
func styleAbbreviations(glossary string) [][2]string {
	lines := strings.Split(glossary, "\n")
	var out [][2]string
	for i, ln := range lines {
		if !strings.HasPrefix(ln, "### ") {
			continue
		}
		term := styleTermVersion.ReplaceAllString(strings.Trim(ln[4:], " \t\r\n"), "")
		capitals := 0
		for _, c := range term {
			if c >= 'A' && c <= 'Z' {
				capitals++
			}
		}
		if strings.Contains(term, " ") || capitals < 2 {
			continue
		}
		var body []string
		j := i + 1
		for j < len(lines) && strings.Trim(lines[j], " \t\r\n") == "" {
			j++
		}
		for j < len(lines) && strings.Trim(lines[j], " \t\r\n") != "" && !strings.HasPrefix(lines[j], "#") {
			body = append(body, strings.Trim(lines[j], " \t\r\n"))
			j++
		}
		text := styleTermMarker.ReplaceAllString(strings.Join(body, " "), "")
		end := len(text)
		for k := 0; k < len(text); k++ {
			if text[k] == ':' || (text[k] == '.' && (k+1 == len(text) || text[k+1] == ' ')) {
				end = k
				break
			}
		}
		expansion := strings.Trim(text[:end], " \t\r\n")
		if expansion == "" || styleArticle.MatchString(expansion) || !styleSpells(term, expansion) {
			continue
		}
		out = append(out, [2]string{term, expansion})
	}
	return out
}

// styleSpells says whether the term's capitals appear in the expansion, in
// order.
func styleSpells(term, expansion string) bool {
	var letters []byte
	for _, c := range []byte(strings.ToUpper(expansion)) {
		if c >= 'A' && c <= 'Z' {
			letters = append(letters, c)
		}
	}
	k := 0
	for _, c := range []byte(term) {
		if c < 'A' || c > 'Z' {
			continue
		}
		for k < len(letters) && letters[k] != c {
			k++
		}
		if k == len(letters) {
			return false
		}
		k++
	}
	return true
}

var styleWordsOf = regexp.MustCompile(`[ \t-]+`)

// styleExpansionPattern is an expansion as a page may write it: in any case,
// with spaces or hyphens between its words, its last word singular or plural,
// and a trailing version optional.
func styleExpansionPattern(expansion string) string {
	version := ""
	if m := regexp.MustCompile(`[ \t]+([0-9]+(\.[0-9]+)*)$`).FindStringSubmatchIndex(expansion); m != nil {
		version = `(?:[ \t\n]+` + regexp.QuoteMeta(expansion[m[2]:m[3]]) + `)?`
		expansion = expansion[:m[0]]
	}
	var words []string
	for _, w := range styleWordsOf.Split(expansion, -1) {
		if w != "" {
			words = append(words, w)
		}
	}
	for i := range words[:len(words)-1] {
		words[i] = regexp.QuoteMeta(words[i])
	}
	last := words[len(words)-1]
	if strings.HasSuffix(last, "s") && !strings.HasSuffix(last, "ss") {
		words[len(words)-1] = regexp.QuoteMeta(last[:len(last)-1]) + "s?"
	} else {
		words[len(words)-1] = regexp.QuoteMeta(last) + "s?"
	}
	return strings.Join(words, `(?:[ \t\n]+|-)`) + version
}

// What may close a term or its expansion before the parenthesis (emphasis, a
// quotation mark, a link's text and target), what may open the parenthesis's
// contents, and a version after the term.
const (
	styleClosers = `["”*_]*(?:\]\([^)]*\))?["”*_]*`
	styleOpeners = `[\["“*_]*`
	styleVersion = `(?:[ \t\n]+[0-9]+(?:\.[0-9]+)*)?`
)

type styleAbbreviation struct {
	term, expansion string
	before, after   *regexp.Regexp
}

// ---------------------------------------------------------------------------
// The allowances for "One word per idea"
//
// Each marks text where a rejected word is not the house style's idea under
// another name. Keep the list short: every entry is a hole in the rule.

var styleAllowed = []*regexp.Regexp{
	// "user agent" is HTTP's name for the browser, and User-Agent its header.
	regexp.MustCompile(`(?i)\buser(?:[ \t\n]+|-)agents?\b`),
	// RFC 8628 names the code a person types on a second device the "user
	// code"; the device pages quote the screen that says so.
	regexp.MustCompile(`(?i)\buser[ \t\n]+codes?\b`),
	// WebAuthn binds a passkey to a "relying party ID", a domain name. It is
	// the field's name, and a person comparing it with their browser's
	// console needs that name.
	regexp.MustCompile(`(?i)\brelying[ \t\n]+party[ \t\n]+IDs?\b`),
	// The Admin API, and the admin tokens that open it, are names of
	// Signari's own parts, each a glossary entry and a command
	// (`signari admin-token`).
	regexp.MustCompile(`\bAdmin[ \t\n]+API\b`),
	regexp.MustCompile(`(?i)\badmin[ \t\n]+tokens?\b`),
	// An authenticator app or a wallet app is software on a person's phone,
	// not an application that signs people in through Signari, so it is not
	// the idea "application" names.
	regexp.MustCompile(`(?i)\b(authenticator|wallet)[ \t\n]+apps?\b`),
	// The titles of the sign-out specifications: OpenID Connect's
	// Back-Channel, Front-Channel and RP-Initiated Logout, and SAML's Single
	// Logout. A reader searches for them by these words. Only the title, in
	// its capitals, is a name; "a back-channel logout" is the reader's action,
	// and is a sign-out.
	regexp.MustCompile(`\b(Back-Channel|Front-Channel|RP-Initiated|Single)[ \t\n]+Logout\b`),
	// A Kerberos realm is Kerberos's own unit, of which an organisation can
	// have several; it is not another word for an organisation. Only the
	// compound is allowed, so a bare "realm" still has to say which it is.
	regexp.MustCompile(`(?i)\b(Kerberos|FreeIPA)[ \t\n]+realms?\b`),
	// The name of Next.js's router, which a reader of that quickstart picks
	// in Next.js's own setup.
	regexp.MustCompile(`\bApp[ \t\n]+Router\b`),
	// OpenID Federation calls each rule of a metadata policy a "policy
	// operator" (§6.1.3), such as subset_of. It is the specification's word
	// for a rule, not a person running Signari. Only the compound is allowed.
	regexp.MustCompile(`(?i)\bpolicy[ \t\n]+operators?\b`),
	// A Kubernetes operator is a kind of program, and Signari has one, the
	// operator/ module. It is not a person running Signari. See also
	// styleAllowedSpans, for "the operator" after it.
	styleKubernetesOperator,
}

var (
	styleKubernetesOperator = regexp.MustCompile(`(?i)\bKubernetes[ \t\n]+operators?\b`)
	styleTheOperator        = regexp.MustCompile(`(?i)\bthe[ \t\n]+operators?\b`)
	styleQuoted             = regexp.MustCompile(`"[^"]*"|“[^”]*”`)
	styleEndUser            = regexp.MustCompile(`(?i)\bend-users?\b`)
)

func styleAllowedSpans(text string, expansions []*regexp.Regexp) [][2]int {
	var spans [][2]int
	for _, re := range styleAllowed {
		for _, m := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, [2]int{m[0], m[1]})
		}
	}
	// What a glossary abbreviation stands for is a name: RADIUS is Remote
	// Authentication Dial-In User Service, and UMA is User-Managed Access,
	// whatever the table prefers.
	for _, re := range expansions {
		for _, m := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, [2]int{m[0], m[1]})
		}
	}
	// Once a paragraph has named the Kubernetes operator, "the operator" in
	// the rest of it is that program. Before the name, or as "an operator",
	// it is still the person, and still a fault.
	if k := styleKubernetesOperator.FindStringIndex(text); k != nil {
		for _, m := range styleTheOperator.FindAllStringIndex(text[k[1]:], -1) {
			spans = append(spans, [2]int{k[1] + m[0], k[1] + m[1]})
		}
	}
	// "End-User" is the OpenID Connect specification's own word. It may stand
	// inside a quotation of the specification, and nowhere else.
	for _, q := range styleQuoted.FindAllStringIndex(text, -1) {
		for _, m := range styleEndUser.FindAllStringIndex(text[q[0]:q[1]], -1) {
			spans = append(spans, [2]int{q[0] + m[0], q[0] + m[1]})
		}
	}
	return spans
}

// styleGlossed says whether a rejected word stands alone inside double
// quotes. It is then being named rather than used: a "relying party" is what
// the protocols call an application.
func styleGlossed(text string, from, to int) bool {
	return (strings.HasSuffix(text[:from], `"`) || strings.HasSuffix(text[:from], "“")) &&
		(strings.HasPrefix(text[to:], `"`) || strings.HasPrefix(text[to:], "”"))
}

// ---------------------------------------------------------------------------
// The rules

// houseStyle is everything the rules read from outside the page being checked.
type houseStyle struct {
	rejected      []styleRejected
	minimiser     *regexp.Regexp
	abbreviations []styleAbbreviation
	expansions    []*regexp.Regexp
	teaching      map[string]bool
	titleOf       func(page string) string
}

// newHouseStyle reads the vocabulary from writing-docs.md, the abbreviations
// from the glossary and the kinds of page from the sidebar. problems are the
// ways those pages no longer say what the rules need, so that a reworded
// page cannot switch a rule off without anyone noticing.
func newHouseStyle(writingDocs, glossary, sidebar string) (*houseStyle, []string) {
	var problems []string
	h := &houseStyle{teaching: map[string]bool{}}
	rejected, minimisers := styleVocabulary(writingDocs)
	h.rejected = rejected
	hasLogin := false
	for _, r := range rejected {
		hasLogin = hasLogin || r.phrase == "login"
	}
	if !hasLogin {
		problems = append(problems, styleWritingDocs+": its \"One word for each idea\" table no longer "+
			"yields the rejected words; the check reads the second column of that table")
	}
	hasSimply := false
	quoted := make([]string, len(minimisers))
	for i, w := range minimisers {
		hasSimply = hasSimply || w == "simply"
		quoted[i] = regexp.QuoteMeta(w)
	}
	if !hasSimply {
		problems = append(problems, styleWritingDocs+": its \"Sentences\" section no longer yields "+
			"the minimisers; the check reads the backticked words after \"Never write\"")
	}
	if len(minimisers) > 0 {
		h.minimiser = regexp.MustCompile(`(?i)\b(` + strings.Join(quoted, "|") + `)\b`)
	}
	hasOIDC := false
	for _, a := range styleAbbreviations(glossary) {
		p := styleExpansionPattern(a[1])
		// "OpenID Connect (OIDC)" or "OIDC (OpenID Connect)". Either side may
		// be bold, quoted or a link, and a version may follow the term, as in
		// "SAML 2.0 (Security Assertion Markup Language)".
		h.abbreviations = append(h.abbreviations, styleAbbreviation{
			term: a[0], expansion: a[1],
			before: regexp.MustCompile(`(?i)` + p + styleClosers + `[ \t\n]*\(` + styleOpeners + `$`),
			after:  regexp.MustCompile(`(?i)^` + styleClosers + styleVersion + `[ \t\n]*\([ \t\n]*` + styleOpeners + p),
		})
		h.expansions = append(h.expansions, regexp.MustCompile(`(?i)\b`+p+`\b`))
		hasOIDC = hasOIDC || a[0] == "OIDC"
	}
	if !hasOIDC {
		problems = append(problems, styleGlossary+": no abbreviations could be read from it, or OIDC "+
			"is not among them; the check reads each `### TERM` entry whose definition opens with "+
			"what the term stands for")
	}
	groups := styleTeachingPages(sidebar)
	for _, g := range styleTeachingGroups {
		if len(groups[g]) == 0 {
			problems = append(problems, fmt.Sprintf("%s: the `- ## %s` group is missing or empty; the "+
				"check reads it to know which pages are tutorials and explanations", styleSidebar, g))
		}
		for _, p := range groups[g] {
			h.teaching[p] = true
		}
	}
	named := styleSidebarTitles(sidebar)
	h.titleOf = func(p string) string { return named[p] }
	return h, problems
}

var (
	styleSidebarLink = regexp.MustCompile(`\]\(([^)# \t\n]+)`)
	styleTitledLink  = regexp.MustCompile(`\[([^\]]+)\]\(([^)# \t\n]+)\)`)
	styleGroupLine   = regexp.MustCompile(`^- ## (.+)$`)
)

// styleTeachingPages is the pages under each sidebar group, by group name.
func styleTeachingPages(sidebar string) map[string][]string {
	found := map[string][]string{}
	for _, g := range styleTeachingGroups {
		found[g] = nil
	}
	group := ""
	for _, ln := range strings.Split(sidebar, "\n") {
		if m := styleGroupLine.FindStringSubmatch(ln); m != nil {
			group = strings.Trim(m[1], " \t\r\n")
			continue
		}
		if _, ok := found[group]; ok {
			for _, m := range styleSidebarLink.FindAllStringSubmatch(ln, -1) {
				found[group] = append(found[group], path.Clean(path.Join("docs", m[1])))
			}
		}
	}
	return found
}

// styleSidebarTitles is each page's name in the sidebar, the one a beginner
// looks for, to suggest as a link's text.
func styleSidebarTitles(sidebar string) map[string]string {
	named := map[string]string{}
	for _, ln := range strings.Split(sidebar, "\n") {
		for _, m := range styleTitledLink.FindAllStringSubmatch(ln, -1) {
			p := path.Clean(path.Join("docs", m[2]))
			if _, ok := named[p]; !ok {
				named[p] = m[1]
			}
		}
	}
	return named
}

var (
	styleWord         = regexp.MustCompile(`[^ \t\r\n]+`)
	styleAlnum        = regexp.MustCompile(`[A-Za-z0-9]`)
	styleListMark     = regexp.MustCompile(`^[ \t]*(>[ \t]*)*([-*+]|[0-9]+[.)])[ \t]+`)
	styleSentenceEnd  = regexp.MustCompile(`[.!?]["'”’)\]*_]*[ \t\n]+`)
	styleQuotePrefix  = regexp.MustCompile(`^[ \t]*>[> \t]*`)
	styleBoldLabel    = regexp.MustCompile(`^(\*\*|__)[A-Za-z]+( [A-Za-z]+)?[:.!]?(\*\*|__)`)
	styleLinkInText   = regexp.MustCompile(`(!?)\[([^\]]*)\]\(([^)]*)\)`)
	styleFileName     = regexp.MustCompile(`(?i)^(\.{1,2}/|/)?([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.md(#[^ \t\n]*)?$`)
	styleWordBoundary = regexp.MustCompile(`[A-Za-z0-9-]`)
)

// check holds one page to every rule except "Every page listed", which reads
// the sidebar instead.
func (h *houseStyle) check(page, text string) []styleFault {
	var faults []styleFault
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	kinds := classifyStyleLines(lines)
	segs := styleSegments(lines, kinds)
	fault := func(line int, rule, message string) {
		if !styleExcused[[2]string{page, rule}] {
			faults = append(faults, styleFault{page, line, rule, message})
		}
	}

	// One title.
	var titles []int
	for i, k := range kinds {
		if k == styleHeading && strings.HasPrefix(lines[i], "# ") {
			titles = append(titles, i)
		}
	}
	if len(titles) == 0 {
		fault(1, "One title", "the page has no title; begin it with one line `# <title>`")
	}
	for _, i := range titles[min(1, len(titles)):] {
		fault(i+1, "One title",
			"a second line beginning `# `; the page has one title, so make this a `##` section")
	}

	// Introduction first.
	first := -1
	for i, k := range kinds {
		if k == styleHeading && strings.HasPrefix(lines[i], "## ") {
			first = i
			break
		}
	}
	if first < 0 {
		fault(1, "Introduction first", "the page has no `##` section; begin it with "+
			"`## Introduction`, one to three short paragraphs on what the page is for")
	} else if heading := strings.TrimRight(lines[first], " \t\r\n"); heading != "## Introduction" {
		fault(first+1, "Introduction first", fmt.Sprintf("the first section is `%s`; make the first "+
			"section `## Introduction`, one to three short paragraphs on what the page is for", heading))
	}

	// Introduced code, and no stacked code. A heading between two blocks puts
	// them in different sections, so it is not stacking; the block after it
	// still needs its own introduction.
	for i, k := range kinds {
		if k != styleOpen {
			continue
		}
		j := i - 1
		for j >= 0 && kinds[j] == styleBlank {
			j--
		}
		if j >= 0 && kinds[j] == styleClose {
			fault(i+1, "No stacked code", "this code block follows another with nothing between "+
				"them; put a sentence ending in `:` between the two that says what this one does")
			continue
		}
		// A list item's own text counts for a block inside the item: it is
		// the line before the block, whatever its indentation.
		if j < 0 || kinds[j] != styleProse || !strings.HasSuffix(strings.TrimRight(lines[j], " \t\r\n"), ":") {
			fault(i+1, "Introduced code", "the line before this code block does not end in `:`; "+
				"introduce the block with a sentence that says what it does and ends in a colon")
		}
	}

	// Two callouts.
	for i, k := range kinds {
		if k != styleProse {
			continue
		}
		m := styleQuotePrefix.FindStringIndex(lines[i])
		if m == nil {
			continue
		}
		content := strings.TrimRight(lines[i][m[1]:], " \t\r\n")
		if strings.HasPrefix(content, "[!") {
			if content != "[!NOTE]" && content != "[!WARNING]" {
				shown := content
				if r := []rune(shown); len(r) > 40 {
					shown = string(r[:40])
				}
				fault(i+1, "Two callouts", fmt.Sprintf("`%s` is not one of the two callouts; write "+
					"`> [!NOTE]` or `> [!WARNING]` on a line of its own", shown))
			}
			continue
		}
		// A quotation that opens with a bold label, such as **Note:**, is a
		// callout written another way. A plain quotation is not.
		opens := i == 0 || kinds[i-1] != styleProse || !styleQuotePrefix.MatchString(lines[i-1])
		if label := styleBoldLabel.FindString(content); opens && label != "" {
			fault(i+1, "Two callouts", fmt.Sprintf("a quotation that opens with %s is a callout in "+
				"disguise; write `> [!NOTE]` or `> [!WARNING]` on a line of its own instead", label))
		}
	}

	// Tables are read like any prose: a cell's words are ours. Quotations are
	// not: see styleSegments.
	var wordSegs, linkSegs []styleSegment
	for _, s := range segs {
		if s.kind == styleProse || s.kind == styleTable || s.kind == styleHeading {
			wordSegs = append(wordSegs, s)
		}
		if s.kind != styleBlank {
			linkSegs = append(linkSegs, s)
		}
	}

	// No minimisers.
	if h.minimiser != nil {
		for _, s := range wordSegs {
			for _, m := range h.minimiser.FindAllStringIndex(s.masked, -1) {
				fault(s.lineOf(m[0]), "No minimisers", fmt.Sprintf("\"%s\" tells a reader who is stuck "+
					"that the fault is theirs; delete it, or say what makes the step short", s.text[m[0]:m[1]]))
			}
		}
	}

	// One word per idea.
	for _, s := range wordSegs {
		if page == styleGlossary && s.kind == styleHeading && strings.HasPrefix(s.text, "### ") {
			// A glossary entry's heading is the term it defines. A reader who
			// meets "relying party" elsewhere looks it up by that word, and
			// the entry says which word these pages use instead.
			continue
		}
		spans := styleAllowedSpans(s.masked, h.expansions)
		type hit struct {
			from, to int
			r        styleRejected
		}
		var hits []hit
		for _, r := range h.rejected {
		next:
			for _, m := range r.pattern.FindAllStringIndex(s.masked, -1) {
				for _, sp := range spans {
					if sp[0] <= m[0] && m[1] <= sp[1] {
						continue next
					}
				}
				if styleGlossed(s.masked, m[0], m[1]) {
					continue
				}
				hits = append(hits, hit{m[0], m[1], r})
			}
		}
		// A longer phrase wins over a word inside it: "end user" is one
		// fault, not two.
		sort.SliceStable(hits, func(i, j int) bool {
			if hits[i].from != hits[j].from {
				return hits[i].from < hits[j].from
			}
			return hits[i].to-hits[i].from > hits[j].to-hits[j].from
		})
		last := -1
		for _, x := range hits {
			if x.from < last {
				continue
			}
			last = x.to
			fault(s.lineOf(x.from), "One word per idea", fmt.Sprintf("\"%s\": these pages write %s "+
				"for this idea; use that, or put the text in backticks if it is a command, path or "+
				"field name", strings.ReplaceAll(s.text[x.from:x.to], "\n", " "), x.r.write))
		}
	}

	// Short sentences, on tutorials and explanations only.
	if h.teaching[page] {
		for _, s := range segs {
			if s.kind != styleProse {
				continue
			}
			for _, sn := range styleSentences(s.masked) {
				var words [][]int
				for _, w := range styleWord.FindAllStringIndex(s.masked[sn[0]:sn[1]], -1) {
					if styleAlnum.MatchString(s.masked[sn[0]+w[0] : sn[0]+w[1]]) {
						words = append(words, w)
					}
				}
				if len(words) > styleMaxWords {
					fault(s.lineOf(sn[0]+words[0][0]), "Short sentences", fmt.Sprintf("this sentence "+
						"has %d words; split it so that none runs past %d on a tutorial or "+
						"explanation page", len(words), styleMaxWords))
				}
			}
		}
	}

	// Abbreviations. Headings are names and are not counted; the first use in
	// a paragraph, a list, a quotation or a table must be spelled out. A link
	// to the glossary is not enough on its own.
	seen := map[string]bool{}
	for _, s := range segs {
		if s.kind != styleProse && s.kind != styleTable {
			continue
		}
		type use struct {
			from, to int
			a        styleAbbreviation
		}
		var uses []use
		for _, a := range h.abbreviations {
			if seen[a.term] {
				continue
			}
			if from, to, ok := styleFirstUse(s.masked, a.term); ok {
				uses = append(uses, use{from, to, a})
			}
		}
		sort.SliceStable(uses, func(i, j int) bool {
			if uses[i].from != uses[j].from {
				return uses[i].from < uses[j].from
			}
			if uses[i].to != uses[j].to {
				return uses[i].to < uses[j].to
			}
			return uses[i].a.term < uses[j].a.term
		})
		for _, u := range uses {
			seen[u.a.term] = true
			if u.a.before.MatchString(s.text[:u.from]) || u.a.after.MatchString(s.text[u.to:]) {
				continue
			}
			fault(s.lineOf(u.from), "Abbreviations", fmt.Sprintf("the first use of %s on this page "+
				"is not spelled out; write \"%s (%s)\" here, then link the glossary entry",
				u.a.term, u.a.expansion, u.a.term))
		}
	}

	// Titles as link text. Links are found where code spans are already
	// masked, so a bracket inside code is never one. The text a reader sees
	// must be words, and a file name is not, with or without backticks, a
	// path or a heading after it.
	for _, s := range linkSegs {
		for _, m := range styleLinkInText.FindAllStringSubmatchIndex(s.codeless, -1) {
			if m[3] > m[2] {
				continue // an image, whose text is its description
			}
			shown := s.text[m[4]:m[5]]
			name := strings.Trim(strings.Trim(strings.Trim(strings.Trim(shown, " \t\n"), "*_"), "`"), " \t\n")
			if !styleFileName.MatchString(name) {
				continue
			}
			target, _, _ := strings.Cut(strings.Trim(s.text[m[6]:m[7]], " \t\r\n"), "#")
			title := ""
			if target != "" && h.titleOf != nil {
				title = h.titleOf(path.Clean(path.Join(path.Dir(page), target)))
			}
			hint := "write the page's title"
			if title != "" {
				hint = "write the page's title, \"" + title + "\","
			}
			fault(s.lineOf(m[4]), "Titles as link text", fmt.Sprintf("the link text \"%s\" is a file name; "+
				"%s or a phrase that reads naturally in the sentence",
				strings.ReplaceAll(strings.Trim(shown, " \t\r\n"), "\n", " "), hint))
		}
	}

	return faults
}

// styleFirstUse is the first place term stands as a word of its own. A
// letter, digit or hyphen before it makes it part of a longer name, as TLS is
// in EAP-TLS and mTLS; a plural s after it is still the term.
func styleFirstUse(text, term string) (int, int, bool) {
	for start := 0; ; {
		k := strings.Index(text[start:], term)
		if k < 0 {
			return 0, 0, false
		}
		from := start + k
		to := from + len(term)
		if to < len(text) && text[to] == 's' {
			to++
		}
		leftOK := from == 0 || !styleWordBoundary.MatchString(text[from-1:from])
		rightOK := to == len(text) || !styleAlnum.MatchString(text[to:to+1])
		if leftOK && rightOK {
			return from, to, true
		}
		start = from + 1
	}
}

// styleSentences is where each sentence starts and ends. A sentence ends at a
// full stop, question mark or exclamation mark followed by space and anything
// but a lower-case letter, at a list item, and at the end of the paragraph.
func styleSentences(masked string) [][2]int {
	cuts := map[int]bool{0: true, len(masked): true}
	offset := 0
	for _, ln := range strings.Split(masked, "\n") {
		if styleListMark.MatchString(ln) {
			cuts[offset] = true
		}
		offset += len(ln) + 1
	}
	for _, m := range styleSentenceEnd.FindAllStringIndex(masked, -1) {
		if m[1] >= len(masked) || masked[m[1]] < 'a' || masked[m[1]] > 'z' {
			cuts[m[1]] = true
		}
	}
	sorted := make([]int, 0, len(cuts))
	for c := range cuts {
		sorted = append(sorted, c)
	}
	sort.Ints(sorted)
	var out [][2]int
	for i := 0; i+1 < len(sorted); i++ {
		out = append(out, [2]int{sorted[i], sorted[i+1]})
	}
	return out
}

// styleListedFaults is "Every page listed": each published page appears once
// in the sidebar, except the two writing-docs.md names.
func styleListedFaults(sidebar string, pages []string) []styleFault {
	lines := strings.Split(sidebar, "\n")
	kinds := classifyStyleLines(lines)
	where := map[string][]int{}
	for i, ln := range lines {
		if kinds[i] == styleCode || kinds[i] == styleOpen || kinds[i] == styleClose {
			continue
		}
		for _, m := range styleSidebarLink.FindAllStringSubmatch(ln, -1) {
			p := path.Clean(path.Join("docs", m[1]))
			where[p] = append(where[p], i+1)
		}
	}
	var faults []styleFault
	for _, page := range pages {
		if styleUnlisted[page] {
			continue
		}
		at := where[page]
		if len(at) == 0 {
			faults = append(faults, styleFault{page, 1, "Every page listed", "the page is not in " +
				styleSidebar + "; add it, once, to the group a beginner would look in"})
		}
		for _, line := range at[min(1, len(at)):] {
			faults = append(faults, styleFault{styleSidebar, line, "Every page listed", fmt.Sprintf(
				"%s is listed again here, after line %d; list each page once",
				strings.TrimPrefix(page, "docs/"), at[0])})
		}
	}
	return faults
}

// stylePendingLine is one line of the pending list: a page and a rule it still
// breaks.
type stylePendingLine struct {
	page, rule string
	line       int
}

func readStylePending(text string) ([]stylePendingLine, []string) {
	var entries []stylePendingLine
	var problems []string
	seen := map[[2]string]bool{}
	for n, ln := range strings.Split(text, "\n") {
		s := strings.Trim(ln, " \t\r\n")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		page, rule, ok := strings.Cut(s, ": ")
		if !ok || styleRuleIndex(rule) < 0 {
			problems = append(problems, fmt.Sprintf("%s:%d: \"%s\" is not `docs/<page>.md: <rule>` with one "+
				"of the rules %s", stylePending, n+1, s, strings.Join(styleRules, ", ")))
			continue
		}
		if seen[[2]string{page, rule}] {
			problems = append(problems, fmt.Sprintf("%s:%d: %s is listed twice; delete this line",
				stylePending, n+1, s))
			continue
		}
		seen[[2]string{page, rule}] = true
		entries = append(entries, stylePendingLine{page, rule, n + 1})
	}
	return entries, problems
}

// styleRatchet splits the faults into those the pending list does not hold,
// and the pending lines whose page no longer breaks the rule, or no longer
// exists.
func styleRatchet(faults []styleFault, pending []stylePendingLine, tracked map[string]bool) (unlisted []styleFault, stale []string) {
	listed := map[[2]string]bool{}
	for _, p := range pending {
		listed[[2]string{p.page, p.rule}] = true
	}
	broken := map[[2]string]bool{}
	for _, f := range faults {
		broken[[2]string{f.page, f.rule}] = true
		if !listed[[2]string{f.page, f.rule}] {
			unlisted = append(unlisted, f)
		}
	}
	for _, p := range pending {
		switch {
		case !tracked[p.page]:
			stale = append(stale, fmt.Sprintf("%s:%d: %s is no longer a page git tracks; delete the line "+
				"\"%s: %s\"", stylePending, p.line, p.page, p.page, p.rule))
		case !broken[[2]string{p.page, p.rule}]:
			stale = append(stale, fmt.Sprintf("%s:%d: %s now passes %s; delete the line \"%s: %s\"",
				stylePending, p.line, p.page, p.rule, p.page, p.rule))
		}
	}
	return unlisted, stale
}

// loadHouseStyle reads the three pages the rules come from, as the repository
// has them.
func loadHouseStyle(t *testing.T, root string) *houseStyle {
	t.Helper()
	read := func(rel string) string { return readRaw(t, filepath.Join(root, filepath.FromSlash(rel))) }
	style, problems := newHouseStyle(read(styleWritingDocs), read(styleGlossary), read(styleSidebar))
	for _, p := range problems {
		t.Error(p)
	}
	named := style.titleOf
	style.titleOf = func(p string) string {
		if title := named(p); title != "" {
			return title
		}
		// Not in the sidebar, such as a README elsewhere in the repository:
		// its own title.
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			return ""
		}
		for _, ln := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(ln, "# ") {
				return strings.Trim(ln[2:], " \t\r\n")
			}
		}
		return ""
	}
	return style
}

func TestTheDocsFollowTheHouseStyle(t *testing.T) {
	root := repoRoot(t)
	pages := trackedDocs(t, root)
	tracked := map[string]bool{}
	for _, p := range pages {
		tracked[p] = true
	}
	style := loadHouseStyle(t, root)

	for page, writer := range styleGenerated {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(writer)))
		if err != nil || !strings.Contains(string(src), path.Base(page)) {
			t.Errorf("%s is exempt from the house style as generated by %s, which no longer mentions "+
				"it; remove the exemption, or name the file that writes it now", page, writer)
		}
	}

	var faults []styleFault
	for _, page := range pages {
		if styleGenerated[page] != "" || styleNotProse[page] {
			continue
		}
		faults = append(faults, style.check(page, readRaw(t, filepath.Join(root, filepath.FromSlash(page))))...)
	}
	faults = append(faults, styleListedFaults(readRaw(t, filepath.Join(root, filepath.FromSlash(styleSidebar))), pages)...)
	sortStyleFaults(faults)

	pending, problems := readStylePending(readRaw(t, filepath.Join(root, filepath.FromSlash(stylePending))))
	for _, p := range problems {
		t.Error(p)
	}
	unlisted, stale := styleRatchet(faults, pending, tracked)
	if len(unlisted) > 0 {
		shown := make([]string, len(unlisted))
		for i, f := range unlisted {
			shown[i] = f.String()
		}
		t.Errorf("%d place(s) break the house style of %s:\n  %s\n\n"+
			"Each line names the page, the line, the rule and what to do. Fix the page. %s "+
			"holds only the faults the pages had when this test was written, and it only "+
			"shrinks, so a new fault is fixed rather than added there.",
			len(unlisted), styleWritingDocs, strings.Join(shown, "\n  "), stylePending)
	}
	if len(stale) > 0 {
		t.Errorf("%d line(s) of the pending list name a fault that is gone:\n  %s\n\n"+
			"Delete each line, so that the list keeps shrinking and a page cannot slide back.",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// styleCleanPage passes every rule, while using each thing the rules must
// leave alone: a glossed word, the allowed names, a command, a path and a
// file name written outside code, a quotation whose words are not ours to
// change, and an introduced block inside a list item.
const styleCleanPage = "# A clean page\n" + // 1
	"\n" +
	"## Introduction\n" + // 3
	"\n" +
	"Signari signs people in. OpenID Connect (OIDC) is what most applications speak.\n" + // 5
	"\n" +
	"The protocols call an application a \"relying party\". A browser is a user agent. Back-Channel Logout keeps its name.\n" + // 7
	"The Admin API takes an admin token. Run signari user create, then open /login\n" + // 8
	"or read logout.md. A passkey has a relying party ID, and an authenticator app\n" + // 9
	"shows a code. See [how Signari works](how-signari-works.md). The Kubernetes operator deploys Signari, and the operator keeps it running. A policy operator trims a list.\n" + // 10
	"\n" +
	"> [!NOTE]\n" + // 12
	"> A note points somewhere else.\n" +
	"\n" +
	"> The End-User logs in to the relying party, just as the specification says.\n" + // 15
	"\n" +
	"Run the check:\n" + // 17
	"\n" +
	"```sh\n" + // 19
	"signari doctor\n" +
	"```\n" +
	"\n" +
	"Then run it again, with JSON:\n" + // 23
	"\n" +
	"```sh\n" + // 25
	"signari doctor -o json\n" +
	"```\n" +
	"\n" +
	"- Show the version:\n" + // 29
	"\n" +
	"  ```sh\n" + // 31
	"  signari version\n" +
	"  ```\n"

// The guard's own guard: each rule, given one fault, names the page, the line
// and the rule, and nothing else. A rule that matched nothing would pass every
// page, and look exactly like a docs tree that follows the style.
func TestEachHouseStyleRuleNamesThePageLineAndRule(t *testing.T) {
	style := loadHouseStyle(t, repoRoot(t))
	// An introduction: a tutorial page, so that "Short sentences" applies.
	const page = "docs/introduction.md"
	if got := style.check(page, styleCleanPage); len(got) != 0 {
		t.Fatalf("the clean page breaks the house style, so it proves nothing:\n%v", got)
	}
	for _, tc := range []struct {
		rule     string
		old, new string
		line     int
	}{
		{"One title", "shows a code.", "shows a code.\n\n# A second title\n", 12},
		{"Introduction first", "## Introduction", "## Overview", 3},
		{"Introduced code", "Run the check:", "Run the check.", 19},
		{"Introduced code", "- Show the version:", "- Show the version.", 31},
		{"No stacked code", "Then run it again, with JSON:\n\n", "", 23},
		{"Two callouts", "> [!NOTE]", "> [!TIP]", 12},
		{"Two callouts", "> [!NOTE]", "> [!NOTE] A note points somewhere else.", 12},
		{"Two callouts", "> The End-User", "> **Note:** The End-User", 15},
		{"One word per idea", "> A note points somewhere else.", "> A note points the user somewhere else.", 13},
		{"No minimisers", "Signari signs people in.", "Signari simply signs people in.", 5},
		{"One word per idea", "Signari signs people in.", "Signari signs users in.", 5},
		{"One word per idea", "Signari signs people in.", "Signari lets people log in.", 5},
		{"One word per idea", "A browser is a user agent.", "A browser is a user agent for the tenant.", 7},
		// The allowed names stop at their own words: a bare "app", a
		// lowercase "logout" and a title written in lowercase are still
		// faults.
		{"One word per idea", "and an authenticator app", "and an app", 9},
		{"One word per idea", "Signari signs people in.", "Signari signs people out at logout.", 5},
		{"One word per idea", "Back-Channel Logout keeps", "back-channel logout keeps", 7},
		// "the operator" is the Kubernetes operator only after the paragraph
		// has named it, and "an operator" is a person even then.
		{"One word per idea", "The Kubernetes operator deploys", "The chart deploys", 10},
		{"One word per idea", "and the operator keeps", "and an operator keeps", 10},
		// A "policy operator" is OpenID Federation's rule, and only the
		// compound is: a bare "operator" is still the person.
		{"One word per idea", "A policy operator trims", "An operator trims", 10},
		{"Short sentences", "Signari signs people in.", "Signari signs people in to every application " +
			"they use, at work and at home, with one account, one password and one second factor " +
			"for all of them.", 5},
		{"Abbreviations", "OpenID Connect (OIDC) is", "OIDC is", 5},
		{"Abbreviations", "OpenID Connect (OIDC) is", "[OIDC](glossary.md#oidc) is", 5},
		{"Titles as link text", "[how Signari works](how-signari-works.md)", "[how-signari-works.md](how-signari-works.md)", 10},
		{"Titles as link text", "[how Signari works](how-signari-works.md)", "[`docs/how-signari-works.md#tokens`](how-signari-works.md#tokens)", 10},
	} {
		if !strings.Contains(styleCleanPage, tc.old) {
			t.Fatalf("%s: the clean page has no %q to change", tc.rule, tc.old)
		}
		got := style.check(page, strings.Replace(styleCleanPage, tc.old, tc.new, 1))
		if len(got) != 1 || got[0].page != page || got[0].rule != tc.rule || got[0].line != tc.line {
			t.Errorf("%s: changing %q to %q should give one fault, %s line %d, and gave %d:\n%v",
				tc.rule, tc.old, tc.new, page, tc.line, len(got), got)
		}
	}

	// Every page listed reads the sidebar, not the page.
	sidebar := "# Documentation\n\n- ## Getting started\n    - [Introduction](introduction.md)\n" +
		"    - [Again](introduction.md)\n"
	got := styleListedFaults(sidebar, []string{"docs/introduction.md", "docs/glossary.md", "docs/README.md"})
	want := []string{
		"docs/documentation.md:5: Every page listed: introduction.md is listed again here, after line 4; list each page once",
		"docs/glossary.md:1: Every page listed: the page is not in docs/documentation.md; add it, once, to the group a beginner would look in",
	}
	sortStyleFaults(got)
	if len(got) != len(want) {
		t.Fatalf("Every page listed gave %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("Every page listed gave\n  %s\nwant\n  %s", got[i], want[i])
		}
	}
}

// The ratchet holds a listed fault, refuses an unlisted one, and refuses a
// line whose page now passes, so that the list can only shrink.
func TestTheHouseStyleRatchetOnlyShrinks(t *testing.T) {
	pending, problems := readStylePending("# a comment\n\ndocs/a.md: Introduced code\n" +
		"docs/b.md: Abbreviations\ndocs/gone.md: One title\ndocs/a.md: Not a rule\n")
	if len(problems) != 1 || !strings.Contains(problems[0], "Not a rule") {
		t.Errorf("an unknown rule should be the one problem, got %v", problems)
	}
	faults := []styleFault{
		{"docs/a.md", 3, "Introduced code", "listed, so held"},
		{"docs/c.md", 1, "One title", "not listed, so refused"},
	}
	tracked := map[string]bool{"docs/a.md": true, "docs/b.md": true, "docs/c.md": true}
	unlisted, stale := styleRatchet(faults, pending, tracked)
	if len(unlisted) != 1 || unlisted[0].page != "docs/c.md" {
		t.Errorf("only docs/c.md's fault is unlisted, got %v", unlisted)
	}
	want := []string{
		stylePending + ":4: docs/b.md now passes Abbreviations; delete the line \"docs/b.md: Abbreviations\"",
		stylePending + ":5: docs/gone.md is no longer a page git tracks; delete the line \"docs/gone.md: One title\"",
	}
	if strings.Join(stale, "\n") != strings.Join(want, "\n") {
		t.Errorf("stale lines:\n  %s\nwant\n  %s", strings.Join(stale, "\n  "), strings.Join(want, "\n  "))
	}
}
