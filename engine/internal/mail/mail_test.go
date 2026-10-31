package mail

import (
	"errors"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"testing"
)

// Header injection. A newline in a subject or address lets an attacker append
// their own headers -- Bcc: themselves on every password reset, for instance.
// The display name and subject are the fields most likely to carry user input.
func TestHeaderInjectionIsNeutralised(t *testing.T) {
	s := &SMTPSender{
		FromAddr: "noreply@example.com",
		FromName: "Signari\r\nBcc: attacker@evil.test",
	}
	msg, err := s.build(Message{
		To:      "user@example.com",
		Subject: "Reset\r\nBcc: attacker@evil.test",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The property is that no NEW HEADER LINE was created. "Bcc:" appearing as
	// literal text inside a Subject value is harmless -- it is one header whose
	// value happens to contain a colon. What must never happen is a line of its
	// own, which is what a surviving CRLF would produce.
	headers, _, _ := strings.Cut(msg, "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "bcc", "cc", "to", "from", "subject", "mime-version", "content-type",
			"auto-submitted", "x-auto-response-suppress":
			// Expected headers only; a "bcc" here would mean injection succeeded.
			if strings.EqualFold(strings.TrimSpace(name), "bcc") {
				t.Fatalf("an injected Bcc became a real header:\n%s", headers)
			}
		default:
			t.Errorf("unexpected header %q -- injection may have created it", name)
		}
	}
	// And no bare CR or LF may survive anywhere in the header block.
	if strings.Contains(headers, "\n\n") || strings.Count(headers, "\r") != strings.Count(headers, "\n") {
		t.Error("unbalanced line endings in the header block")
	}
	for _, want := range []string{"From: ", "To: ", "Subject: ", "Content-Type: multipart/alternative"} {
		if !strings.Contains(headers, want) {
			t.Errorf("missing header %q", want)
		}
	}
}

// An organisation's sender is written by an operator, so the name on it gets the
// same treatment as the deployment's.
func TestAnOrganisationsSenderCannotInjectAHeader(t *testing.T) {
	s := &SMTPSender{FromAddr: "noreply@example.com"}
	msg, err := s.build(Message{To: "u@example.com", Subject: "s", Body: "b",
		From: "id@acme.example", FromName: "Acme\r\nBcc: attacker@evil.test"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Header.Get("Bcc"); got != "" {
		t.Fatalf("an injected Bcc became a real header: %q", got)
	}
	from, err := mail.ParseAddress(parsed.Header.Get("From"))
	if err != nil || from.Address != "id@acme.example" {
		t.Errorf("From = %v (%v), wanting the organisation's address", from, err)
	}
}

// Without a sender of its own an organisation's mail is the deployment's, name
// included: a name from one sender on the address of another would be a lie.
func TestTheSenderIsOneOrTheOther(t *testing.T) {
	s := &SMTPSender{FromAddr: "noreply@example.com", FromName: "Example Identity"}
	for _, c := range []struct {
		name       string
		m          Message
		addr, says string
	}{
		{"the deployment's", Message{}, "noreply@example.com", "Example Identity"},
		{"the organisation's", Message{From: "id@acme.example", FromName: "Acme"}, "id@acme.example", "Acme"},
		{"an address with no name", Message{From: "id@acme.example"}, "id@acme.example", ""},
	} {
		c.m.To, c.m.Subject, c.m.Body = "u@example.com", "s", "b"
		msg, err := s.build(c.m)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := mail.ReadMessage(strings.NewReader(msg))
		if err != nil {
			t.Fatal(err)
		}
		from, err := mail.ParseAddress(parsed.Header.Get("From"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if from.Address != c.addr || from.Name != c.says {
			t.Errorf("%s: From = %q %q, wanting %q %q", c.name, from.Name, from.Address, c.says, c.addr)
		}
	}
}

// parts reads a built message the way a mail client does.
func parts(t *testing.T, raw string) (plain, page string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	kind, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" {
		t.Fatalf("Content-Type = %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	var order []string
	for {
		part, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		// NextPart undoes the quoted-printable, as a client does.
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		kind, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, kind)
		switch kind {
		case "text/plain":
			plain = string(body)
		case "text/html":
			page = string(body)
		default:
			t.Errorf("a part of type %q", kind)
		}
	}
	// A client shows the last it can, so the plainest comes first.
	if len(order) != 2 || order[0] != "text/plain" || order[1] != "text/html" {
		t.Fatalf("parts in the order %v", order)
	}
	return plain, page
}

// Both parts, the same words in each, on the same message.
func TestAMessageCarriesBothParts(t *testing.T) {
	s := &SMTPSender{FromAddr: "noreply@example.com"}
	body := "Your code is 123456.\n\nIt lasts ten minutes.\n\n" + strings.Repeat("long line ", 200)
	raw, err := s.build(Message{To: "u@example.com", Subject: "Your code", Body: body,
		Look: Look{Product: "Acme Identity", Background: "#fafafa", Text: "#101010", Link: "#aa0000"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "Auto-Submitted: auto-generated") {
		t.Error("transactional mail must not invite auto-replies")
	}
	plain, page := parts(t, raw)
	if strings.ReplaceAll(plain, "\r\n", "\n") != body {
		t.Errorf("the text part changed the words:\n%q", plain)
	}
	for _, want := range []string{"Your code is 123456.", "It lasts ten minutes.", "Acme Identity",
		"background:#fafafa", "color:#101010"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q:\n%s", want, page)
		}
	}
	// SMTP's own limit is 998 octets a line, and nothing above it survives a relay.
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("a line of %d octets", len(line))
		}
	}
}

// What a message says is text, whoever wrote it: a display name, a device or a
// provider's name can reach a body, and none of them may become markup.
func TestTheBodyIsEscaped(t *testing.T) {
	page, err := render(Message{Subject: "<b>s</b>", Body: `<script>alert(1)</script> & <img src=x onerror=y>`,
		Look: Look{Product: "<i>Acme</i>"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script", "<img", "<i>", "<b>"} {
		if strings.Contains(page, bad) {
			t.Errorf("%q came through unescaped:\n%s", bad, page)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Errorf("the words themselves were lost:\n%s", page)
	}
}

// The reason for the layout: a message never hides where a link goes. If this
// fails because somebody wants a button, the test is the argument against it.
func TestEveryLinkShowsWhereItGoes(t *testing.T) {
	body := "Open https://id.example/enrol?token=abc&x=1 to finish.\n\n" +
		"Or see (https://id.example/account/security), or http://id.example/a."
	page, err := render(Message{Subject: "s", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	anchor := regexp.MustCompile(`<a\b[^>]*href="([^"]*)"[^>]*>([^<]*)</a>`)
	found := anchor.FindAllStringSubmatch(page, -1)
	want := []string{"https://id.example/enrol?token=abc&x=1", "https://id.example/account/security",
		"http://id.example/a"}
	if len(found) != len(want) {
		t.Fatalf("%d links, wanting %d:\n%s", len(found), len(want), page)
	}
	for i, m := range found {
		href, text := html.UnescapeString(m[1]), html.UnescapeString(m[2])
		if href != text {
			t.Errorf("a link to %q reads %q", href, text)
		}
		if href != want[i] {
			t.Errorf("link %d is %q, wanting %q", i, href, want[i])
		}
	}
	// The sentence keeps what the link gave back.
	if !strings.Contains(page, "</a>) , or") && !strings.Contains(page, "</a>), or") {
		t.Errorf("the bracket after a link was lost:\n%s", page)
	}
	// A page with nothing to load has nothing that tells a sender it was opened,
	// and one with a form or a button has what the layout exists to leave out.
	for _, bad := range []string{"<img", "<button", "<form", "<script", "src=", "url("} {
		if strings.Contains(page, bad) {
			t.Errorf("the layout grew %q", bad)
		}
	}
}

// A colour lands in a style attribute, so only a colour is let in.
func TestALookIsOnlyColours(t *testing.T) {
	for _, bad := range []string{"red;background:url(https://evil.test/x)", "#12345", "#gggggg", "expression(1)"} {
		page, err := render(Message{Subject: "s", Body: "b", Look: Look{Background: bad, Text: bad, Link: bad}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(page, "evil.test") || !strings.Contains(page, "background:#ffffff") {
			t.Errorf("a colour of %q reached the page:\n%s", bad, page)
		}
	}
}

// Arabic is read right to left in a part the client lays out itself.
func TestEachParagraphFindsItsOwnDirection(t *testing.T) {
	page, err := render(Message{Subject: "s", Body: "رمزك 123456"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, `<p dir="auto"`) || !strings.Contains(page, "رمزك 123456") {
		t.Errorf("the paragraph has no direction of its own:\n%s", page)
	}
}

func TestRefusesMalformedRecipients(t *testing.T) {
	s := &SMTPSender{Host: "127.0.0.1", Port: 1, FromAddr: "noreply@example.com"}
	for _, bad := range []string{"", "not-an-address", "a@b@c", "user@example.com\r\nBcc: x@y.z"} {
		if err := s.Send(t.Context(), Message{To: bad, Subject: "s", Body: "b"}); err == nil {
			t.Errorf("accepted recipient %q", bad)
		}
	}
}

// A report with any Fail must not claim deliverability.
func TestReportDeliverability(t *testing.T) {
	r := Report{Findings: []Finding{{Severity: Pass}, {Severity: Warn}}}
	if !r.Deliverable() {
		t.Error("warnings alone should not mark mail undeliverable")
	}
	r.Findings = append(r.Findings, Finding{Severity: Fail})
	if r.Deliverable() {
		t.Error("a failing check was reported as deliverable")
	}
}
