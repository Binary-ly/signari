package pages

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"signari.dev/engine/internal/i18n"
)

// A rendered copy of every page, for looking at.
//
// The validator proves a page still carries its CSRF token; it cannot tell you
// the button is now invisible against the background, or that a heading wraps
// badly at 320px. Those need eyes, and eyes need something to look at.
//
//	SIGNARI_PAGE_PREVIEW_DIR=/tmp/pages go test ./internal/pages/ -run Preview
//
// Off unless that variable is set, so an ordinary `go test ./...` neither writes
// files nor slows down.
//
// The sample data below is deliberately REALISTIC rather than minimal: real
// application names, a real-looking error, eight recovery codes rather than one.
// A page reviewed with the word "x" in every field looks fine and tells you
// nothing about the page a person actually meets.
func TestPreview(t *testing.T) {
	out := os.Getenv("SIGNARI_PAGE_PREVIEW_DIR")
	if out == "" {
		t.Skip("set SIGNARI_PAGE_PREVIEW_DIR to write a preview of every page")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}

	set := loadOrFail(t, "")
	bundle := set.Bundle()
	// One set of sample data per language, because some of what a handler puts
	// into a page is itself translated -- the scope descriptions on the consent
	// screen most of all. Rendering one English dataset in Arabic would show a
	// half-translated consent screen that the real server never produces.
	samples := previewData(bundle.For("en"))
	samplesAr := previewData(bundle.For("ar"))

	// Every page must have sample data, or the preview quietly covers less than
	// it appears to and a page nobody looked at ships unreviewed.
	var missing []string
	for _, name := range set.Names() {
		if _, ok := samples[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d page(s) have no preview data, so they would be silently "+
			"absent from the review: %s", len(missing), strings.Join(missing, ", "))
	}

	// Four copies of every page: as the viewer's own setting renders it, one
	// pinned to each theme, and one carrying an operator's brand colours.
	//
	// Baked into the file rather than switched by script in the contact sheet,
	// because a review has to be looking at a fixed thing. It also exercises the
	// real mechanism -- data-theme on <html> is exactly what an operator writes
	// into a layout override to pin one theme.
	themes := []struct{ dir, attr string }{
		{"", ""}, {"light", ` data-theme="light"`}, {"dark", ` data-theme="dark"`},
		{"brand", ""}, // colours injected below, the way writeBranded does it
	}
	for _, th := range themes {
		if th.dir != "" {
			if err := os.MkdirAll(filepath.Join(out, th.dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Arabic gets its own directory rather than a theme attribute: it is a
	// different render, not a restyle of the same one.
	if err := os.MkdirAll(filepath.Join(out, "ar"), 0o755); err != nil {
		t.Fatal(err)
	}

	var wrote []previewEntry
	const openTag = `<html lang="en" dir="ltr">`

	for _, name := range set.Names() {
		var sb strings.Builder
		if err := set.Execute(&sb, name, samples[name]); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		page := sb.String()
		if !strings.Contains(page, openTag) {
			t.Errorf("%s does not open with %s, so the preview cannot pin a theme "+
				"on it and it would be reviewed in only one", name, openTag)
			continue
		}
		for _, th := range themes {
			body := strings.Replace(page, openTag,
				`<html lang="en" dir="ltr"`+th.attr+`>`, 1)
			if th.dir == "brand" {
				body = brandedLikeTheServer(body)
			}
			if err := os.WriteFile(filepath.Join(out, th.dir, name+".html"),
				[]byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		// The same page in Arabic, which is the only variant that exercises
		// right-to-left layout and the plural forms English cannot reach. A
		// translation nobody looks at is a translation nobody has checked.
		var ar strings.Builder
		if err := set.ExecuteIn(&ar, "ar", name, samplesAr[name]); err != nil {
			t.Errorf("%s in Arabic: %v", name, err)
			continue
		}
		if err := os.WriteFile(filepath.Join(out, "ar", name+".html"),
			[]byte(ar.String()), 0o644); err != nil {
			t.Fatal(err)
		}

		wrote = append(wrote, previewEntry{name, name + ".html"})
	}
	sort.Slice(wrote, func(i, j int) bool { return wrote[i].Name < wrote[j].Name })

	for _, th := range themes {
		label := "your system setting"
		switch th.dir {
		case "light", "dark":
			label = th.dir
		case "brand":
			label = "an operator's brand colours"
		}
		file := filepath.Join(out, "index.html")
		if th.dir != "" {
			file = filepath.Join(out, th.dir, "index.html")
		}
		if err := os.WriteFile(file,
			[]byte(contactSheet(wrote, label, th.attr, th.dir)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "ar", "index.html"),
		[]byte(contactSheet(wrote, "Arabic, right-to-left", "", "ar")), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d page(s) x 5 variants to %s (index.html, light/, dark/, "+
		"brand/, ar/)", len(wrote), out)
}

type previewEntry struct{ Name, File string }

// brandedLikeTheServer injects an operator palette the same way writeBranded
// does at runtime: a :root block appended at the very end of <head>.
//
// This is the variant worth looking at hardest. Every token in the stylesheet
// reads its brand variable at the point the token is DEFINED, and the greys are
// then mixed from the operator's own surface and text -- so if that mixing is
// wrong, it is wrong on every page at once and this is where it shows.
func brandedLikeTheServer(page string) string {
	const css = `<style>:root{--brand-primary:#166534;--brand-on-primary:#ffffff;` +
		`--brand-background:#fbfaf7;--brand-text:#1c1917;}</style>`
	i := strings.LastIndex(page, "</head>")
	if i < 0 {
		return page
	}
	return page[:i] + css + page[i:]
}

// contactSheet is one page showing all of them at once.
//
// Live iframes rather than screenshots, so what is being reviewed is the real
// page at a real width, and clicking through opens the same file full size.
func contactSheet(entries []previewEntry, label, attr, dir string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"` + attr + `><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signari pages</title><style>`)
	b.WriteString(`
/* The chrome follows the switch too. Judging a light palette while it sits in a
   dark surround tells you about the surround, not the palette. */
:root{color-scheme:light dark;--bg:#f6f6f7;--fg:#18181b;--mut:#71717a;--line:#e4e4e7;--card:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#09090b;--fg:#ededf0;--mut:#a1a1aa;--line:#27272a;--card:#141417}}
:root[data-theme="dark"]{color-scheme:dark;
--bg:#09090b;--fg:#ededf0;--mut:#a1a1aa;--line:#27272a;--card:#141417}
:root[data-theme="light"]{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);
font:.9375rem/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
-webkit-font-smoothing:antialiased}
h1{margin:0 0 .25rem;font-size:1.375rem;font-weight:600;letter-spacing:-.022em}
.sub{margin:0 0 2rem;color:var(--mut);font-size:.875rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(23rem,1fr));gap:1.25rem}
figure{margin:0}
.frame{height:30rem;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden}
iframe{width:100%;height:100%;border:0;display:block}
figcaption{display:flex;align-items:baseline;gap:.5rem;margin-top:.5rem;font-size:.8125rem}
figcaption a{color:inherit;font-weight:500;text-decoration:none}
figcaption a:hover{text-decoration:underline}
figcaption span{color:var(--mut);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
font-size:.75rem}
.bar{display:flex;align-items:center;gap:.5rem;margin:0 0 2rem}
.bar button{font:inherit;font-size:.8125rem;font-weight:500;padding:.3125rem .75rem;
color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:7px;
cursor:pointer}
.bar a{font-size:.8125rem;font-weight:500;padding:.3125rem .75rem;text-decoration:none;
color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:7px}
.bar a[aria-current="page"]{background:var(--fg);color:var(--bg);border-color:var(--fg)}
</style></head><body>
<h1>Signari sign-in pages</h1>
<p class="sub">Every built-in page, rendered live, in ` + label + `.
Click a name to open one full size.</p>
<div class="bar">` + themeLinks(dir) + `</div>
<div class="grid">
`)
	// The auto-posting bridges submit themselves the moment they load, so an
	// ordinary iframe shows whatever their form action returned -- here, a failed
	// navigation. Sandboxing WITHOUT allow-scripts stops the submit, which also
	// happens to be the only state a person ever sees one of these pages in: the
	// <noscript> fallback.
	selfSubmitting := map[string]bool{"saml": true, "formpost": true, "wsfed": true}

	for _, e := range entries {
		attrs, note := "", ""
		if selfSubmitting[e.Name] {
			attrs = ` sandbox="allow-same-origin"`
			note = ` &middot; scripting off`
		}
		// Not loading="lazy": thirty-three local files cost nothing to load at
		// once, and a frame that is still blank when you scroll past it is a frame
		// that did not get reviewed.
		fmt.Fprintf(&b, `<figure><div class="frame"><iframe src="%s" title="%s"%s></iframe></div>`+
			`<figcaption><a href="%s" target="_blank">%s</a><span>%s%s</span></figcaption></figure>`+"\n",
			e.File, e.Name, attrs, e.File, e.Name, e.File, note)
	}
	b.WriteString("</div></body></html>\n")
	return b.String()
}

// themeLinks is the switch: three plain links to three prebuilt sheets. No
// script, so what is on screen is only ever the file that was opened.
func themeLinks(dir string) string {
	links := []struct{ href, text, match string }{
		{"/index.html", "System", ""},
		{"/light/index.html", "Light", "light"},
		{"/dark/index.html", "Dark", "dark"},
		{"/brand/index.html", "Branded", "brand"},
		// The only variant that shows right-to-left layout and the plural forms
		// English has no way to reach.
		{"/ar/index.html", "العربية", "ar"},
	}
	var b strings.Builder
	for _, l := range links {
		cur := ""
		if l.match == dir {
			cur = ` aria-current="page"`
		}
		fmt.Fprintf(&b, `<a href="%s"%s>%s</a>`, l.href, cur, l.text)
	}
	return b.String()
}

// describeScopeLikeTheServer mirrors httpapi.describeScope.
//
// Mirrored rather than imported because internal/httpapi imports this package,
// so reaching back into it would be a cycle. The pairing is held by
// TestThePreviewDescribesScopesTheWayTheServerDoes, which fails if the two
// drift -- which is the actual risk, and worth a test rather than a comment.
func describeScopeLikeTheServer(p *i18n.Printer, scope string) string {
	if key := "scope." + scope; p.Has(key) {
		return string(p.T(key))
	}
	return scope
}

func previewData(p *i18n.Printer) map[string]map[string]any {
	// Shared by every page that posts a form back.
	csrf := func(m map[string]any) map[string]any {
		m["CSRF"] = "8f2c1d94a7be4e0f9c3a5b6d8e1f2a3b"
		m["CSRFField"] = "csrf_token"
		return m
	}
	const authz = "6a1f9c2e-4d7b-4a83-9e15-2c8f7b0d4e61"

	qr := template.HTML(`<svg viewBox="0 0 25 25" xmlns="http://www.w3.org/2000/svg" ` +
		`shape-rendering="crispEdges"><rect width="25" height="25" fill="#fff"/>` +
		qrBlocks() + `</svg>`)

	return map[string]map[string]any{
		"login": csrf(map[string]any{
			"Authz": authz, "Error": "", "Reference": "",
			"Providers": []map[string]any{
				{"Name": "Okta", "Slug": "okta"},
				{"Name": "Google Workspace", "Slug": "google"},
			},
			"BrandSupport": "",
		}),
		"mfa": csrf(map[string]any{
			"Authz": authz,
			"Error": "That code was not correct. Two attempts remain.",
			"Ref":   "", "Reference": "7QF-2K9",
		}),
		"consent": csrf(map[string]any{
			"Client": "Northwind Analytics", "ClientID": "northwind-analytics", "Authz": authz,
			// Descriptions looked up rather than written here, because the
			// server looks them up too. Inventing them once produced a preview
			// showing wording the product does not actually use -- and, once
			// the catalogue existed, a consent screen whose scope list stayed
			// English in every language while the rest of the page translated.
			//
			// invoices.read is deliberately not in the catalogue: it stands for
			// a client-registered scope, which we cannot translate and show
			// verbatim. Seeing that in the review is the point.
			"Scopes": []map[string]any{
				{"Name": "profile", "Description": describeScopeLikeTheServer(p, "profile")},
				{"Name": "email", "Description": describeScopeLikeTheServer(p, "email")},
				{"Name": "offline_access", "Description": describeScopeLikeTheServer(p, "offline_access")},
				{"Name": "invoices.read", "Description": describeScopeLikeTheServer(p, "invoices.read")},
			},
			"Details": []map[string]any{{
				"Type": "payment_initiation",
				"Rows": []map[string]any{
					{"Label": "Amount", "Value": "£1,250.00"},
					{"Label": "To", "Value": "Contoso Ltd"},
					{"Label": "Reference", "Value": "INV-2026-0841"},
				},
			}},
		}),
		// Scopes here is []string -- device.go builds it with strings.Fields, not
		// the {Name,Description} pairs the consent page uses. Getting this wrong
		// in the sample data printed `map[Description:… Name:openid]` on screen
		// and looked exactly like a template bug.
		"device": csrf(map[string]any{
			"ClientName": "Signari CLI", "UserCode": "BDWP-HQPJ",
			"Scopes":  []string{"openid", "offline_access"},
			"Confirm": true, "Denied": false, "Done": false, "Error": "",
		}),
		"emailotp": csrf(map[string]any{
			"Address": "amelia.hart@example.com", "Stage": "verify", "Error": "",
		}),
		"smsotp": csrf(map[string]any{
			"Number": "+44 7700 •••912", "Stage": "verify", "Configured": true, "Error": "",
		}),
		"enrol": csrf(map[string]any{
			"Secret": "JBSWY3DPEHPK3PXP", "QR": qr,
			"URI":   "otpauth://totp/Example:amelia.hart@example.com?secret=JBSWY3DPEHPK3PXP",
			"Error": "",
		}),
		"recovery": map[string]any{
			"Codes": []string{
				"4f2a-9c1b", "7d38-e05a", "b16c-4429", "0e7f-a3d2",
				"91ba-6c40", "cc25-71ef", "38d9-04b7", "a5e1-8f33",
			},
		},
		"recover": csrf(map[string]any{}),
		// The reason is a message KEY in the database, resolved at render time --
		// see httpapi.renderChangeReason. Written as the key here so the preview
		// shows what the product does rather than an English sentence that would
		// stay English in every language.
		"changepw": csrf(map[string]any{"Reason": p.T("reason.administrator"), "Error": ""}),
		"reset": csrf(map[string]any{
			"Ready": true, "Pending": false, "Wait": "", "When": "",
			"Token": "0a94c1f7-6b2e-4d38-9f05-71c8ea4b2d63", "Error": "",
		}),
		"sent":       map[string]any{},
		"done":       map[string]any{},
		"cancelled":  map[string]any{},
		"logout":     map[string]any{"Action": "/logout", "Field": "csrf_token", "CSRF": "8f2c1d94a7be4e0f"},
		"signupdone": map[string]any{"Email": "amelia.hart@example.com"},
		// Domains is a STRING -- signup.go joins it before it gets here. Passing a
		// slice rendered "[example.com example.org]" and looked like the page was
		// printing a raw Go value; the page was right and the sample was wrong.
		"signup": csrf(map[string]any{
			"Email": "amelia.hart@example.com", "EmailFixed": false,
			"Invite": "", "Domains": "example.com, example.org", "Error": "",
		}),
		"account": csrf(map[string]any{
			"Providers": []map[string]any{
				{"Name": "Okta", "Slug": "okta", "Linked": true,
					"Email": "amelia.hart@example.com", "Verified": true},
				{"Name": "GitHub", "Slug": "github", "Linked": true,
					"Email": "amelia@users.noreply.github.com", "Verified": false},
				{"Name": "Google Workspace", "Slug": "google", "Linked": false},
			},
		}),
		"connected": map[string]any{
			"CSRF": "8f2c1d94a7be4e0f", "Message": "",
			"Apps": []map[string]any{
				{"Name": "Northwind Analytics", "ClientID": "northwind-analytics",
					"Scopes":  []string{"openid", "profile", "invoices.read"},
					"Granted": "14 March 2026", "ActiveTokens": 2},
				{"Name": "Contoso Expenses", "ClientID": "contoso-expenses",
					"Scopes":  []string{"openid", "email"},
					"Granted": "2 January 2026", "ActiveTokens": 0},
			},
		},
		"portal": map[string]any{
			"Empty": false,
			"Open": []map[string]any{
				{"Name": "Northwind Analytics", "LaunchURL": "https://analytics.example.com", "LogoURI": "", "Unlaunchable": false},
				{"Name": "Contoso Expenses", "LaunchURL": "https://expenses.example.com", "LogoURI": "", "Unlaunchable": false},
				{"Name": "Fabrikam Wiki", "LaunchURL": "", "LogoURI": "", "Unlaunchable": true},
			},
			"Blocked": []map[string]any{
				{"Name": "Payroll", "Reason": "Requires the finance group."},
				{"Name": "Production console", "Reason": "Requires a hardware security key."},
			},
		},
		"prompt": csrf(map[string]any{
			"Title": "Before you continue", "Slug": "terms",
			"Body":  "Your organisation asks everyone to confirm a few things once a year.",
			"Error": "",
			"Fields": []map[string]any{
				{"Type": "notice", "Name": "n1",
					"Label": "This account is monitored under the acceptable use policy."},
				{"Type": "checkbox", "Name": "accept", "Required": true,
					"Label": "I have read and accept the acceptable use policy.",
					"Help":  "A copy was emailed to you on 1 August."},
				{"Type": "select", "Name": "dept", "Required": true, "Label": "Department",
					"Options": []string{"Engineering", "Finance", "Operations"}, "Help": ""},
				{"Type": "text", "Name": "phone", "Required": false,
					"Label": "Contact number", "Help": "Used only if we need to reach you about your account."},
			},
		}),
		"backchannel": csrf(map[string]any{
			"Requests": []map[string]any{{
				"ID": "8c1f0a2b", "ClientName": "Point-of-sale terminal 14",
				"Scope": "openid payments.authorize", "BindingMessage": "W7-42",
				// The page says "Expires in {{.Expires}}", so this is the duration.
				// Through N, the way the handler builds it: a duration is a
				// count, and the form it takes is the language's business.
				"Expires": p.N("common.minutes", 4),
			}},
		}),
		"racindex": map[string]any{
			"Configured": true,
			"Connections": []map[string]any{
				{"Slug": "build-01", "DisplayName": "Build server 01", "Protocol": "SSH", "Hostname": "build-01.internal"},
				{"Slug": "win-lab", "DisplayName": "Windows lab", "Protocol": "RDP", "Hostname": "win-lab.internal"},
			},
		},
		"racview": map[string]any{
			"Name": "Windows lab", "Protocol": "RDP", "Slug": "windows-lab",
		},
		"umaclaims": csrf(map[string]any{
			"ClientName": "Northwind Analytics", "ResourceServer": "Contoso Documents",
			"Handle": "c9f1a7d3",
			"Asks": []map[string]any{
				{"Resource": "Q3 forecast.xlsx", "Scopes": "view, comment"},
			},
		}),
		"umaclaimserr": map[string]any{
			"Title":  "This request has expired",
			"Detail": "Ask the application to try again; it will send you back here with a fresh request.",
		},
		"err": map[string]any{
			"Code":        "invalid_request",
			"Description": "The application asked for a response type this server does not support.",
		},
		"federr": map[string]any{
			"Reason":        "The sign-in provider returned an account with an unverified email address, and this organisation does not accept those.",
			"CorrelationID": "7QF-2K9",
		},
		"samlerr": map[string]any{
			"Reason":        "The service provider's certificate expired on 3 August 2026, so the assertion could not be signed for it.",
			"CorrelationID": "3BX-8M2",
		},
		"fclogout": map[string]any{
			"Targets": []map[string]any{
				{"URL": "https://analytics.example.com/logout"},
				{"URL": "https://expenses.example.com/logout"},
			},
			"ContinueTo": "https://example.com/",
		},
		"saml": map[string]any{
			"ACS": "https://sp.example.com/saml/acs", "Response": "PHNhbWxwOl…",
			"RelayState": "a7f2c1",
		},
		"formpost": map[string]any{
			"Action": "https://app.example.com/callback", "Nonce": "r4nd0m",
			"Fields": []map[string]any{
				{"Name": "code", "Value": "9c2a…"}, {"Name": "state", "Value": "b81f…"},
			},
		},
		"wsfed": map[string]any{
			"Action": "https://app.example.com/wsfed", "WResult": "<t:RequestSecurityTokenResponse…",
			"WCtx": "rm=0&id=passive", "Nonce": "r4nd0m",
		},
	}
}

// A fixed, meaningless QR pattern. Enough shape to judge the layout around it
// without pulling in an encoder the preview does not need.
func qrBlocks() string {
	var b strings.Builder
	seed := 0x2f
	for y := 0; y < 25; y++ {
		for x := 0; x < 25; x++ {
			seed = (seed*1103515245 + 12345) & 0x7fffffff
			// The three finder squares, then noise for the rest.
			finder := (x < 7 && y < 7) || (x > 17 && y < 7) || (x < 7 && y > 17)
			on := finder && (x == 0 || x == 6 || y == 0 || y == 6 ||
				(x > 1 && x < 5 && y > 1 && y < 5) ||
				(x > 18 && x < 22 && y > 1 && y < 5) ||
				(x > 1 && x < 5 && y > 18 && y < 22))
			if !finder {
				on = seed>>16&1 == 1
			}
			if on {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1"/>`, x, y)
			}
		}
	}
	return b.String()
}
