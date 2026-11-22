package mail

import (
	"bytes"
	"cmp"
	"html/template"
	"regexp"
	"strings"
)

// Look is what a deployment's brand changes about a message.
type Look struct {
	// Product stands at the top of the page.
	Product string
	// Background, Text and Link are colours, #rrggbb. Anything else is ignored.
	Background string
	Text       string
	Link       string
}

// The HTML part is a fixed layout, not a template an operator writes, and the
// reason is what mail from an identity provider must not teach. A styled button
// in a message about somebody's account is the exact shape of the attack we are
// trying to make them resistant to: the words on it say one thing, and where it
// goes is hidden. So this layout has no button and no image, and each link's
// visible text is the whole address it goes to. Nothing in the page came from
// anywhere but the text part, and with no image nothing in it calls home when it
// is opened.
var layout = template.Must(template.New("mail").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:24px;background:{{.Background}};color:{{.Text}};font-family:system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;font-size:16px;line-height:1.5">
<div style="max-width:560px;margin:0 auto">
{{- if .Product}}
<p dir="auto" style="margin:0 0 24px;font-weight:600">{{.Product}}</p>
{{- end}}
{{- range .Paragraphs}}
<p dir="auto" style="margin:0 0 16px;white-space:pre-line;overflow-wrap:anywhere">
{{- range .}}{{if .Link}}<a href="{{.Link}}" style="color:{{$.Link}}">{{.Link}}</a>{{else}}{{.Text}}{{end}}{{end -}}
</p>
{{- end}}
</div>
</body></html>
`))

// span is a run of a paragraph: words, or one link.
type span struct {
	Text string
	Link string
}

// A link is a web address in the text. A trailing full stop or bracket belongs
// to the sentence around it, not to the address.
var (
	linkPattern    = regexp.MustCompile(`https?://[^\s<>"]+`)
	trailingPunct  = ".,;:!?)]'"
	colourPattern  = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	paragraphBreak = regexp.MustCompile(`\n[ \t]*\n`)
)

// render makes the HTML part from the text part.
//
// A paragraph is what a blank line ends. A single line break stays one, because
// the text carries codes and links on lines of their own.
func render(m Message) (string, error) {
	var page struct {
		Subject, Product       string
		Background, Text, Link string
		Paragraphs             [][]span
	}
	page.Subject, page.Product = m.Subject, m.Look.Product
	page.Background = colour(m.Look.Background, "#ffffff")
	page.Text = colour(m.Look.Text, "#18181b")
	page.Link = colour(m.Look.Link, "#0b5fff")
	body := strings.ReplaceAll(m.Body, "\r\n", "\n")
	for _, para := range paragraphBreak.Split(strings.TrimSpace(body), -1) {
		page.Paragraphs = append(page.Paragraphs, spans(para))
	}
	var b bytes.Buffer
	if err := layout.Execute(&b, page); err != nil {
		return "", err
	}
	return b.String(), nil
}

// spans cuts a paragraph into its words and its links.
func spans(para string) []span {
	var out []span
	at := 0
	for _, loc := range linkPattern.FindAllStringIndex(para, -1) {
		link := strings.TrimRight(para[loc[0]:loc[1]], trailingPunct)
		if at < loc[0] {
			out = append(out, span{Text: para[at:loc[0]]})
		}
		out = append(out, span{Link: link})
		at = loc[0] + len(link)
	}
	if at < len(para) {
		out = append(out, span{Text: para[at:]})
	}
	return out
}

// colour is a brand's colour when it is one, since a value here lands in a style
// attribute, and the plain page's otherwise.
func colour(asked, otherwise string) string {
	if colourPattern.MatchString(asked) {
		return cmp.Or(asked, otherwise)
	}
	return otherwise
}
