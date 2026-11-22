package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/text/language"

	"signari.dev/engine/internal/store"
)

// A client's name in the reader's language (10.12). RFC 7591 section 2.2 lets a client
// name itself in several, "client_name#ja", and lets the server choose which to show "based
// on system configuration, user preferences or other factors"; one without a tag "MUST be
// used as is" (specs/rfc7591.txt:703-751). So a page that names a client shows the name
// tagged with a language the person asked for, and otherwise the untagged one.

// localizedNamesIn reads the client_name#<tag> members of a registration's body. A member
// that is not a string, or a tag that is not one, is refused rather than dropped: the
// registrant would believe the name was registered.
func localizedNamesIn(body []byte) (map[string]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for key, raw := range members {
		tag, ok := strings.CutPrefix(key, "client_name#")
		if !ok {
			continue
		}
		var name string
		if err := json.Unmarshal(raw, &name); err != nil {
			return nil, fmt.Errorf("%s is not a string", key)
		}
		out[tag] = name
	}
	return store.NormaliseClientNames(out)
}

// withLocalizedNames adds a client's names to a registration response as the members they
// were registered as: RFC 7591 section 3.2.1 returns all registered metadata.
func withLocalizedNames(body map[string]any, names map[string]string) {
	for tag, name := range names {
		body["client_name#"+tag] = name
	}
}

// languagePreferences is what the person reading this page asked for, most wanted first:
// the application's ui_locales, then the language they chose here, then their browser's.
// Not limited to the languages this server's pages are written in: a client may be named
// in a language the pages are not.
func (s *Server) languagePreferences(r *http.Request) []language.Tag {
	var out []language.Tag
	for _, t := range strings.Fields(uiLocalesFrom(r)) {
		if tag, err := language.Parse(t); err == nil {
			out = append(out, tag)
		}
	}
	if lang := chosenLanguage(r); lang != "" {
		if tag, err := language.Parse(lang); err == nil {
			out = append(out, tag)
		}
	}
	if browser, _, err := language.ParseAcceptLanguage(r.Header.Get("Accept-Language")); err == nil {
		out = append(out, browser...)
	}
	return out
}

// pickClientName is the name tagged with a language the reader asked for, the closest
// such, or untagged when none is near enough. Near enough is the same language: a name
// in Brazilian Portuguese for somebody asking for Portuguese, never one in another
// language because it is the closest there is.
func pickClientName(names map[string]string, prefs []language.Tag, untagged string) string {
	if len(names) == 0 || len(prefs) == 0 {
		return untagged
	}
	tags := make([]language.Tag, 0, len(names))
	written := make([]string, 0, len(names))
	for t := range names {
		tag, err := language.Parse(t)
		if err != nil {
			continue
		}
		tags, written = append(tags, tag), append(written, t)
	}
	if len(tags) == 0 {
		return untagged
	}
	_, index, confidence := language.NewMatcher(tags).Match(prefs...)
	if confidence < language.High {
		return untagged
	}
	return names[written[index]]
}

// clientNameFor is the name of clientID to show on this request's page, untagged when the
// client has no name in a language the reader asked for or its names cannot be read: a
// page naming the client in the wrong language is better than no page.
func (s *Server) clientNameFor(ctx context.Context, r *http.Request, clientID, untagged string) string {
	names, err := store.ClientNames(ctx, s.db, clientID)
	if err != nil {
		s.log.WarnContext(ctx, "reading a client's names", "client_id", clientID, "err", err)
		return untagged
	}
	return pickClientName(names, s.languagePreferences(r), untagged)
}
