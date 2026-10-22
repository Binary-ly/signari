package httpapi

import (
	"net/http"
	"time"

	"signari.dev/engine/internal/i18n"
)

// A person choosing the language the pages and their mail speak (5.20).
//
// users.locale was set only by `signari user locale`, and pages followed the
// browser's Accept-Language alone. The account page now has a selector: the
// choice is saved on the account, where notices already read it, and in a
// cookie, which every page reads without a query, the sign-in page included.
// Signing in on another browser brings the saved choice with it. An
// application's ui_locales still comes first: it is a request about this one
// interaction.

// LanguageCookieName carries the chosen language. It names nobody and grants
// nothing, and a value no catalogue has is ignored (langFor).
const LanguageCookieName = "__Host-signari_lang"

const languageCookieAge = 365 * 24 * time.Hour

func chosenLanguage(r *http.Request) string {
	c, err := r.Cookie(LanguageCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// setLanguageCookie remembers lang in this browser; "" forgets it, back to the
// browser's own setting.
func setLanguageCookie(w http.ResponseWriter, lang string) {
	maxAge := int(languageCookieAge.Seconds())
	if lang == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: LanguageCookieName, Value: lang, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// languageChoice is one entry of the account page's selector.
type languageChoice struct {
	Tag, Name string
	Selected  bool
}

// languageChoices lists the loaded catalogues, each named in its own
// language, with current selected ("" for the browser's setting).
func (s *Server) languageChoices(current string) []languageChoice {
	bundle := s.pageSet().Bundle()
	if bundle == nil {
		return nil
	}
	fallback := bundle.For(i18n.Default).Text("language.name")
	var out []languageChoice
	for _, tag := range bundle.Languages() {
		name := bundle.For(tag).Text("language.name")
		if tag != i18n.Default && name == fallback {
			// A catalogue that does not name itself: its tag beats the
			// default language's name.
			name = tag
		}
		out = append(out, languageChoice{Tag: tag, Name: name, Selected: tag == current})
	}
	return out
}

// handleAccountLanguage saves the person's choice, or with "" forgets it.
func (s *Server) handleAccountLanguage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, _, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		http.Error(w, "that form has expired; reload and try again", http.StatusForbidden)
		return
	}
	lang := r.PostForm.Get("language")
	if lang != "" && !s.pageSet().Bundle().Has(lang) {
		http.Error(w, "no such language here", http.StatusBadRequest)
		return
	}
	if _, err := s.db.Exec(ctx, `UPDATE core.users SET locale = NULLIF($2, ''), updated_at = now()
		WHERE id = $1::uuid`, userID, lang); err != nil {
		s.log.Error("saving the chosen language", "err", err)
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	setLanguageCookie(w, lang)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
