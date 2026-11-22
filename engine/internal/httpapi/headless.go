package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
)

// A sign-in for an application that draws its own page (10.11).
//
// This has no walker of its own. Each step is a request made to the same handlers
// the HTML pages post to, and the page they answer with is read back as JSON: its
// forms, what it asks and what it said. So every stage, refusal, rate limit, policy
// and hook is the one a browser meets, and a stage added to the flow reaches this
// with nothing added here. A second walker would be a second place for the rule that
// matters to be missing.
//
// It ends the way a browser's does: the application is told where the walk's last
// redirect was going, which is its own redirect URI with a code in it, and it redeems
// that with its PKCE verifier. A token is never answered here.
//
// What a browser keeps in cookies travels in a state sealed under the root key, so
// the application's script holds nothing it can read, including the session the walk
// makes. There is no cookie and so no CSRF: nothing is ambient, and the page's own
// token goes from one step to the next inside the seal.

const (
	pathHeadlessStart  = "/login/api/start"
	pathHeadlessSubmit = "/login/api/submit"

	headlessStateContext = "signari headless sign-in"
	// headlessLife is how long one step may wait for the next.
	headlessLife = 10 * time.Minute
	// headlessMaxHops bounds a step's redirects. The longest walk is a form, the
	// authorization it returns to and the sign-in page or code that answers it.
	headlessMaxHops = 8
)

// headlessNote is how a handler says which page it answered with.
type headlessNote struct {
	page string
	data map[string]any
}

type headlessKey struct{}

// headlessFrom is the note of a request the driver made, nil for anybody else's.
func headlessFrom(ctx context.Context) *headlessNote {
	note, _ := ctx.Value(headlessKey{}).(*headlessNote)
	return note
}

// headlessState is what a browser would be holding, sealed.
type headlessState struct {
	Expiry  int64             `json:"exp"`
	Cookies map[string]string `json:"cookies"`
	// Forms is the hidden fields of each form the last page offered, by action:
	// what may be posted next, and all that may.
	Forms map[string]url.Values `json:"forms"`
}

func (s *Server) sealHeadless(st *headlessState) (string, error) {
	st.Expiry = time.Now().Add(headlessLife).Unix()
	raw, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sealed, err := s.cfg.Root.Seal(raw, headlessStateContext)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

var errHeadlessState = errors.New("the state was not one this server made, or it has run out")

func (s *Server) openHeadless(sealed string) (*headlessState, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, errHeadlessState
	}
	plain, err := s.cfg.Root.Open(raw, headlessStateContext)
	if err != nil {
		return nil, errHeadlessState
	}
	var st headlessState
	if err := json.Unmarshal(plain, &st); err != nil || time.Now().Unix() > st.Expiry {
		return nil, errHeadlessState
	}
	return &st, nil
}

// headlessField is one thing a form asks.
type headlessField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Label    string `json:"label,omitempty"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// headlessButton is a named submit button: which of them is pressed is an answer.
type headlessButton struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Label string `json:"label"`
}

type headlessForm struct {
	Action  string           `json:"action"`
	Fields  []headlessField  `json:"fields"`
	Buttons []headlessButton `json:"buttons,omitempty"`
}

type headlessProvider struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// headlessStep is one answer of the walk.
type headlessStep struct {
	Done       bool               `json:"done"`
	RedirectTo string             `json:"redirect_to,omitempty"`
	State      string             `json:"state,omitempty"`
	Page       string             `json:"page,omitempty"`
	Status     int                `json:"status,omitempty"`
	Message    string             `json:"message,omitempty"`
	Forms      []headlessForm     `json:"forms,omitempty"`
	Providers  []headlessProvider `json:"providers,omitempty"`
}

func headlessRefuse(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": oauth.ErrorText(detail)})
}

// handleHeadlessStart begins a walk from an authorization request.
//
// Only a client that named a page of its own, and only for what ends in a code the
// client proves with PKCE: this is one more place a password is typed, and nothing
// that place holds may become a token by another road.
func (s *Server) handleHeadlessStart(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Root == nil {
		headlessRefuse(w, http.StatusServiceUnavailable, "not_available", "this deployment has no root key to seal a walk with")
		return
	}
	var req struct {
		Authz string `json:"authz"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		headlessRefuse(w, http.StatusBadRequest, "invalid_request", "give authz, the authorization request's query")
		return
	}
	q, err := url.ParseQuery(req.Authz)
	switch {
	case err != nil, q.Get("response_type") != "code", q.Get("code_challenge") == "",
		q.Get("code_challenge_method") != "S256", q.Get("response_mode") != "" && q.Get("response_mode") != "query":
		headlessRefuse(w, http.StatusBadRequest, "invalid_request",
			"a walk is for response_type=code with an S256 code_challenge, answered in the query")
		return
	}
	c, err := s.lookupClient(r.Context(), q.Get("client_id"))
	if err != nil || c == nil {
		headlessRefuse(w, http.StatusBadRequest, "invalid_client", "no such client")
		return
	}
	if c.LoginUI == "" {
		headlessRefuse(w, http.StatusForbidden, "unauthorized_client", "this client has named no sign-in page of its own")
		return
	}
	st := &headlessState{Cookies: map[string]string{}, Forms: map[string]url.Values{}}
	s.headlessWalk(w, r, st, http.MethodGet, oidc.PathAuthorize+"?"+req.Authz, nil)
}

// handleHeadlessSubmit answers a form the last step offered.
func (s *Server) handleHeadlessSubmit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Root == nil {
		headlessRefuse(w, http.StatusServiceUnavailable, "not_available", "this deployment has no root key to seal a walk with")
		return
	}
	var req struct {
		State  string            `json:"state"`
		Action string            `json:"action"`
		Fields map[string]string `json:"fields"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		headlessRefuse(w, http.StatusBadRequest, "invalid_request", "give state, action and fields")
		return
	}
	st, err := s.openHeadless(req.State)
	if err != nil {
		headlessRefuse(w, http.StatusBadRequest, "invalid_state", err.Error())
		return
	}
	hidden, offered := st.Forms[req.Action]
	if !offered {
		headlessRefuse(w, http.StatusBadRequest, "invalid_action", "the last step offered no such form")
		return
	}
	form := url.Values{}
	for name, value := range req.Fields {
		form.Set(name, value)
	}
	// The page's own say, over the caller's: the CSRF token and the parked request
	// are what the page was given and not the application's to change.
	for name, values := range hidden {
		form[name] = values
	}
	s.headlessWalk(w, r, st, http.MethodPost, req.Action, form)
}

// headlessWalk makes one request and follows it to the next thing for a person to
// answer, or out of this server.
func (s *Server) headlessWalk(w http.ResponseWriter, r *http.Request, st *headlessState,
	method, target string, form url.Values) {

	w.Header().Set("Cache-Control", "no-store")
	for range headlessMaxHops {
		rec, note, err := s.headlessRequest(r, st, method, target, form)
		if err != nil {
			s.log.ErrorContext(r.Context(), "walking a sign-in", "err", err)
			headlessRefuse(w, http.StatusInternalServerError, "server_error", "the walk could not continue")
			return
		}
		st.keepCookies(rec.header)
		if location := rec.header.Get("Location"); location != "" && rec.status >= 300 && rec.status < 400 {
			next, own := s.ownPath(location)
			if !own {
				writeJSON(w, http.StatusOK, headlessStep{Done: true, RedirectTo: location})
				return
			}
			method, target, form = http.MethodGet, next, nil
			continue
		}
		s.headlessAnswer(r.Context(), w, st, target, rec, note)
		return
	}
	s.log.ErrorContext(r.Context(), "a sign-in walked in circles")
	headlessRefuse(w, http.StatusInternalServerError, "server_error", "the walk did not settle")
}

// ownPath is a redirect's path on this server, or says it leaves.
func (s *Server) ownPath(location string) (string, bool) {
	if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		return location, true
	}
	if rest, ok := strings.CutPrefix(location, s.cfg.Issuer+"/"); ok {
		return "/" + rest, true
	}
	return "", false
}

func (s *Server) headlessRequest(r *http.Request, st *headlessState, method, target string,
	form url.Values) (*headlessRecorder, *headlessNote, error) {

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	note := &headlessNote{}
	sub, err := http.NewRequestWithContext(context.WithValue(r.Context(), headlessKey{}, note), method, target, body)
	if err != nil {
		return nil, nil, err
	}
	sub.Host, sub.RemoteAddr = r.Host, r.RemoteAddr
	for _, name := range []string{"User-Agent", "Accept-Language", "X-Forwarded-For", "Forwarded", "X-Real-Ip"} {
		if v := r.Header.Get(name); v != "" {
			sub.Header.Set(name, v)
		}
	}
	if form != nil {
		sub.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, value := range st.Cookies {
		sub.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := &headlessRecorder{header: http.Header{}, status: http.StatusOK}
	s.mux().ServeHTTP(rec, sub)
	return rec, note, nil
}

// keepCookies does what a browser does with what a response set.
func (st *headlessState) keepCookies(h http.Header) {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(st.Cookies, c.Name)
			continue
		}
		st.Cookies[c.Name] = c.Value
	}
}

// headlessRecorder keeps a response, for the driver to read rather than a browser.
type headlessRecorder struct {
	header http.Header
	status int
	wrote  bool
	body   strings.Builder
}

func (h *headlessRecorder) Header() http.Header { return h.header }

func (h *headlessRecorder) WriteHeader(status int) {
	if !h.wrote {
		h.status, h.wrote = status, true
	}
}

func (h *headlessRecorder) Write(b []byte) (int, error) {
	h.wrote = true
	return h.body.Write(b)
}

// headlessAnswer reads the page the handlers answered with.
func (s *Server) headlessAnswer(ctx context.Context, w http.ResponseWriter, st *headlessState, target string,
	rec *headlessRecorder, note *headlessNote) {

	forms, hidden := readForms(rec.body.String(), target)
	st.Forms = hidden
	sealed, err := s.sealHeadless(st)
	if err != nil {
		s.log.ErrorContext(ctx, "sealing a walk", "err", err)
		headlessRefuse(w, http.StatusInternalServerError, "server_error", "the walk could not continue")
		return
	}
	step := headlessStep{State: sealed, Page: note.page, Status: rec.status, Forms: forms}
	if said, ok := note.data["Error"].(string); ok {
		step.Message = said
	}
	if listed, ok := note.data["Providers"].([]externalProvider); ok {
		for _, p := range listed {
			step.Providers = append(step.Providers, headlessProvider{Name: p.Name, URL: s.cfg.Issuer + p.Href})
		}
	}
	writeJSON(w, http.StatusOK, step)
}

var (
	formTag   = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	fieldTag  = regexp.MustCompile(`(?is)<(input|select|textarea)\b([^>]*)>`)
	buttonTag = regexp.MustCompile(`(?is)<button\b([^>]*)>(.*?)</button>`)
	labelTag  = regexp.MustCompile(`(?is)<label\b([^>]*)>(.*?)</label>`)
	attribute = regexp.MustCompile(`([a-zA-Z-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`)
	anyTag    = regexp.MustCompile(`(?s)<[^>]*>`)
)

func attributes(raw string) map[string]string {
	out := map[string]string{}
	for _, m := range attribute.FindAllStringSubmatch(raw, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2] + m[3] + m[4])
	}
	return out
}

func plainText(markup string) string {
	return strings.Join(strings.Fields(html.UnescapeString(anyTag.ReplaceAllString(markup, " "))), " ")
}

// readForms is a page's POST forms: what each asks, and its hidden fields apart.
//
// The pages are the engine's own or a theme's that passed validation, which requires
// the fields that matter, so a form is found the way a browser finds it.
func readForms(page, target string) ([]headlessForm, map[string]url.Values) {
	forms := []headlessForm{}
	hidden := map[string]url.Values{}
	for _, m := range formTag.FindAllStringSubmatch(page, -1) {
		attrs := attributes(m[1])
		if !strings.EqualFold(attrs["method"], http.MethodPost) {
			continue
		}
		action := attrs["action"]
		if action == "" {
			action = target
		}
		labels := map[string]string{}
		for _, l := range labelTag.FindAllStringSubmatch(m[2], -1) {
			if id := attributes(l[1])["for"]; id != "" {
				labels[id] = plainText(l[2])
			}
		}
		form := headlessForm{Action: action, Fields: []headlessField{}}
		secret := url.Values{}
		for _, f := range fieldTag.FindAllStringSubmatch(m[2], -1) {
			a := attributes(f[2])
			if a["name"] == "" {
				continue
			}
			kind := a["type"]
			if kind == "" {
				kind = strings.ToLower(f[1])
			}
			if kind == "hidden" {
				secret.Add(a["name"], a["value"])
				continue
			}
			_, required := a["required"]
			form.Fields = append(form.Fields, headlessField{Name: a["name"], Type: kind,
				Label: labels[a["id"]], Value: a["value"], Required: required})
		}
		for _, b := range buttonTag.FindAllStringSubmatch(m[2], -1) {
			if a := attributes(b[1]); a["name"] != "" {
				form.Buttons = append(form.Buttons, headlessButton{Name: a["name"], Value: a["value"], Label: plainText(b[2])})
			}
		}
		forms = append(forms, form)
		hidden[action] = secret
	}
	return forms, hidden
}

// loginUIRedirect sends an authorization request to a client's own sign-in page.
func loginUIRedirect(page, authzQuery string) string {
	join := "?"
	if strings.Contains(page, "?") {
		join = "&"
	}
	return page + join + url.Values{"authz": {authzQuery}}.Encode()
}
