package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/rac"
	"signari.dev/engine/internal/store"
)

// Remote access through the browser.
//
// The browser speaks the Guacamole protocol over a WebSocket; this endpoint
// authenticates the person, decides whether they may reach the host, opens a
// connection to guacd, and then copies bytes.
//
// # Everything before the copying is the product
//
// guacd will connect to whatever it is told to connect to. It has no notion of
// a user and cannot be given one. So the order here is not incidental:
//
//	1. the request's origin         is this OUR page asking
//	2. a signed-in session          who
//	3. the access policy            may they be here at all, right now
//	4. the connection's group       is this machine theirs to reach
//	5. an audit entry               recorded before a single byte moves
//	6. guacd
//
// Step 1 was missing from this list and from this position, and the omission was
// not cosmetic. The WebSocket library checks the origin during the upgrade --
// correctly, and it is still doing so -- but the upgrade is the LAST thing that
// happens here. guacd had already been dialled, which means a connection to the
// target host was already open, a session row was already written and an audit
// entry already recorded, before anything asked who was asking.
//
// A WebSocket handshake carries cookies like any other request, so a page on
// another origin could open one against a signed-in victim: every check above
// passes, because the victim genuinely is entitled to that host. The attacker
// cannot read a byte -- the upgrade is refused a moment later -- but the
// connection to the internal machine happened, and it happens again on every
// reload of their page. An origin check that runs after the side effects is a
// check on the wrong thing.
//
// Steps 2 and 3 are separate on purpose. Policy answers "is this person, on
// this device, from this network, permitted"; the group answers "is this
// particular machine theirs". Collapsing them would mean either every host
// shares one rule or the policy language grows a copy of group membership.

// racHandshakeTimeout bounds the guacd handshake.
const racHandshakeTimeout = 10 * time.Second

// handleRACConnect proxies a browser to guacd.
func (s *Server) handleRACConnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.guacdAddr == "" {
		// Not configured. Said plainly rather than 404: an operator who has
		// registered connections and not set the address should be told which
		// half is missing.
		writeError(w, http.StatusServiceUnavailable, "unavailable",
			"remote access is not configured on this server")
		return
	}

	// Before the session is even looked up, because everything below it has an
	// effect somewhere: a policy evaluation, an audit row, a TCP connection to a
	// machine somebody cares about.
	if !sameOriginRequest(r) {
		s.log.Info("remote access refused: cross-origin upgrade",
			"origin", r.Header.Get("Origin"), "correlation_id", correlationID(ctx))
		writeError(w, http.StatusForbidden, "access_denied",
			"a remote access session may only be opened from this site")
		return
	}

	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "sign in first")
		return
	}

	slug := r.PathValue("slug")
	conn, err := store.LoadRACConnection(ctx, s.db, orgID, slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}

	// The access policy, exactly as every other authorization goes through it.
	mfa, amr := sessionFactors(ctx, s.db, sid)
	if pd := s.checkAccessPolicy(ctx, r, orgID, "rac:"+slug, userID,
		"remote_access", mfa, amr); pd != nil {
		s.log.Info("remote access refused by policy", "connection", slug,
			"rule", pd.Rule, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusForbidden, "access_denied", pd.Message)
		return
	}

	// And the connection's own group requirement.
	allowed, err := store.MayUse(ctx, s.db, conn, userID)
	if err != nil {
		s.log.Error("checking remote access group", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if !allowed {
		// The same answer as an unknown connection. Distinguishing them would
		// let anybody enumerate which machines exist by asking for each in turn.
		writeError(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}

	width := intParam(r, "width", 1024)
	height := intParam(r, "height", 768)
	dpi := intParam(r, "dpi", 96)

	target, err := conn.Resolve(s.cfg.Root, width, height, dpi)
	if err != nil {
		s.log.Error("resolving a remote connection", "err", err, "connection", slug)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// Recorded BEFORE anything is opened. An audit entry written after a
	// successful connection misses every attempt that failed at guacd -- which
	// is the half somebody investigating an incident wants.
	s.auditDetached(ctx, audit.Event{
		Type: "rac.session_requested", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"connection": slug, "protocol": conn.Protocol, "host": conn.Hostname,
		},
	})

	guac, err := rac.Dial(s.guacdAddr, target, racHandshakeTimeout)
	if err != nil {
		s.log.Error("connecting to guacd", "err", err, "connection", slug)
		writeError(w, http.StatusBadGateway, "upstream_error",
			"the remote host could not be reached")
		return
	}
	defer func() { _ = guac.Close() }()

	sessionID, err := store.StartRACSession(ctx, s.db, conn, userID, guac.ID)
	if err != nil {
		s.log.Error("recording a remote session", "err", err)
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"guacamole"},
		// nil means same-origin only: the library compares the Origin host to
		// the request Host (`authenticateOrigin`, coder/websocket v1.8.15).
		//
		// Kept even though the handler now checks the origin itself, before any
		// of this runs. Two checks of one rule is usually a smell; here the
		// earlier one exists to protect the SIDE EFFECTS above and this one
		// protects the STREAM, and a future edit that reorders the handler
		// should not be able to open a cross-origin socket by accident.
		OriginPatterns: nil,
	})
	if err != nil {
		s.log.Info("websocket upgrade refused", "err", err)
		_ = store.EndRACSession(ctx, s.db, sessionID, "upgrade failed")
		return
	}

	reason := rac.Proxy(ctx, wsPeer{ws}, guac)

	if sessionID != "" {
		if err := store.EndRACSession(context.Background(), s.db, sessionID, reason); err != nil {
			s.log.Error("closing the remote session record", "err", err)
		}
	}
	s.auditDetached(context.Background(), audit.Event{
		Type: "rac.session_ended", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"connection": slug, "reason": reason},
	})
	_ = ws.Close(websocket.StatusNormalClosure, "")
}

// wsPeer adapts a WebSocket to rac.Peer.
//
// The adapter is here rather than in the rac package so that package does not
// depend on a WebSocket library to describe something that is not about
// WebSockets.
type wsPeer struct{ ws *websocket.Conn }

func (p wsPeer) ReadMessage(ctx context.Context) ([]byte, error) {
	typ, data, err := p.ws.Read(ctx)
	if err != nil {
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil, rac.NormalClose
		}
		return nil, err
	}
	if typ != websocket.MessageText {
		// The Guacamole protocol is text. A binary frame is either a confused
		// client or somebody probing.
		return nil, errors.New("client sent a binary frame")
	}
	return data, nil
}

func (p wsPeer) WriteMessage(ctx context.Context, data []byte) error {
	err := p.ws.Write(ctx, websocket.MessageText, data)
	if err != nil && websocket.CloseStatus(err) == websocket.StatusNormalClosure {
		return rac.NormalClose
	}
	return err
}

// handleRACList shows what a user may reach.
func (s *Server) handleRACList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "sign in first")
		return
	}
	conns, err := store.ListRACConnections(ctx, s.db, orgID, userID)
	if err != nil {
		s.log.Error("listing remote connections", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	out := make([]map[string]any, 0, len(conns))
	for _, c := range conns {
		// Deliberately no parameters and no credentials: this answers "what may
		// I reach", not "how does the server reach it".
		out = append(out, map[string]any{
			"slug": c.Slug, "name": c.DisplayName, "protocol": c.Protocol,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 10000 {
		return def
	}
	return n
}

// sameOriginRequest reports whether a request came from this server's own pages.
//
// ASVS 5.0.0 V4.4.2: "during the initial HTTP WebSocket handshake, the Origin
// header field is checked against a list of origins allowed for the
// application."
//
// The same rule the WebSocket library applies, hoisted so it can run before the
// handler does anything: Origin's host must equal the Host the request was sent
// to.
//
// An ABSENT Origin is allowed, which is the library's behaviour too and is
// deliberate rather than inherited. Browsers always send Origin on a WebSocket
// handshake and on any cross-site form post, so absence means a non-browser
// client -- a CLI, a test, a native app -- and those are not the thing this
// defends against. A browser cannot suppress the header, so nothing an attacker
// controls reaches this branch.
func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
