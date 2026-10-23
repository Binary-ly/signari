package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/safedial"
	"signari.dev/engine/internal/store"
)

// Shared Signals (6.07), as `signari ssf` configures it: the streams that
// carry security events to a relying party's receiver, and the transmitters
// whose events this engine acts on. A receiver's bearer token is sealed and
// never read back.

type streamView struct {
	ID       string   `json:"id"`
	ClientID string   `json:"client_id"`
	Method   string   `json:"delivery_method"`
	Endpoint string   `json:"endpoint"`
	Status   string   `json:"status"`
	Events   []string `json:"events"`
	HasToken bool     `json:"has_receiver_token"`
}

// addStreamRequest registers a client's stream: pushed to endpoint, with the
// bearer token the receiver issued us, or pulled by the receiver from
// /ssf/poll as its client when poll is true.
type addStreamRequest struct {
	ClientID      string   `json:"client_id"`
	Endpoint      string   `json:"endpoint"`
	ReceiverToken string   `json:"receiver_token"`
	Events        []string `json:"events"`
	Poll          bool     `json:"poll"`
}

type streamStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type sourceView struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Issuer          string   `json:"issuer"`
	JWKSURI         string   `json:"jwks_uri"`
	Audience        string   `json:"audience"`
	Events          []string `json:"events"`
	CriticalMembers []string `json:"critical_members"`
	Enabled         bool     `json:"enabled"`
}

// putSourceRequest registers or replaces a transmitter, keyed by issuer.
type putSourceRequest struct {
	Name            string   `json:"name"`
	Issuer          string   `json:"issuer"`
	JWKSURI         string   `json:"jwks_uri"`
	Audience        string   `json:"audience"`
	Events          []string `json:"events"`
	CriticalMembers []string `json:"critical_members"`
}

var errPrivilegedStream = errors.New("this application is where administrators sign in to the Admin API; " +
	"a stream for it needs " + ScopePrivilegedUsersWrite)

func (s *Server) listStreams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	// A token narrowed to some applications sees their streams only.
	got, err := store.Streams(ctx, s.db, orgID, clientFilter(ctx))
	if err != nil {
		s.log.Error("listing streams", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]streamView, 0, len(got))
	for _, st := range got {
		out = append(out, streamView{ID: st.ID, ClientID: st.ClientID, Method: st.Method, Endpoint: st.Endpoint,
			Status: st.Status, Events: st.Events, HasToken: st.HasToken})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "streams": out})
}

func (s *Server) addStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req addStreamRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if err := requireClient(ctx, req.ClientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	spec := store.StreamSpec{ClientID: req.ClientID, Endpoint: strings.TrimSpace(req.Endpoint),
		ReceiverToken: req.ReceiverToken, Events: cleanList(req.Events, false), Poll: req.Poll}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_stream", "detail": err.Error()})
		return
	}
	// A pushed stream posts security events about people to the endpoint,
	// so one reaching this engine's own network is refused here, as an event
	// subscription is.
	if !spec.Poll {
		if err := safedial.CheckURL(spec.Endpoint); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_url", "detail": err.Error()})
			return
		}
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var id string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		// The application administrators sign in through: its sessions'
		// events go wherever its stream says, so adding one takes what every
		// other write on it takes.
		if _, privileged, _, err := store.PrivilegedClient(ctx, tx, spec.ClientID); err != nil {
			return err
		} else if p, _ := principalFrom(ctx); privileged && (p == nil || !p.Can(ScopePrivilegedUsersWrite)) {
			return errPrivilegedStream
		}
		var err error
		if id, err = store.AddStream(ctx, tx, s.root, orgID, spec); err != nil {
			return err
		}
		// Never the token.
		return audit.Write(ctx, tx, audit.Event{Type: "admin.ssf_stream_added", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: spec.ClientID, Detail: map[string]any{"stream": id, "poll": spec.Poll,
				"endpoint": spec.Endpoint, "events": spec.Events}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrStreamClientElsewhere):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case errors.Is(err, errPrivilegedStream):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "privileged_target", "detail": err.Error()})
		return
	case errors.Is(err, store.ErrStreamExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_exists", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("adding a stream", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "client_id": spec.ClientID, "events": spec.Events,
		"config_version": version})
}

// setStreamStatus pauses, disables or re-enables the stream of the client
// the path names, telling the receiver as SSF 1.0 requires
// (store.SetStreamStatus).
func (s *Server) setStreamStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := r.PathValue("clientID")
	if err := requireClient(ctx, clientID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	var req streamStatusRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	switch req.Status {
	case "enabled", "paused", "disabled":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_status",
			"detail": "a stream's status is enabled, paused or disabled"})
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	var prev string
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		orgID, err := clientOrg(ctx, tx, clientID)
		if err != nil {
			return err
		}
		if prev, err = store.SetStreamStatus(ctx, tx, orgID, clientID, req.Status, req.Reason); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.ssf_stream_status_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, ClientID: clientID, Detail: map[string]any{"from": prev, "to": req.Status,
				"reason": req.Reason}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return
	case errors.Is(err, store.ErrStreamUnknown):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "stream_not_found"})
		return
	case err != nil:
		s.log.Error("setting a stream's status", "client_id", clientID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"client_id": clientID, "status": req.Status, "was": prev,
		"config_version": version})
}

func (s *Server) listSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}
	got, err := store.Sources(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("listing sources", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]sourceView, 0, len(got))
	for _, src := range got {
		out = append(out, sourceView{ID: src.ID, Name: src.Name, Issuer: src.Issuer, JWKSURI: src.JWKSURI,
			Audience: src.Audience, Events: src.Events, CriticalMembers: src.CriticalMembers, Enabled: src.Enabled})
	}
	s.writeList(w, r, map[string]any{"org_id": orgID, "sources": out})
}

// putSource registers or replaces a transmitter, as `signari ssf add-source`
// does. Its events are acted on: a session-revoked one signs somebody out.
func (s *Server) putSource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("orgID")
	var req putSourceRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	req.Name, req.Issuer = strings.TrimSpace(req.Name), strings.TrimSpace(req.Issuer)
	req.JWKSURI, req.Audience = strings.TrimSpace(req.JWKSURI), strings.TrimSpace(req.Audience)
	events, critical := cleanList(req.Events, false), cleanList(req.CriticalMembers, false)
	refuse := func(detail string) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_source", "detail": detail})
	}
	switch {
	case req.Name == "":
		refuse("give a name")
		return
	case req.Issuer == "":
		refuse("give the issuer: every event must carry exactly this in iss, and it selects the keys to verify against")
		return
	case req.Audience == "":
		refuse("give the audience: a token addressed to somebody else is not ours to act on, however valid its signature")
		return
	case len(events) == 0:
		refuse("give the events: a source permitted to send nothing is not useful, and one permitted to send " +
			"everything is not what you meant")
		return
	}
	// Keys come from there, never from the token, fetched through the
	// outbound dialer when an event arrives.
	if err := safedial.CheckURL(req.JWKSURI); err != nil {
		refuse("the jwks_uri: " + err.Error())
		return
	}
	if narrowedTokenRefused(w, r, "accept events that can sign anybody in the organisation out") {
		return
	}
	pre, ok := s.readPrecondition(w, r)
	if !ok {
		return
	}
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		if err := requireNamedOrg(ctx, tx, orgID); err != nil {
			return err
		}
		if err := store.AddSource(ctx, tx, orgID, req.Name, req.Issuer, req.JWKSURI, req.Audience, events,
			critical); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{Type: "admin.ssf_source_set", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, Detail: map[string]any{"name": req.Name, "issuer": req.Issuer, "audience": req.Audience,
				"events": events, "critical_members": critical}})
	})
	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case writeOrgRefusal(w, err):
		return
	case errors.Is(err, store.ErrSourceAudienceTaken):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "audience_taken", "detail": err.Error()})
		return
	case err != nil:
		s.log.Error("registering a source", "org_id", orgID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "issuer": req.Issuer, "config_version": version})
}
