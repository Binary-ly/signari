package httpapi

import (
	"encoding/json"
	"net/http"
	"slices"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// The Event Stream Management API (SSF 1.0 §8.1), as a receiver sees it. A receiver is
// its client, authenticated as verification is, and has the one stream. It may read and
// change that stream but not make or delete one, nor say where it delivers: those are
// an operator's, because they decide who hears about whom.

// maxStreamBody is more than any stream configuration or subject comes to.
const maxStreamBody = 64 << 10

// streamView is the configuration §8.1.1 describes.
type streamView struct {
	StreamID                string   `json:"stream_id"`
	Issuer                  string   `json:"iss"`
	Audience                string   `json:"aud"`
	EventsSupported         []string `json:"events_supported"`
	EventsRequested         []string `json:"events_requested"`
	EventsDelivered         []string `json:"events_delivered"`
	Delivery                delivery `json:"delivery"`
	MinVerificationInterval int      `json:"min_verification_interval"`
	Description             string   `json:"description,omitempty"`
}

// delivery is §8.1.1's `delivery`. The receiver's token goes in and stays in.
type delivery struct {
	Method      string `json:"method"`
	EndpointURL string `json:"endpoint_url,omitempty"`
}

func (s *Server) streamView(st *store.ReceiverStream) streamView {
	view := streamView{StreamID: st.ID, Issuer: s.cfg.Issuer, Audience: st.ClientID,
		EventsSupported: ssf.SupportedEvents(), EventsRequested: st.Events,
		Delivery:                s.streamDelivery(st),
		MinVerificationInterval: int(store.MinVerificationInterval.Seconds()), Description: st.Description}
	view.EventsDelivered = deliveredEvents(st.Events)
	return view
}

func (s *Server) streamDelivery(st *store.ReceiverStream) delivery {
	if st.Method == "poll" {
		return delivery{Method: ssf.DeliveryPoll, EndpointURL: s.cfg.Issuer + "/ssf/poll"}
	}
	return delivery{Method: ssf.DeliveryPush, EndpointURL: st.Endpoint}
}

// deliveredEvents is §8.1.1's "subset ... of the intersection" of what is supported and
// what was asked for, never nil: a receiver reads this to know what to expect.
func deliveredEvents(requested []string) []string {
	out := []string{}
	for _, event := range requested {
		if slices.Contains(ssf.SupportedEvents(), event) {
			out = append(out, event)
		}
	}
	return out
}

// callerStream authenticates the caller and reads its stream, nil when it has none.
func (s *Server) callerStream(w http.ResponseWriter, r *http.Request) (*store.ReceiverStream, bool) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	clientID, ok := s.authenticateStreamClient(w, r)
	if !ok {
		return nil, false
	}
	st, err := store.ReceiverStreamOf(ctx, s.db, clientID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a receiver's stream", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return nil, false
	}
	return st, true
}

// receiverStream is the caller's stream, which streamID has to name.
func (s *Server) receiverStream(w http.ResponseWriter, r *http.Request, streamID string) (*store.ReceiverStream, bool) {
	st, ok := s.callerStream(w, r)
	if !ok {
		return nil, false
	}
	if st == nil || st.ID != streamID {
		writeError(w, http.StatusNotFound, "invalid_request", "this client has no stream with that id")
		return nil, false
	}
	return st, true
}

// handleSSFStreamRead is §8.1.1.2. With no stream_id it "MUST return a list of the
// stream configurations available to this Receiver", which here is one or none.
func (s *Server) handleSSFStreamRead(w http.ResponseWriter, r *http.Request) {
	if id := r.URL.Query().Get("stream_id"); id != "" {
		if st, ok := s.receiverStream(w, r, id); ok {
			writeJSON(w, http.StatusOK, s.streamView(st))
		}
		return
	}
	st, ok := s.callerStream(w, r)
	if !ok {
		return
	}
	views := []streamView{}
	if st != nil {
		views = append(views, s.streamView(st))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleSSFStreamNotYours is §8.1.1.1 and §8.1.1.5, which an operator keeps: 403, "if
// the Event Receiver is not allowed to".
func (s *Server) handleSSFStreamNotYours(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.authenticateStreamClient(w, r); ok {
		writeError(w, http.StatusForbidden, "access_denied", "a stream is made and deleted by the operator")
	}
}

// streamChange is a PATCH or PUT body. Pointers, because absent and empty differ.
type streamChange struct {
	StreamID                string    `json:"stream_id"`
	Issuer                  *string   `json:"iss"`
	Audience                any       `json:"aud"`
	EventsSupported         *[]string `json:"events_supported"`
	EventsRequested         *[]string `json:"events_requested"`
	EventsDelivered         *[]string `json:"events_delivered"`
	Delivery                *delivery `json:"delivery"`
	MinVerificationInterval *int      `json:"min_verification_interval"`
	Description             *string   `json:"description"`
}

// handleSSFStreamChange is §8.1.1.3, PATCH, and §8.1.1.4, PUT. They differ in what an
// absent property means: left alone, or "requested to be deleted".
func (s *Server) handleSSFStreamChange(replace bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var req streamChange
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStreamBody)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid JSON")
			return
		}
		if req.StreamID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
			return
		}
		st, ok := s.receiverStream(w, r, req.StreamID)
		if !ok {
			return
		}

		// §8.1.1.3: "Transmitter-Supplied properties besides the stream_id MAY be
		// present, but they MUST match the expected value."
		view := s.streamView(st)
		if !req.matches(view) {
			writeError(w, http.StatusBadRequest, "invalid_request", "a property this server supplies is not what it is")
			return
		}
		if req.Delivery != nil && *req.Delivery != view.Delivery {
			writeError(w, http.StatusForbidden, "access_denied", "where a stream delivers is the operator's to change")
			return
		}

		events, description := st.Events, st.Description
		if replace {
			events, description = nil, ""
		}
		if req.EventsRequested != nil {
			// §8.1.1: "A Transmitter MUST ignore any array values that it does not understand."
			events = deliveredEvents(*req.EventsRequested)
		}
		if req.Description != nil {
			description = *req.Description
		}
		if len(description) > 1024 {
			// §8.1.1: "MAY truncate the string", and a refusal says more than losing the end.
			writeError(w, http.StatusBadRequest, "invalid_request", "description is over 1024 bytes")
			return
		}
		if events == nil {
			events = []string{}
		}

		tx, err := s.db.Begin(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		err = store.SetReceiverStream(ctx, tx, st, events, description)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			s.log.ErrorContext(ctx, "changing a stream", "err", err, "correlation_id", correlationID(ctx))
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		st.Events, st.Description = events, description
		writeJSON(w, http.StatusOK, s.streamView(st))
	}
}

// matches is whether what the server supplies is, where the request says, what it is.
func (c streamChange) matches(view streamView) bool {
	if c.Issuer != nil && *c.Issuer != view.Issuer {
		return false
	}
	switch aud := c.Audience.(type) {
	case nil:
	case string:
		if aud != view.Audience {
			return false
		}
	case []any:
		if len(aud) != 1 || aud[0] != view.Audience {
			return false
		}
	default:
		return false
	}
	if c.EventsSupported != nil && !slices.Equal(*c.EventsSupported, view.EventsSupported) {
		return false
	}
	// "if present, MUST match the Transmitter's expected value before any updates are applied."
	if c.EventsDelivered != nil && !slices.Equal(*c.EventsDelivered, view.EventsDelivered) {
		return false
	}
	return c.MinVerificationInterval == nil || *c.MinVerificationInterval == view.MinVerificationInterval
}

// handleSSFStatusRead is §8.1.2.1.
func (s *Server) handleSSFStatusRead(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}
	if st, ok := s.receiverStream(w, r, id); ok {
		writeJSON(w, http.StatusOK, map[string]string{"stream_id": st.ID, "status": st.Status})
	}
}

// handleSSFStatusUpdate is §8.1.2.2.
func (s *Server) handleSSFStatusUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		StreamID string `json:"stream_id"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStreamBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid JSON")
		return
	}
	if req.StreamID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}
	if req.Status != "enabled" && req.Status != "paused" && req.Status != "disabled" {
		writeError(w, http.StatusBadRequest, "invalid_request", "status is enabled, paused or disabled")
		return
	}
	st, ok := s.receiverStream(w, r, req.StreamID)
	if !ok {
		return
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = store.SetReceiverStreamStatus(ctx, tx, st, req.Status, req.Reason)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		s.log.ErrorContext(ctx, "changing a stream's status", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stream_id": st.ID, "status": req.Status, "reason": req.Reason})
}

// subjectClaim is the subject of an add or remove request, §8.1.3.2. A complex subject
// names its person under `user`, and nothing else here has one to find.
type subjectClaim struct {
	Format string        `json:"format"`
	Issuer string        `json:"iss"`
	Sub    string        `json:"sub"`
	Email  string        `json:"email"`
	User   *subjectClaim `json:"user"`
}

func (c subjectClaim) person() store.StreamSubject {
	if c.Format == "complex" && c.User != nil {
		return c.User.person()
	}
	return store.StreamSubject{Format: c.Format, Issuer: c.Issuer, Sub: c.Sub, Email: c.Email}
}

// handleSSFSubject is §8.1.3.2 and §8.1.3.3. The answer does not depend on whether
// the subject is anybody, as §9.1 warns it otherwise would: "A "404" response may
// indicate to the Event Receiver that the subject does not exist".
func (s *Server) handleSSFSubject(removed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var req struct {
			StreamID string        `json:"stream_id"`
			Subject  *subjectClaim `json:"subject"`
			Verified *bool         `json:"verified"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStreamBody)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid JSON")
			return
		}
		if req.StreamID == "" || req.Subject == nil || req.Subject.Format == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "stream_id and subject are required")
			return
		}
		st, ok := s.receiverStream(w, r, req.StreamID)
		if !ok {
			return
		}
		person, err := store.PersonOfStreamSubject(ctx, s.db, st, s.cfg.Issuer, req.Subject.person())
		if err == nil && person != "" {
			err = store.SetStreamSubjectRemoved(ctx, s.db, st, person, removed)
		}
		if err != nil {
			s.log.ErrorContext(ctx, "changing a stream's subjects", "err", err, "correlation_id", correlationID(ctx))
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
