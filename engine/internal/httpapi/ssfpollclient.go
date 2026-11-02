package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/store"
)

// Pulling events from a transmitter (RFC 8936), for a receiver no transmitter can
// reach and a transmitter that only offers polling. The other half of handleSSFPoll:
// the same request and answer, from this side, and the same tokens as a push, verified
// and acted on by the same code.
//
// An event is acknowledged only once it has been acted on, in the request after. A node
// that stops in between is sent it again, and the replay guard answers that.

const (
	// ssfPollEvery is how late a polled event may be. Not per source: nobody has yet
	// asked to choose, and a signal is worth about the same to everybody.
	ssfPollEvery = 30 * time.Second
	// ssfPollRounds bounds one source's turn, so a queue that never empties leaves
	// the others theirs.
	ssfPollRounds = 20
	// ssfPollBatch is how many events one request asks for.
	ssfPollBatch = 100
	// ssfPollMaxAnswer caps what is read, at a full batch of generous tokens.
	ssfPollMaxAnswer = 8 << 20
)

// RunSSFPolls pulls every source that is polled until ctx ends. A scheduled job and not
// a cache: it holds nothing, and each pass reads which sources are due.
func (s *Server) RunSSFPolls(ctx context.Context) {
	s.pollDueSSFSources(ctx)
	t := time.NewTicker(ssfPollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pollDueSSFSources(ctx)
		}
	}
}

// pollDueSSFSources takes what is due, one source at a time, and says how many.
func (s *Server) pollDueSSFSources(ctx context.Context) int {
	taken := 0
	for ctx.Err() == nil {
		due, err := store.ClaimSSFPoll(ctx, s.db, s.root, s.instanceID, ssfPollEvery)
		if err != nil {
			s.log.ErrorContext(ctx, "claiming a shared-signals poll", "err", err)
			return taken
		}
		if due == nil {
			return taken
		}
		taken++
		problem := ""
		if err := s.pollSSFSource(ctx, due); err != nil {
			s.log.WarnContext(ctx, "polling a shared-signals transmitter", "source", due.ID, "err", err)
			problem = err.Error()
		}
		if err := store.RecordSSFPoll(ctx, s.db, due.ID, problem); err != nil {
			s.log.ErrorContext(ctx, "recording a shared-signals poll", "err", err)
		}
	}
	return taken
}

// pollSSFSource empties a transmitter's queue, as far as one turn goes.
func (s *Server) pollSSFSource(ctx context.Context, due *store.DueSSFPoll) error {
	ack, refused := []string{}, map[string]pollSetError{}
	for range ssfPollRounds {
		answer, err := s.askTransmitter(ctx, due, ack, refused)
		if err != nil {
			return err
		}
		ack, refused = []string{}, map[string]pollSetError{}
		for jti, raw := range answer.Sets {
			res := s.acceptSET(ctx, strings.TrimSpace(raw), due.ID)
			switch res.status {
			case http.StatusAccepted:
				ack = append(ack, jti)
			case http.StatusBadRequest:
				// It will never verify, so it is told and not left to come back.
				refused[jti] = pollSetError{Err: res.code, Description: res.description}
			default:
				// Ours, and passing. Neither acknowledged nor refused, so it comes again.
			}
		}
		if !answer.MoreAvailable && len(ack) == 0 && len(refused) == 0 {
			return nil
		}
	}
	return nil
}

// pollSetError is RFC 8936's report of a token that was not taken.
type pollSetError struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

// askTransmitter is one poll: what was done with the last batch, and the next.
func (s *Server) askTransmitter(ctx context.Context, due *store.DueSSFPoll, ack []string, refused map[string]pollSetError) (*pollResponse, error) {
	body, err := json.Marshal(map[string]any{"maxEvents": ssfPollBatch, "returnImmediately": true, "ack": ack, "setErrs": refused})
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, due.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if due.ClientID != "" {
		r.SetBasicAuth(due.ClientID, due.Secret)
	} else if due.Secret != "" {
		r.Header.Set("Authorization", "Bearer "+due.Secret)
	}
	resp, err := s.outboundClient(federationTimeout).Do(r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the transmitter answered %d", resp.StatusCode)
	}
	var answer pollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, ssfPollMaxAnswer)).Decode(&answer); err != nil {
		return nil, fmt.Errorf("the transmitter's answer: %w", err)
	}
	return &answer, nil
}
