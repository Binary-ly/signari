package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/flow"
)

// A reload of the sign-in flows whose read fails partway keeps the flows
// already loaded (0.31). It replaced them with what it had read, so every
// organisation whose row went unread was served the built-in journey, the one
// its operator had replaced, perhaps to require a second factor.

// failedRows is a read that ends with an error, as pgx reports one: no more
// rows, and the failure from Err.
type failedRows struct{}

func (failedRows) Close()                                       {}
func (failedRows) Err() error                                   { return errors.New("connection reset mid-read") }
func (failedRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (failedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (failedRows) Next() bool                                   { return false }
func (failedRows) Scan(...any) error                            { return nil }
func (failedRows) Values() ([]any, error)                       { return nil, nil }
func (failedRows) RawValues() [][]byte                          { return nil }
func (failedRows) Conn() *pgx.Conn                              { return nil }

type failingReader struct{}

func (failingReader) QueryRow(context.Context, string, ...any) pgx.Row { return nil }
func (failingReader) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return failedRows{}, nil
}

func TestAFailedFlowReloadKeepsTheFlowsAlreadyLoaded(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), flows: newFlowCache()}
	configured := &flow.File{}
	s.flows.byOrg["org-with-a-flow"] = configured
	s.flows.everLoaded = true

	s.reloadFlowsFrom(context.Background(), failingReader{})

	s.flows.mu.RLock()
	defer s.flows.mu.RUnlock()
	if s.flows.byOrg["org-with-a-flow"] != configured {
		t.Error("a reload whose read failed dropped the organisation's flow, so it is served the built-in journey")
	}
}
