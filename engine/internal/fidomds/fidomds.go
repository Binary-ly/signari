// Package fidomds resolves an authenticator's AAGUID to a human-readable model
// name -- "YubiKey 5 NFC" rather than the nickname a user typed -- using the
// FIDO Alliance Metadata Service (MDS) BLOB.
//
// This is display only. The mapping NEVER decides whether a passkey may enrol.
// An allow-list keyed on AAGUID is a separate and deliberate decision -- it can
// lock out a user who bought a model the operator did not foresee -- and it is
// not this. So a missing, stale, or even wrong entry here costs a nicer label,
// never a sign-in.
//
// Off by default. An identity provider that silently reached out to
// fidoalliance.org on every start would be making an outbound call its operator
// never asked for. A source is configured explicitly -- a mounted BLOB file for
// an air-gapped deployment, or an opt-in fetch -- or the resolver is nil and
// every lookup falls back to the nickname.
package fidomds

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"
)

// maxBLOB caps how much is read from a URL source. The real BLOB is a few
// megabytes; the limit stops a misconfigured URL pointing at something enormous
// from exhausting memory.
const maxBLOB = 32 << 20

// DefaultRefresh is how often the catalogue is reloaded. The FIDO MDS BLOB
// changes at most monthly, so a daily reload is already far more current than it
// needs to be, and costs one request a day.
const DefaultRefresh = 24 * time.Hour

// source is where a BLOB comes from. Exactly one of path or url is set.
type source struct {
	path string
	url  string
}

// Resolver holds a snapshot of AAGUID -> model name and refreshes it in the
// background.
//
// A nil *Resolver is valid and resolves nothing, so a caller that was never
// given one needs no special case.
type Resolver struct {
	src  source
	log  *slog.Logger
	http *http.Client
	// table is swapped atomically on each successful refresh, so Model reads are
	// lock-free and never observe a half-built map.
	table atomic.Pointer[map[uuid.UUID]string]
	// loaded records whether a refresh has ever succeeded. It separates
	// "configured but the source has never loaded" -- an operator problem worth
	// surfacing -- from "loaded, and this AAGUID simply is not in the catalogue".
	loaded atomic.Bool
}

// Model returns the authenticator model for an AAGUID, or ok=false when it does
// not resolve: an unknown device, an unconfigured resolver, or a nil one.
//
// The AAGUID is the 16 raw bytes stored on the credential.
func (r *Resolver) Model(aaguid []byte) (string, bool) {
	if r == nil || len(aaguid) != 16 {
		return "", false
	}
	id, err := uuid.FromBytes(aaguid)
	if err != nil || id == uuid.Nil {
		// uuid.Nil is the all-zero AAGUID that many platform authenticators send
		// to avoid being fingerprinted. It is the absence of a model, not a model,
		// and must never map to one.
		return "", false
	}
	t := r.table.Load()
	if t == nil {
		return "", false
	}
	name, ok := (*t)[id]
	return name, ok
}

// Loaded reports whether the catalogue has been read successfully at least once.
func (r *Resolver) Loaded() bool { return r != nil && r.loaded.Load() }

// Size reports how many AAGUIDs are currently resolvable, for diagnostics.
func (r *Resolver) Size() int {
	if r == nil {
		return 0
	}
	if t := r.table.Load(); t != nil {
		return len(*t)
	}
	return 0
}

// Refresh loads the BLOB from the configured source and swaps in a new table.
//
// A failed refresh leaves the previous table in place: a network blip or a
// briefly missing file should not blank out every model name until the next
// tick.
func (r *Resolver) Refresh(ctx context.Context) error {
	if r == nil {
		return nil
	}
	raw, err := r.read(ctx)
	if err != nil {
		return err
	}
	// WithIgnoreEntryParsingErrors: one malformed entry among the hundreds in the
	// BLOB should degrade to that one model being unknown, not the whole catalogue
	// failing to load. The signature over the BLOB is still verified.
	dec, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return fmt.Errorf("fidomds: building a decoder: %w", err)
	}
	payload, err := dec.DecodeBytes(raw)
	if err != nil {
		return fmt.Errorf("fidomds: verifying the metadata BLOB: %w", err)
	}
	md, err := dec.Parse(payload)
	if err != nil {
		return fmt.Errorf("fidomds: parsing the metadata BLOB: %w", err)
	}
	table := make(map[uuid.UUID]string, len(md.Parsed.Entries))
	for i := range md.Parsed.Entries {
		e := &md.Parsed.Entries[i]
		if e.AaGUID == uuid.Nil || e.MetadataStatement.Description == "" {
			continue
		}
		table[e.AaGUID] = e.MetadataStatement.Description
	}
	r.table.Store(&table)
	r.loaded.Store(true)
	r.log.Info("loaded the FIDO metadata catalogue", "authenticators", len(table))
	return nil
}

// read returns the raw BLOB bytes from whichever source is configured.
func (r *Resolver) read(ctx context.Context) ([]byte, error) {
	if r.src.path != "" {
		b, err := os.ReadFile(r.src.path)
		if err != nil {
			return nil, fmt.Errorf("fidomds: reading %s: %w", r.src.path, err)
		}
		return b, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.src.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fidomds: fetching %s: %w", r.src.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fidomds: fetching %s: status %d", r.src.url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBLOB))
}

// Run refreshes once, then on every tick until the context ends.
//
// The first refresh is best-effort: a failure is logged and the loop keeps
// trying, because the model catalogue is an enhancement and must never hold up
// serving.
func (r *Resolver) Run(ctx context.Context, interval time.Duration) {
	if r == nil {
		return
	}
	if err := r.Refresh(ctx); err != nil {
		r.log.Warn("the FIDO metadata catalogue did not load; model names are unavailable", "err", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Refresh(ctx); err != nil {
				r.log.Warn("refreshing the FIDO metadata catalogue failed; keeping the previous one", "err", err)
			}
		}
	}
}

// NewFromEnv builds a resolver from the environment, or returns nil when no
// source is configured -- the default, in which case model names are simply not
// shown.
//
//	SIGNARI_FIDO_MDS_PATH   a mounted copy of the MDS BLOB (air-gapped / pinned)
//	SIGNARI_FIDO_MDS_URL    fetch the BLOB from this URL
//	SIGNARI_FIDO_MDS_FETCH  "1" fetches from the official FIDO endpoint
//
// A path wins over a URL if both are set. The BLOB, wherever it comes from, must
// be signed by the FIDO production root; an unsigned or wrongly signed BLOB is
// refused, because a spoofed catalogue naming an attacker's device after a
// trusted one is the only way this display feature could mislead.
func NewFromEnv(getenv func(string) string, log *slog.Logger) *Resolver {
	var src source
	switch {
	case getenv("SIGNARI_FIDO_MDS_PATH") != "":
		src.path = getenv("SIGNARI_FIDO_MDS_PATH")
	case getenv("SIGNARI_FIDO_MDS_URL") != "":
		src.url = getenv("SIGNARI_FIDO_MDS_URL")
	case getenv("SIGNARI_FIDO_MDS_FETCH") == "1":
		src.url = metadata.ProductionMDSURL
	default:
		return nil
	}
	return &Resolver{
		src:  src,
		log:  log,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}
