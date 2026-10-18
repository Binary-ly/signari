// Package fidomds reads the FIDO Alliance Metadata Service (MDS) BLOB for two
// purposes.
//
// Display: an authenticator's AAGUID resolves to a model name -- "YubiKey 5 NFC"
// rather than the nickname a user typed.
//
// Trust anchors: the Resolver is a go-webauthn metadata.Provider, so a
// registration that conveys a certificate-chain attestation is checked against
// the roots the catalogue lists for that model, and a model the Alliance has
// marked revoked or compromised is refused. This is what lets an approved-model
// allow-list mean anything: an AAGUID is the authenticator's own claim, and
// only a chain anchored in the catalogue vouches for it. Without a catalogue an
// allow-list can verify nothing, and registration under one is refused.
//
// The model name still never decides enrolment on its own, and a model with no
// catalogue entry is not refused -- the allow-list is a separate, deliberate
// operator decision, because it can lock out a user who bought a model nobody
// foresaw.
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
	// entries is the full catalogue, swapped with table, for attestation
	// anchoring. Separate from table because a model with an entry need not
	// have a description, and the reverse.
	entries atomic.Pointer[map[uuid.UUID]*metadata.Entry]
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

// Anchors reports whether the catalogue holds an entry for this AAGUID.
//
// That is the condition under which go-webauthn checks a certificate-chain
// attestation against a trust anchor at all: with no entry it accepts the chain
// unexamined. So a registration's attestation vouches for its AAGUID only when
// this is true AND the attestation carried a chain -- see AttestationAnchored.
func (r *Resolver) Anchors(aaguid []byte) bool {
	if r == nil || len(aaguid) != 16 {
		return false
	}
	id, err := uuid.FromBytes(aaguid)
	if err != nil || id == uuid.Nil {
		return false
	}
	m := r.entries.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[id]
	return ok
}

// chainTypes are the attestation types that carry a certificate chain, which
// is the only kind a trust anchor can vouch for. basic_surrogate (packed
// self-attestation) is signed by the credential's own key, so it proves the
// authenticator holds that key and nothing about what model it is.
var chainTypes = map[string]bool{"basic_full": true, "attca": true, "anonca": true}

// AttestationAnchored reports whether a completed registration's AAGUID is
// vouched for: the catalogue was loaded and given to the ceremony, it holds an
// entry for the model, and the attestation was a certificate chain -- which
// go-webauthn then validated against that entry's roots or refused.
func AttestationAnchored(r *Resolver, aaguid []byte, attestationType string) bool {
	return r.Loaded() && chainTypes[attestationType] && r.Anchors(aaguid)
}

// Provider returns the Resolver as a go-webauthn metadata provider, or nil when
// there is no loaded catalogue -- so a ceremony without one is configured with
// no provider at all rather than an empty one.
func (r *Resolver) Provider() metadata.Provider {
	if !r.Loaded() {
		return nil
	}
	return r
}

// GetEntry implements metadata.Provider.
func (r *Resolver) GetEntry(_ context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
	if r == nil {
		return nil, nil
	}
	m := r.entries.Load()
	if m == nil {
		return nil, nil
	}
	return (*m)[aaguid], nil
}

// GetValidateEntry implements metadata.Provider: a model absent from the
// catalogue is not refused. Plenty of legitimate authenticators are not listed,
// and refusing them would turn an optional catalogue into a lockout.
func (r *Resolver) GetValidateEntry(context.Context) bool { return false }

// GetValidateEntryPermitZeroAAGUID implements metadata.Provider.
func (r *Resolver) GetValidateEntryPermitZeroAAGUID(context.Context) bool { return true }

// GetValidateTrustAnchor implements metadata.Provider: a chain for a listed
// model must anchor in that model's roots.
func (r *Resolver) GetValidateTrustAnchor(context.Context) bool { return true }

// GetValidateStatus implements metadata.Provider: a listed model the Alliance
// has marked revoked or compromised is refused at registration.
func (r *Resolver) GetValidateStatus(context.Context) bool { return true }

// GetValidateAttestationTypes implements metadata.Provider. Off: entries are
// not consistently complete about the types a model uses, and a mismatch is not
// evidence of anything worth refusing a user over.
func (r *Resolver) GetValidateAttestationTypes(context.Context) bool { return false }

// ValidateStatusReports implements metadata.Provider with the library's
// default undesired statuses (revoked, attestation key compromise, user
// verification bypass, user key compromise).
func (r *Resolver) ValidateStatusReports(_ context.Context, reports []metadata.StatusReport) error {
	return metadata.ValidateStatusReports(reports, nil, metadata.DefaultUndesiredAuthenticatorStatuses())
}

var _ metadata.Provider = (*Resolver)(nil)

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
	entries := make(map[uuid.UUID]*metadata.Entry, len(md.Parsed.Entries))
	for i := range md.Parsed.Entries {
		e := &md.Parsed.Entries[i]
		if e.AaGUID == uuid.Nil {
			continue
		}
		entries[e.AaGUID] = e
		if e.MetadataStatement.Description != "" {
			table[e.AaGUID] = e.MetadataStatement.Description
		}
	}
	r.table.Store(&table)
	r.entries.Store(&entries)
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
