package fidomds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// withTable builds a resolver whose catalogue is set directly, bypassing the
// network. The AAGUID resolution logic is what these tests exercise; the BLOB
// decoding is the go-webauthn library's own concern.
func withTable(t map[uuid.UUID]string) *Resolver {
	r := &Resolver{log: quietLog()}
	r.table.Store(&t)
	r.loaded.Store(true)
	return r
}

// A real YubiKey 5 series AAGUID, so the test resolves the same 16 bytes a
// credential actually stores.
const yubi5 = "ee882879-721c-4913-9775-3dfcce97072a"

func TestModelResolvesAStoredAAGUID(t *testing.T) {
	id := uuid.MustParse(yubi5)
	r := withTable(map[uuid.UUID]string{id: "YubiKey 5 NFC"})

	got, ok := r.Model(id[:])
	if !ok {
		t.Fatalf("a known AAGUID did not resolve")
	}
	if got != "YubiKey 5 NFC" {
		t.Errorf("resolved %q, want %q", got, "YubiKey 5 NFC")
	}
}

func TestModelUnknownAAGUIDDoesNotResolve(t *testing.T) {
	known := uuid.MustParse(yubi5)
	other := uuid.MustParse("00000000-0000-0000-0000-0000000000ff")
	r := withTable(map[uuid.UUID]string{known: "YubiKey 5 NFC"})

	if _, ok := r.Model(other[:]); ok {
		t.Error("an AAGUID absent from the catalogue resolved to a model")
	}
}

// The all-zero AAGUID is what many platform authenticators send to avoid being
// fingerprinted. It is the absence of a model, and must never map to one even if
// a catalogue somehow carried an entry for it.
func TestModelRejectsTheNilAAGUID(t *testing.T) {
	r := withTable(map[uuid.UUID]string{uuid.Nil: "should never be shown"})
	zero := make([]byte, 16)
	if got, ok := r.Model(zero); ok {
		t.Errorf("the all-zero AAGUID resolved to %q; it must be treated as no model", got)
	}
}

func TestModelRejectsWrongLength(t *testing.T) {
	r := withTable(map[uuid.UUID]string{uuid.MustParse(yubi5): "YubiKey 5 NFC"})
	for _, b := range [][]byte{nil, {}, make([]byte, 15), make([]byte, 17)} {
		if _, ok := r.Model(b); ok {
			t.Errorf("a %d-byte AAGUID resolved; only 16 bytes is a valid AAGUID", len(b))
		}
	}
}

// A nil resolver is the unconfigured case, and every caller relies on it being
// safe so no notice path has to nil-check before naming a passkey.
func TestNilResolverIsSafe(t *testing.T) {
	var r *Resolver
	if _, ok := r.Model(make([]byte, 16)); ok {
		t.Error("a nil resolver resolved a model")
	}
	if r.Loaded() {
		t.Error("a nil resolver reported itself loaded")
	}
	if r.Size() != 0 {
		t.Error("a nil resolver reported a non-zero size")
	}
}

func TestNewFromEnvSelectsASource(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantNil bool
		wantURL string
		want    string // "path", "url", or ""
	}{
		{name: "nothing configured", env: nil, wantNil: true},
		{name: "path", env: map[string]string{"SIGNARI_FIDO_MDS_PATH": "/etc/mds.jwt"}, want: "path"},
		{name: "url", env: map[string]string{"SIGNARI_FIDO_MDS_URL": "https://mirror.example/mds"}, want: "url", wantURL: "https://mirror.example/mds"},
		{name: "fetch", env: map[string]string{"SIGNARI_FIDO_MDS_FETCH": "1"}, want: "url"},
		{
			name: "path wins over url",
			env: map[string]string{
				"SIGNARI_FIDO_MDS_PATH": "/etc/mds.jwt",
				"SIGNARI_FIDO_MDS_URL":  "https://mirror.example/mds",
			},
			want: "path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string { return c.env[k] }
			r := NewFromEnv(getenv, quietLog())
			if c.wantNil {
				if r != nil {
					t.Fatalf("expected no resolver when no source is configured, got %+v", r.src)
				}
				return
			}
			if r == nil {
				t.Fatal("expected a resolver, got nil")
			}
			switch c.want {
			case "path":
				if r.src.path == "" || r.src.url != "" {
					t.Errorf("expected a file source, got %+v", r.src)
				}
			case "url":
				if r.src.url == "" || r.src.path != "" {
					t.Errorf("expected a url source, got %+v", r.src)
				}
				if c.wantURL != "" && r.src.url != c.wantURL {
					t.Errorf("url = %q, want %q", r.src.url, c.wantURL)
				}
			}
		})
	}
}

func TestReadFromFileReturnsTheBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mds.jwt")
	want := []byte("not a real blob, just bytes")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{src: source{path: path}, log: quietLog()}
	got, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}
}

// An unsigned or corrupt BLOB must be refused, AND the previously loaded
// catalogue must survive the failure -- a bad refresh should degrade to "the
// last good names" rather than "no names at all".
func TestRefreshRejectsAGarbageBlobAndKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mds.jwt")
	if err := os.WriteFile(path, []byte("this is not a signed JWT"), 0o600); err != nil {
		t.Fatal(err)
	}

	id := uuid.MustParse(yubi5)
	r := &Resolver{src: source{path: path}, log: quietLog()}
	// Seed a good table, as a prior successful refresh would have.
	seed := map[uuid.UUID]string{id: "YubiKey 5 NFC"}
	r.table.Store(&seed)
	r.loaded.Store(true)

	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh accepted a BLOB that is not a signed JWT")
	}
	// The old table is still in force.
	if got, ok := r.Model(id[:]); !ok || got != "YubiKey 5 NFC" {
		t.Errorf("a failed refresh discarded the previous catalogue: got %q ok=%v", got, ok)
	}
}

// withEntries builds a loaded resolver holding catalogue entries for ids.
func withEntries(ids ...uuid.UUID) *Resolver {
	r := withTable(map[uuid.UUID]string{})
	m := map[uuid.UUID]*metadata.Entry{}
	for _, id := range ids {
		m[id] = &metadata.Entry{AaGUID: id}
	}
	r.entries.Store(&m)
	return r
}

// issue makes a certificate for cn, signed by parent (self-signed when parent
// is nil), with any extra extensions.
func issue(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool,
	ext ...pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"Vendor"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: ca,
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtraExtensions: ext,
	}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// attObject is a CBOR attestation object whose statement carries chain as x5c.
func attObject(t *testing.T, chain ...*x509.Certificate) []byte {
	t.Helper()
	stmt := map[string]any{"alg": int64(-7), "sig": []byte{1}}
	if len(chain) > 0 {
		x5c := []any{}
		for _, c := range chain {
			x5c = append(x5c, c.Raw)
		}
		stmt["x5c"] = x5c
	}
	b, err := webauthncbor.Marshal(map[string]any{"fmt": "packed", "authData": []byte{0}, "attStmt": stmt})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Only a certificate chain that reaches the roots the catalogue lists for the
// model vouches for an AAGUID, whatever the certificates' common names. Every
// other combination must say no, and a chain for a listed model that does not
// reach its roots must be refused -- this is what the approved-model
// allow-list rests on.
func TestOnlyAnAnchoredChainVouchesForAnAAGUID(t *testing.T) {
	listed := uuid.MustParse(yubi5)
	unlisted := uuid.MustParse("00000000-0000-0000-0000-0000000000ff")

	root, rootKey := issue(t, "Vendor Root", nil, nil, true)
	inter, interKey := issue(t, "Vendor Intermediate", root, rootKey, true)
	r := withEntries(listed)
	(*r.entries.Load())[listed].MetadataStatement.AttestationRootCertificates = []*x509.Certificate{root}

	genuine, _ := issue(t, "Vendor EE", root, rootKey, false)
	viaInter, _ := issue(t, "Vendor EE 2", inter, interKey, false)
	// A genuine leaf may share its issuer's common name; the old library path
	// skipped the check for exactly this shape, so it must still pass on merit.
	sameNameGenuine, _ := issue(t, "Vendor Root", root, rootKey, false)
	selfSigned, _ := issue(t, "Totally A YubiKey", nil, nil, false)
	fakeCA, fakeKey := issue(t, "Same Name", nil, nil, true)
	sameNameForged, _ := issue(t, "Same Name", fakeCA, fakeKey, false)
	otherCA, otherKey := issue(t, "Attacker CA", nil, nil, true)
	otherForged, _ := issue(t, "Leaf", otherCA, otherKey, false)

	// A TPM AIK certificate: empty subject, a critical SAN holding only a
	// directoryName, which x509 leaves unhandled, and the AIK key purpose
	// rather than a TLS one.
	tpmName, _ := asn1.Marshal(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:49465800"}}}.ToRDNSequence())
	san, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: tpmName}})
	aikEKU, _ := asn1.Marshal([]asn1.ObjectIdentifier{{2, 23, 133, 8, 3}})
	aik, _ := issue(t, "", root, rootKey, false,
		pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: san},
		pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: aikEKU})
	if len(aik.UnhandledCriticalExtensions) == 0 {
		t.Fatal("the AIK fixture's SAN is not left unhandled, so it proves nothing")
	}

	cases := []struct {
		name    string
		r       *Resolver
		aaguid  uuid.UUID
		attType string
		object  []byte
		vouched bool
		refused bool
	}{
		{"chain for a listed model", r, listed, "basic_full", attObject(t, genuine), true, false},
		{"chain through an intermediate", r, listed, "basic_full", attObject(t, viaInter, inter), true, false},
		{"genuine leaf sharing its issuer's name", r, listed, "basic_full", attObject(t, sameNameGenuine), true, false},
		{"attestation CA with a TPM SAN", r, listed, "attca", attObject(t, aik), true, false},
		{"self-signed leaf claiming a listed model", r, listed, "basic_full", attObject(t, selfSigned), false, true},
		{"made-up CA sharing the leaf's name", r, listed, "basic_full", attObject(t, sameNameForged, fakeCA), false, true},
		{"made-up CA with another name", r, listed, "basic_full", attObject(t, otherForged, otherCA), false, true},
		{"made-up AIK", r, listed, "attca", attObject(t, selfSigned), false, true},
		{"chain kept outside x5c", r, listed, "basic_full", attObject(t), false, false},
		{"packed self-attestation", r, listed, "basic_surrogate", attObject(t), false, false},
		{"no attestation", r, listed, "none", attObject(t), false, false},
		{"chain for an unlisted model (accepted unexamined by the library)", r, unlisted, "basic_full", attObject(t, selfSigned), false, false},
		{"no catalogue configured", nil, listed, "basic_full", attObject(t, genuine), false, false},
		{"catalogue configured but never loaded", &Resolver{log: quietLog()}, listed, "basic_full", attObject(t, genuine), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := AttestationAnchored(c.r, c.aaguid[:], c.attType, c.object)
			if got != c.vouched {
				t.Errorf("vouched = %v, want %v (err %v)", got, c.vouched, err)
			}
			if refused := errors.Is(err, ErrUnanchoredChain); refused != c.refused {
				t.Errorf("refused = %v, want %v (err %v)", refused, c.refused, err)
			}
		})
	}

	if ok, err := AttestationAnchored(r, make([]byte, 16), "basic_full", attObject(t, genuine)); ok || err != nil {
		t.Errorf("the all-zero AAGUID was vouched for or refused: %v %v", ok, err)
	}
}

// The ceremony gets a provider only when there is a loaded catalogue, and the
// provider enforces the trust anchor and the revocation statuses.
func TestTheProviderIsOnlyGivenWhenLoadedAndEnforcesAnchorsAndStatus(t *testing.T) {
	var none *Resolver
	if none.Provider() != nil {
		t.Error("a nil resolver produced a provider")
	}
	if (&Resolver{log: quietLog()}).Provider() != nil {
		t.Error("a never-loaded resolver produced a provider")
	}
	p := withEntries(uuid.MustParse(yubi5)).Provider()
	if p == nil {
		t.Fatal("a loaded resolver produced no provider")
	}
	ctx := context.Background()
	if !p.GetValidateTrustAnchor(ctx) {
		t.Error("the provider does not enforce trust anchors, so a self-made chain passes")
	}
	if !p.GetValidateStatus(ctx) {
		t.Error("the provider does not refuse revoked or compromised models")
	}
	if p.GetValidateEntry(ctx) {
		t.Error("the provider refuses models absent from the catalogue, turning it into a lockout")
	}
	if err := p.ValidateStatusReports(ctx, []metadata.StatusReport{{Status: metadata.Revoked}}); err == nil {
		t.Error("a revoked model passed status validation")
	}
}

func TestRefreshReportsAMissingFile(t *testing.T) {
	r := &Resolver{src: source{path: filepath.Join(t.TempDir(), "absent.jwt")}, log: quietLog()}
	if err := r.Refresh(context.Background()); err == nil {
		t.Error("Refresh did not report a missing source file")
	}
}
