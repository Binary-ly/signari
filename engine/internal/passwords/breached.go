package passwords

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the HIBP range API, not a security claim
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Refusing passwords that are already in a breach corpus.
//
// # The password never leaves this process
//
// The Have I Been Pwned range API is a k-anonymity construction: SHA-1 the
// candidate, send the FIRST FIVE hex characters of the digest, and receive every
// suffix sharing that prefix — around 800 of them. The comparison happens here.
//
// So the service learns a 20-bit prefix shared by roughly one in a million
// passwords and never sees the password, the digest, or which suffix matched.
// SHA-1 appears here because the API is defined in terms of it; it is an index
// into a public corpus, not a security claim about the password.
//
// # An offline list, which the alternatives do not offer
//
// Every comparable implementation requires calling a third party on the path of
// a password change. Plenty of deployments cannot: airgapped networks,
// regulated environments, anywhere an outbound call from the identity provider
// is a review. So a local file of SHA-1 prefixes is supported as an equal
// citizen, and a deployment can use one, the other, or both.
//
// # Reachability is not a verdict
//
// When the corpus cannot be consulted, this reports that it could not check —
// never that the password is fine. What to do about that is the caller's
// decision, and Policy makes it explicitly rather than by omission.

// ErrUnavailable means the corpus could not be consulted.
//
// Distinct from "not breached" on purpose. Collapsing them is how an outage at a
// third party silently turns a control off, and nobody finds out because the
// system keeps saying yes.
var ErrUnavailable = fmt.Errorf("the breach corpus could not be consulted")

// HIBPEndpoint is the range API.
const HIBPEndpoint = "https://api.pwnedpasswords.com/range/"

// BreachChecker reports whether a password appears in a breach corpus.
type BreachChecker struct {
	// Endpoint overrides the range API, for tests and mirrors.
	Endpoint string
	// LocalFile is a newline-separated list of SHA-1 hashes (full or suffix
	// form, upper or lower case). Loaded once, kept in memory.
	LocalFile string
	// Online enables the range API. Both may be used together: local first,
	// because it costs nothing and cannot fail.
	Online bool

	HTTP    *http.Client
	Timeout time.Duration

	once  sync.Once
	local map[string]bool
	err   error
}

func (b *BreachChecker) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	t := b.Timeout
	if t <= 0 {
		// Short. This sits on the path of a password change, and a person
		// waiting on a form should not wait on somebody else's outage.
		t = 3 * time.Second
	}
	return &http.Client{Timeout: t}
}

// loadLocal reads the offline corpus once.
func (b *BreachChecker) loadLocal() {
	b.once.Do(func() {
		if b.LocalFile == "" {
			return
		}
		f, err := os.Open(b.LocalFile)
		if err != nil {
			b.err = fmt.Errorf("opening the local breach list: %w", err)
			return
		}
		defer func() { _ = f.Close() }()

		b.local = make(map[string]bool, 1<<16)
		sc := bufio.NewScanner(f)
		// Lines in the published corpus are short; the default buffer is ample.
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// The published format is HASH:COUNT. The count is not used: a
			// password in the corpus once is still in the corpus.
			if i := strings.IndexByte(line, ':'); i >= 0 {
				line = line[:i]
			}
			b.local[strings.ToUpper(line)] = true
		}
		if err := sc.Err(); err != nil {
			b.err = fmt.Errorf("reading the local breach list: %w", err)
		}
	})
}

// Breached reports whether the password appears in the corpus.
//
// Returns ErrUnavailable when no source could answer, which is not the same as
// false and must not be treated as such by the caller.
func (b *BreachChecker) Breached(ctx context.Context, password string) (bool, error) {
	if password == "" {
		return false, nil
	}
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- see the file comment
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	// Local first: it costs nothing, cannot fail, and cannot leak anything.
	b.loadLocal()
	if b.err != nil {
		return false, b.err
	}
	if b.local != nil {
		if b.local[digest] || b.local[suffix] {
			return true, nil
		}
		// A local list that does not contain it is only conclusive when there is
		// no online source to consult as well.
		if !b.Online {
			return false, nil
		}
	}

	if !b.Online {
		return false, ErrUnavailable
	}

	endpoint := b.Endpoint
	if endpoint == "" {
		endpoint = HIBPEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+prefix, nil)
	if err != nil {
		return false, err
	}
	// Padding asks the service to return a variable number of decoy suffixes, so
	// the RESPONSE SIZE does not narrow down which prefix was asked about to
	// anyone watching the connection.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "signari")

	resp, err := b.client().Do(req)
	if err != nil {
		return false, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, ErrUnavailable
	}

	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), suffix) {
			// Padding entries are returned with a count of 0. A real match has a
			// non-zero count, and treating a decoy as a match would refuse a
			// password that is not in the corpus at all.
			if strings.TrimSpace(line[i+1:]) == "0" {
				continue
			}
			return true, nil
		}
	}
	return false, sc.Err()
}
