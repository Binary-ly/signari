package passwords

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// The cost new passwords are hashed with, and the pepper (4.08).
//
// The Argon2id cost was three constants, the OWASP minimums, whatever the
// hardware. It is set with SIGNARI_ARGON2_MEMORY_MIB, _ITERATIONS and
// _PARALLELISM, never below those minimums, and a password hashed under a
// lower cost is rehashed at its next sign-in, so raising it reaches everybody
// who signs in. `signari passwords calibrate` says what this host can afford.
//
// A pepper is a secret mixed into every password before it is hashed, kept out
// of the database as the root key is, so a stolen database alone cannot be
// guessed against. SIGNARI_PASSWORD_PEPPERS lists them as id:base64, the first
// the current one. Each hash names the pepper it was made with (`k=<id>` among
// its parameters), so a new pepper is added in front, every password moves to
// it at its next sign-in, and the old one can be removed once doctor reports no
// hash naming it. Removing a pepper a hash still names makes that password
// unverifiable: the person resets it.

// Params are an Argon2id cost.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Floor is the OWASP Password Storage Cheat Sheet's minimum, the default, and
// the least SIGNARI_ARGON2_* may set.
var Floor = Params{MemoryKiB: argonMemoryKiB, Time: argonTime, Threads: argonThreads}

// The most SIGNARI_ARGON2_* may set. 256 MiB, so the shared 512 MiB budget
// still lets two run at once; the time and threads ceilings are an imported
// hash's (argonMaxTime, argonMaxThreads), so our own hashes re-verify.
const (
	maxConfiguredMemoryKiB = 256 * 1024
	maxConfiguredTime      = argonMaxTime
	maxConfiguredThreads   = argonMaxThreads
)

// Pepper is one secret and the id hashes name it by.
type Pepper struct {
	ID  string
	Key []byte
}

// Config is what the shared Hasher hashes with.
type Config struct {
	Params Params
	// Peppers, the current one first. Empty is no pepper.
	Peppers []Pepper
}

var pepperID = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// ConfigFromEnv reads SIGNARI_ARGON2_* and SIGNARI_PASSWORD_PEPPERS, refusing
// a value it would have to ignore: a cost below the floor or above the
// ceiling, or a pepper that is short, malformed or named twice. serve refuses
// to start on one, because hashing with something other than what was set is
// a weaker password store nobody chose.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{Params: Floor}
	read := func(name string, floor, ceiling int64) (int64, bool, error) {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return 0, false, nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < floor || n > ceiling {
			return 0, false, fmt.Errorf("%s=%q: give a whole number from %d to %d", name, v, floor, ceiling)
		}
		return n, true, nil
	}
	if n, ok, err := read("SIGNARI_ARGON2_MEMORY_MIB", int64(argonMemoryKiB/1024),
		maxConfiguredMemoryKiB/1024); err != nil {
		return c, err
	} else if ok {
		c.Params.MemoryKiB = uint32(n * 1024)
	}
	if n, ok, err := read("SIGNARI_ARGON2_ITERATIONS", argonTime, maxConfiguredTime); err != nil {
		return c, err
	} else if ok {
		c.Params.Time = uint32(n)
	}
	if n, ok, err := read("SIGNARI_ARGON2_PARALLELISM", argonThreads, maxConfiguredThreads); err != nil {
		return c, err
	} else if ok {
		c.Params.Threads = uint8(n)
	}

	seen := map[string]bool{}
	for _, entry := range strings.Split(getenv("SIGNARI_PASSWORD_PEPPERS"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, encoded, ok := strings.Cut(entry, ":")
		if !ok || !pepperID.MatchString(id) {
			return c, fmt.Errorf("SIGNARI_PASSWORD_PEPPERS: each entry is id:base64, the id 1 to 16 " +
				"lower-case letters or digits")
		}
		if seen[id] {
			return c, fmt.Errorf("SIGNARI_PASSWORD_PEPPERS names %q twice", id)
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			key, err = base64.RawURLEncoding.DecodeString(encoded)
		}
		if err != nil || len(key) < 32 {
			return c, fmt.Errorf("SIGNARI_PASSWORD_PEPPERS: pepper %q must be at least 32 random "+
				"bytes, base64", id)
		}
		seen[id] = true
		c.Peppers = append(c.Peppers, Pepper{ID: id, Key: key})
	}
	return c, nil
}

// current is the pepper new hashes are made with, or nil.
func (c *Config) current() *Pepper {
	if c == nil || len(c.Peppers) == 0 {
		return nil
	}
	return &c.Peppers[0]
}

// pepper finds a pepper by id.
func (c *Config) pepper(id string) (*Pepper, bool) {
	if c == nil {
		return nil, false
	}
	for i := range c.Peppers {
		if c.Peppers[i].ID == id {
			return &c.Peppers[i], true
		}
	}
	return nil, false
}

// params are the cost new hashes are made with.
func (c *Config) params() Params {
	if c == nil {
		return Floor
	}
	return c.Params
}

// peppered is the password a hash is made of under p: HMAC-SHA256 keyed with
// the pepper. A keyed hash rather than concatenation, so a pepper cannot be
// recovered from, or cancelled by, anything a person types.
func peppered(p *Pepper, password string) string {
	if p == nil {
		return password
	}
	mac := hmac.New(sha256.New, p.Key)
	mac.Write([]byte(password))
	return string(mac.Sum(nil))
}

// hashParams reads a PHC parameter segment (`m=19456,t=2,p=1,k=a`) into its
// pairs.
func hashParams(segment string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(segment, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

// Measure is how long one Argon2id derivation with p takes on this host, the
// middle of three, for `signari passwords calibrate`.
func Measure(p Params) time.Duration {
	salt := make([]byte, argonSaltLen)
	runs := make([]time.Duration, 3)
	for i := range runs {
		start := time.Now()
		argon2.IDKey([]byte("calibration"), salt, p.Time, p.MemoryKiB, p.Threads, argonKeyLen)
		runs[i] = time.Since(start)
	}
	slices.Sort(runs)
	return runs[1]
}

// Bounds are what SIGNARI_ARGON2_* may be set to, for calibration to stay in.
func Bounds() (floor, ceiling Params) {
	return Floor, Params{MemoryKiB: maxConfiguredMemoryKiB, Time: maxConfiguredTime,
		Threads: maxConfiguredThreads}
}

// PepperID is the pepper a stored hash names, or empty, for doctor: a hash
// naming one that is not configured can never verify.
func PepperID(stored string) string {
	parts := strings.Split(stored, "$")
	switch {
	case strings.HasPrefix(stored, "$argon2id$") && len(parts) > 3:
		return hashParams(parts[3])["k"]
	case strings.HasPrefix(stored, pbkdf2Prefix) && len(parts) > 2:
		return hashParams(parts[2])["k"]
	}
	return ""
}
