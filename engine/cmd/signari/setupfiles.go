package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"signari.dev/engine/internal/keys"
)

// The files `signari setup` writes, and how. Two of them, each holding a secret:
// the root key, which seals every stored secret and is kept nowhere else, and
// the env file `serve` reads, which holds the engine's database password.
//
// Each is written whole or not at all: to a temporary file beside it, synced,
// then moved into place. The root key is moved by a hard link, which fails when
// the name is taken, so no run and no race can replace a key that may already
// have sealed something. Both are 0600, and, when root runs setup, belong to the
// owner of the directory they are made in: a /etc/signari made for the service's
// own user gives that user its key, so a later run as root does not leave the
// service unable to read a file root made.

// setupFileNames are the defaults for -root-key-file and -env-file.
const (
	rootKeyFileName = "root.key"
	envFileName     = "signari.env"
)

// setupConfigDir is where setup keeps its two files unless told otherwise:
// /etc/signari for root, else the user's configuration directory, the XDG one
// when it is set.
func setupConfigDir(euid int, getenv func(string) string, home string) string {
	if euid == 0 {
		return "/etc/signari"
	}
	if x := getenv("XDG_CONFIG_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, "signari")
	}
	return filepath.Join(home, ".config", "signari")
}

// setupDirMode is the mode a directory setup makes is given: 0750 for root,
// whose /etc/signari a service user's group may need to traverse, else 0700.
func setupDirMode(euid int) fs.FileMode {
	if euid == 0 {
		return 0o750
	}
	return 0o700
}

// errFileExists is a file setup was to create and found already there.
var errFileExists = errors.New("the file is already there")

// writeFileAtomic writes data to path through a temporary file in its
// directory. With create, the file is put in place by a hard link, so one
// already there is never replaced and errFileExists says so; otherwise it
// replaces what is there by rename. made records the directories it had to
// create, so a failed run can remove them again.
func writeFileAtomic(path string, data []byte, create bool, euid int, made *[]string) error {
	dir := filepath.Dir(path)
	if err := mkdirAllRecorded(dir, setupDirMode(euid), made); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if euid == 0 {
		if uid, gid, ok := dirOwner(dir); ok && uid != 0 {
			if err := os.Chown(tmp, uid, gid); err != nil {
				return fmt.Errorf("giving %s to the owner of %s: %w", path, dir, err)
			}
		}
	}
	if create {
		switch err := os.Link(tmp, path); {
		case errors.Is(err, fs.ErrExist):
			return errFileExists
		case err != nil:
			// A file system without hard links: an exclusive create refuses a
			// file already there just the same, without the atomic move.
			if err := writeExclusive(path, data); err != nil {
				return err
			}
		}
	} else if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// writeExclusive creates path, refusing one that is there, and writes data.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 G703 -- the operator names the file
	if errors.Is(err, fs.ErrExist) {
		return errFileExists
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// syncDir makes a rename or link in dir durable. Best effort: a file system
// that cannot sync a directory still has the file.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 G703 -- the directory of a file the operator names
		_ = d.Sync()
		_ = d.Close()
	}
}

// mkdirAllRecorded is os.MkdirAll that appends each directory it made to made,
// outermost first.
func mkdirAllRecorded(dir string, mode fs.FileMode, made *[]string) error {
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if made != nil {
			*made = append(*made, missing[i])
		}
	}
	return nil
}

// newRootKeyFile is a root key as SIGNARI_ROOT_KEY_FILE holds one: 32 random
// bytes, base64, and a newline.
func newRootKeyFile() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), nil
}

// loadRootKeyFile opens the root key at path by the rules `serve` applies to
// SIGNARI_ROOT_KEY_FILE, and nothing else: no inline key, no module, no key
// accepted beside it.
func loadRootKeyFile(path string) (*keys.RootKey, error) {
	return keys.LoadRootKeyring(func(name string) string {
		if name == "SIGNARI_ROOT_KEY_FILE" {
			return path
		}
		return ""
	})
}

// rootKeyFileState says what is at path: nothing, a key serve would open, or
// something that is neither, with the fix.
func rootKeyFileState(path string) (exists bool, err error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	if _, err := loadRootKeyFile(path); err != nil {
		return true, fmt.Errorf("%s is there and serve would refuse it: %w. Setup never replaces a root "+
			"key: fix this one, or name another with -root-key-file", path, err)
	}
	return true, nil
}

// envKeys are the settings setup writes to the env file, in the order it
// writes them.
var envKeys = []string{"SIGNARI_DSN", "SIGNARI_ROOT_KEY_FILE", "SIGNARI_ISSUER", "SIGNARI_ADDR"}

// envOrder is every setting setup may write, in that order: the four it
// always does, then those the TLS chosen needs (setuptls.go).
var envOrder = append(slices.Clone(envKeys), "SIGNARI_TLS_CERT", "SIGNARI_TLS_KEY", "SIGNARI_TRUSTED_PROXIES",
	"SIGNARI_CLIENT_IP_SOURCE")

// envFile is an env file as setup reads one: its lines, kept as written, and
// the settings in them.
type envFile struct {
	path   string
	exists bool
	lines  []string
	values map[string]string
}

var envLine = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// readEnvFile reads the env file at path, which need not exist. A file its
// group or anybody else may read is refused: it holds a database password.
func readEnvFile(path string) (envFile, error) {
	e := envFile{path: path, values: map[string]string{}}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	if info.IsDir() {
		return e, fmt.Errorf("%s is a directory, and -env-file names a file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return e, fmt.Errorf("%s may be read by its group or others (mode %04o), and it holds the engine's "+
			"database password: chmod 600 %s, then run setup again", path, perm, path)
	}
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- the operator names the file
	if err != nil {
		return e, err
	}
	e.exists = true
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		e.lines = append(e.lines, line)
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if m := envLine.FindStringSubmatch(t); m != nil {
			e.values[m[1]] = unquoteEnv(m[2])
		}
	}
	return e, sc.Err()
}

// unquoteEnv is a value as the shell and systemd both read it, for the forms
// setup writes: bare, or in matching single or double quotes.
func unquoteEnv(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// envSafe says whether v can be written in single quotes, which the shell and
// systemd's EnvironmentFile both read the same way.
func envSafe(v string) bool {
	return !strings.ContainsAny(v, "'\n\r\x00")
}

// envHeader opens an env file setup makes.
const envHeader = `# Signari's settings, written by signari setup. signari serve reads them:
#   systemctl enable --now signari       (when the installer made the unit)
#   set -a; . %s; set +a; signari serve
# SIGNARI_DSN holds the engine's database password: keep this file 0600.
`

// render is the file with want's settings in it: every line kept as it was,
// and each setting it lacks added at the end, so a re-run fills what is
// missing and changes nothing else. added names those it added. A setting the
// file holds with another value is the caller's to refuse before this.
func (e envFile) render(want map[string]string) (content string, added []string, err error) {
	return e.renderKeys(envOrder, fmt.Sprintf(envHeader, e.path), want)
}

// renderKeys is render for a file of other settings, in order, opened by
// header when it is new: the compose project's .env (setupcompose.go).
func (e envFile) renderKeys(order []string, header string, want map[string]string) (content string, added []string, err error) {
	var b strings.Builder
	if e.exists {
		for _, l := range e.lines {
			b.WriteString(l + "\n")
		}
	} else {
		b.WriteString(header)
	}
	for _, k := range order {
		v, ok := want[k]
		if !ok {
			continue
		}
		if have, ok := e.values[k]; ok {
			if have != v {
				return "", nil, fmt.Errorf("%s says %s=%s, and setup would write %s", e.path, k, have, v)
			}
			continue
		}
		if !envSafe(v) {
			return "", nil, fmt.Errorf("%s=%s cannot be written to an env file: it holds a quote or a line break", k, v)
		}
		fmt.Fprintf(&b, "%s='%s'\n", k, v)
		added = append(added, k)
	}
	return b.String(), added, nil
}
