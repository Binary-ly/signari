package main

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The log every run of `signari setup` appends to, for the person reading it
// after a run went wrong: what ran, with which flags, and each step's outcome
// and how long it took. It holds no secret. Nothing secret is written to it,
// and every line is also scrubbed of each secret the run knows (the engine's
// password, the superuser's, the root key, the link's token), so an error
// message that carried one would not carry it here. A dry run and -check write
// nothing, as they change nothing.

const setupLogName = "setup.log"

// setupLogDir is where setup's log is kept unless -log-file says otherwise:
// /var/log/signari for root, else the user's state directory, the XDG one when
// it is set.
func setupLogDir(euid int, getenv func(string) string, home string) string {
	if euid == 0 {
		return "/var/log/signari"
	}
	if x := getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, "signari")
	}
	return filepath.Join(home, ".local", "state", "signari")
}

// redacted stands in for a secret wherever one would have been written.
const redacted = "…"

// setupLog is one run's handle on the log. A nil one writes nothing, so a run
// with no log calls it the same.
type setupLog struct {
	path    string
	f       *os.File
	now     func() time.Time
	secrets []string
}

// openSetupLog opens path to append to, making its directory, and keeps the
// file 0600. A symbolic link there is refused rather than followed.
func openSetupLog(path string, euid int, now func() time.Time) (*setupLog, error) {
	if err := mkdirAllRecorded(filepath.Dir(path), setupDirMode(euid), nil); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link, and setup appends only to a file of its own", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 G703 -- the operator names the file
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &setupLog{path: path, f: f, now: now}, nil
}

// secret adds values never to be written, longest first, so a secret that
// holds another is replaced whole.
func (l *setupLog) secret(values ...string) {
	if l == nil {
		return
	}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(l.secrets, v) {
			l.secrets = append(l.secrets, v)
		}
	}
	slices.SortFunc(l.secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
}

func (l *setupLog) scrub(s string) string {
	for _, v := range l.secrets {
		s = strings.ReplaceAll(s, v, redacted)
	}
	return strings.ReplaceAll(s, "\n", " / ")
}

// line appends one line, stamped with the time.
func (l *setupLog) line(format string, args ...any) {
	if l == nil {
		return
	}
	stamp := l.now().UTC().Format("2006-01-02T15:04:05.000Z")
	_, _ = fmt.Fprintf(l.f, "%s %s\n", stamp, l.scrub(fmt.Sprintf(format, args...)))
}

// header opens a run's record: when, which release, who and where, and the
// flags it was given, a password in a URL among them replaced.
func (l *setupLog) header(command string, f setupFlags) {
	if l == nil {
		return
	}
	release := version
	if release == "" {
		release = "unreleased"
	}
	l.line("==== signari %s, %s, by %s, pid %d", command, release, cliOperator(), os.Getpid())
	names := make([]string, 0, len(f.args))
	for name := range f.args {
		names = append(names, name)
	}
	slices.Sort(names)
	var given []string
	for _, name := range names {
		v := f.args[name]
		switch {
		case v == "true":
			given = append(given, "-"+name)
		default:
			given = append(given, "-"+name+" "+redactURL(v))
		}
	}
	l.line("flags %s", cmp.Or(strings.Join(given, " "), "(none)"))
}

// step records a step's outcome: its state, how long it took, when it began
// and what it did or found.
func (l *setupLog) step(name, state string, start, end time.Time, detail string) {
	if l == nil {
		return
	}
	l.line("%-5s %-12s %8s  started %s: %s", state, name, end.Sub(start).Round(time.Millisecond),
		start.UTC().Format("15:04:05.000"), detail)
}

func (l *setupLog) close() {
	if l != nil {
		_ = l.f.Close()
	}
}

// tail is the last n lines of the log, for a failed run to print.
func (l *setupLog) tail(n int) []string {
	if l == nil {
		return nil
	}
	f, err := os.Open(l.path) // #nosec G304 G703 -- the log this run wrote
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines
}

// redactURL is a value with the password of any URL in it replaced.
func redactURL(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" {
		return v
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "REDACTED")
	}
	q := u.Query()
	if q.Has("password") {
		q.Set("password", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return strings.ReplaceAll(u.String(), "REDACTED", redacted)
}

// linkForLog is the first administrator's link with its token replaced: the
// token is the credential, and the rest says which deployment it was for.
func linkForLog(link string) string {
	before, after, ok := strings.Cut(link, "invite=")
	if !ok {
		return link
	}
	if _, rest, more := strings.Cut(after, "&"); more {
		return before + "invite=" + redacted + "&" + rest
	}
	return before + "invite=" + redacted
}

// linkToken is the token in the link, for the log to scrub.
func linkToken(link string) string {
	_, after, ok := strings.Cut(link, "invite=")
	if !ok {
		return ""
	}
	token, _, _ := strings.Cut(after, "&")
	return token
}

// openLog opens the run's log: -log-file, or the default, which a run goes on
// without when it cannot be opened, saying so. The secrets known before the
// run begins are the superuser's: PGPASSWORD, and the file -superuser-dsn-file
// names.
func (r *setupRun) openLog() (*setupLog, error) {
	path := r.f.logFile
	if path == "" {
		path = filepath.Join(setupLogDir(r.h.euid, r.h.getenv, r.h.home), setupLogName)
	} else if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	l, err := openSetupLog(path, r.h.euid, r.h.now)
	if err != nil {
		if r.f.logFile != "" {
			return nil, fmt.Errorf("-log-file: %w", err)
		}
		fmt.Fprintf(r.out, "\n  setup keeps no log this run: %v\n", err)
		return nil, nil
	}
	l.secret(r.h.getenv("PGPASSWORD"))
	if r.f.superuserDSNFile != "" {
		if b, err := os.ReadFile(r.f.superuserDSNFile); err == nil { // #nosec G304 G703 -- the operator names the file
			l.secret(string(b))
		}
	}
	l.header("setup", r.f)
	return l, nil
}

// secrets are the secrets this run knows by now, for the log to scrub.
func (r *setupRun) secrets() []string {
	s := []string{r.password, r.rootKeyText, linkToken(r.link)}
	if r.su != nil {
		s = append(s, r.su.cfg.Password)
	}
	return s
}

// logf writes a line to the log, scrubbed of every secret known so far.
func (r *setupRun) logf(format string, args ...any) {
	r.log.secret(r.secrets()...)
	r.log.line(format, args...)
}

// logStep records a step's outcome, its detail as the plan and the steps
// printed it.
func (r *setupRun) logStep(s setupStep, start time.Time, err error) {
	detail := s.what
	switch s.state {
	case "skipped":
		detail += ": " + s.skip
	case "waiting":
		detail += ": " + s.wait
	case "failed":
		detail += ": " + err.Error()
	case "done":
		if s.name == "first-admin" && r.link != "" {
			detail += fmt.Sprintf("; the link %s is open until %s", linkForLog(r.link),
				r.linkExpires.UTC().Format(time.RFC3339))
		}
	}
	state := map[string]string{"skipped": "skip", "waiting": "wait", "failed": "fail"}[s.state]
	r.log.secret(r.secrets()...)
	r.log.step(s.name, cmp.Or(state, s.state), start, r.h.now(), detail)
}

// logResult ends the run's record. A failed run prints the log's last lines,
// and where it is, under its error.
func (r *setupRun) logResult(err error) {
	if r.log == nil {
		return
	}
	switch {
	case err == nil:
		r.logf("result ok")
	case errors.Is(err, errCancelled):
		r.logf("result cancelled, before anything was changed")
	default:
		r.logf("result failed: %v", err)
		fmt.Fprintf(r.out, "\n  The last lines of the log, %s:\n", r.log.path)
		for _, line := range r.log.tail(15) {
			fmt.Fprintf(r.out, "    %s\n", line)
		}
	}
}
