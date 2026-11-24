package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// `signari setup -compose <dir>` writes a compose project that runs Signari
// and its own PostgreSQL in containers: compose.yaml, its settings in .env,
// the engine's env file and the root key, each written only where it is
// missing, so a second run keeps the passwords the database was made with.
// It is the way to run Signari where there is no release binary, macOS and
// ARM among them, from an image built from the release's source.
//
// The project's setup service is this same command without -compose, run
// against the project's PostgreSQL on every start: it makes the database,
// gives signari_engine the env file's password, applies the migrations and
// prints the first administrator's link, and skips whatever is done.

//go:embed setupfiles/compose.yaml
var composeYAML string

// composeMarker opens the compose.yaml setup writes.
const composeMarker = "# Written by signari setup -compose."

// composeTrustedProxies are where a proxy on the host reaches the engine
// from: Docker's default address pools, through which a published port is
// forwarded.
const composeTrustedProxies = "172.16.0.0/12,192.168.0.0/16"

// composeKeys are the project's settings in .env, in order.
var composeKeys = []string{"COMPOSE_PROJECT_NAME", "ENGINE_IMAGE", "PROJECT_DIR", "PUBLISH", "RUN_AS",
	"FIRST_EMAIL", "POSTGRES_PASSWORD"}

const composeEnvHeader = `# The compose project's settings, written by signari setup -compose, which
# fills a missing one and changes none. POSTGRES_PASSWORD is the database
# superuser's, used by the setup service alone: keep this file 0600.
`

// composeProject says whether dir holds a compose project setup wrote.
func composeProject(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "compose.yaml")) // #nosec G304 G703 -- beside the env file the operator names
	return err == nil && strings.HasPrefix(string(b), composeMarker)
}

// composeImage is the image a project runs unless -image says: the one
// install.sh --docker builds for this release.
func composeImage() string {
	if version != "" {
		return "signari:" + version
	}
	return "signari:local"
}

// composeFixed are setup's flags that name what a compose project fixes.
var composeFixed = []string{"superuser-dsn", "superuser-dsn-file", "database", "root-key-file", "env-file",
	"tls-cert", "tls-key"}

// composeSetup is `signari setup -compose`.
func composeSetup(ctx context.Context, stdout, out io.Writer, h setupHost, f setupFlags) error {
	dir, err := filepath.Abs(f.compose)
	if err != nil {
		return err
	}
	if strings.ContainsAny(dir, ": \"'$\n") {
		return usageError{fmt.Errorf("-compose %s: a project directory with a colon, a space, a quote or a $ "+
			"cannot be mounted as compose writes it", dir)}
	}
	for _, name := range composeFixed {
		if f.given[name] {
			return usageError{fmt.Errorf("-compose fixes what -%s would name: the project's own PostgreSQL, its "+
				"database signari, and the files in %s", name, dir)}
		}
	}
	if f.tls == tlsFiles {
		return usageError{errors.New("-compose takes -tls proxy or -tls none: the project publishes plain HTTP " +
			"on -addr, for a proxy in front to end TLS")}
	}
	r := &setupRun{f: f, h: h, out: out, manifest: filepath.Join(dir, manifestName)}
	if f.prompts(h) {
		r.ask = newTermPrompter(out)
	}
	if r.f.logFile == "" {
		r.f.logFile = filepath.Join(dir, setupLogName)
	}
	if !f.dryRun {
		l, err := r.openLog()
		if err != nil {
			return err
		}
		r.log = l
		defer r.log.close()
	}
	err = r.composeRun(ctx, dir)
	r.recordManifest()
	r.logResult(err)
	if f.json {
		line, jerr := json.Marshal(r.result(err))
		if jerr != nil {
			return jerr
		}
		fmt.Fprintln(stdout, string(line))
	}
	return err
}

func (r *setupRun) composeRun(ctx context.Context, dir string) error {
	fmt.Fprintf(r.out, "\n  signari setup -compose, for %s on %s/%s\n", dir, r.h.goos, r.h.goarch)
	dotEnv, err := readEnvFile(filepath.Join(dir, ".env"))
	if err != nil {
		return err
	}
	envPath := filepath.Join(dir, envFileName)
	if r.prior, err = readEnvFile(envPath); err != nil {
		return err
	}
	a := setupAnswers{compose: dir, envFile: envPath, rootKeyFile: filepath.Join(dir, rootKeyFileName),
		database: "signari", from: map[string]string{}}
	settle := func(name, given, before, def string, valid func(string) error, q *setupQuestion) (string, error) {
		switch {
		case given != "":
			if before != "" && before != given {
				return "", usageError{fmt.Errorf("-%s is %s, and the project in %s says %s. Setup never changes "+
					"what it settled: edit the file yourself, or give -compose another directory", name, given,
					dir, before)}
			}
			a.from[name] = "flag"
			return given, valid(given)
		case before != "":
			a.from[name] = "env file"
			return before, valid(before)
		case q != nil && r.ask != nil:
			a.from[name] = "asked"
			v, err := r.ask.ask(q.label, q.hint, def, valid)
			return strings.TrimSpace(v), err
		case def != "":
			a.from[name] = "default"
			return def, nil
		}
		return "", fmt.Errorf("give -%s, the first administrator's address, which setup cannot work out", name)
	}
	if a.addr, err = settle("addr", r.f.addr, dotEnv.values["PUBLISH"], "127.0.0.1:8080", validAddr, nil); err != nil {
		return err
	}
	q := setupQuestions["issuer"]
	if a.issuer, err = settle("issuer", r.f.issuer, r.prior.values["SIGNARI_ISSUER"], suggestIssuer(r.h, a.addr),
		validIssuer, &q); err != nil {
		return err
	}
	q = setupQuestions["email"]
	email := strings.ToLower(strings.TrimSpace(r.f.email))
	if a.email, err = settle("email", email, dotEnv.values["FIRST_EMAIL"], "", validEmail, &q); err != nil {
		if !r.f.dryRun || dotEnv.values["FIRST_EMAIL"] != "" || email != "" {
			return err
		}
		r.missing = append(r.missing, "email")
	}
	a.email = strings.ToLower(a.email)
	image, err := settle("image", r.f.image, dotEnv.values["ENGINE_IMAGE"], composeImage(), validImage, nil)
	if err != nil {
		return err
	}
	if err := resolveTLS(r.f, r.h, r.prior, r.ask, &a); err != nil {
		return err
	}
	if a.tls == tlsFiles {
		return usageError{errors.New("-compose takes -tls proxy or -tls none")}
	}
	r.a = a
	r.composeName = cmp.Or(dotEnv.values["COMPOSE_PROJECT_NAME"], "signari")
	r.keyExists, err = rootKeyFileState(a.rootKeyFile)
	if err != nil {
		return err
	}

	// The secrets are made once: a second run reads them back.
	pgPassword := cmp.Or(dotEnv.values["POSTGRES_PASSWORD"], rand.Text())
	r.engineDSN = cmp.Or(r.prior.values["SIGNARI_DSN"],
		"postgres://"+engineRole+":"+rand.Text()+"@postgres:5432/signari?sslmode=disable")
	_, r.password, _, _, _ = dsnParts(r.engineDSN)
	r.log.secret(pgPassword)
	project := map[string]string{"COMPOSE_PROJECT_NAME": r.composeName, "ENGINE_IMAGE": image,
		"PROJECT_DIR": dir, "PUBLISH": a.addr, "RUN_AS": fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"FIRST_EMAIL": a.email, "POSTGRES_PASSWORD": pgPassword}
	if a.email == "" {
		delete(project, "FIRST_EMAIL")
	}
	dotContent, dotAdded, err := dotEnv.renderKeys(composeKeys, composeEnvHeader, project)
	if err != nil {
		return fmt.Errorf("%w: give -compose another directory for another project", err)
	}
	engineEnv := r.envValues()
	engineEnv["SIGNARI_ADDR"] = "0.0.0.0:8080" // inside its container; the host's is PUBLISH
	composeFile := filepath.Join(dir, "compose.yaml")
	r.steps = []setupStep{
		{name: "compose-file", what: "write " + composeFile, skip: when(composeProject(dir),
			"it is there, and a later run leaves it as it is"), run: func(context.Context) error {
			return r.writeCreated(composeFile, []byte(composeYAML))
		}},
		{name: "compose-env", what: "write " + dotEnv.path + ", the project's settings, with a generated " +
			"password for its PostgreSQL superuser", skip: when(len(dotAdded) == 0, "it holds every setting"),
			run: func(context.Context) error {
				if dotEnv.exists {
					return writeFileAtomic(dotEnv.path, []byte(dotContent), false, r.h.euid, &r.madeDirs)
				}
				return r.writeCreated(dotEnv.path, []byte(dotContent))
			}},
		{name: "root-key", what: "generate the root key into " + a.rootKeyFile, run: r.writeRootKey,
			skip: when(r.keyExists, "it is there")},
		{name: "env-file", what: "write the engine's env file " + envPath + ", with a generated password for " +
			engineRole, run: func(ctx context.Context) error {
			content, _, err := r.prior.renderKeys(envOrder, fmt.Sprintf(envHeader, envPath), engineEnv)
			if err != nil {
				return err
			}
			if r.prior.exists {
				return writeFileAtomic(envPath, []byte(content), false, r.h.euid, &r.madeDirs)
			}
			if err := writeFileAtomic(envPath, []byte(content), true, r.h.euid, &r.madeDirs); err != nil {
				return err
			}
			r.createdEnv = true
			return nil
		}, skip: when(r.envHolds(engineEnv), "it holds every setting")},
	}
	for i := range r.steps {
		r.steps[i].state = "planned"
	}
	r.logf("settled the compose project %s: the address %s, the first administrator %s, published on %s, "+
		"the image %s", dir, a.issuer, cmp.Or(a.email, "-"), a.addr, image)

	w := r.out
	fmt.Fprintf(w, "\n  Plan\n")
	fmt.Fprintf(w, "    %-16s %s\n", "address", a.issuer)
	fmt.Fprintf(w, "    %-16s %s\n", "first admin", cmp.Or(a.email, "(give -email)"))
	fmt.Fprintf(w, "    %-16s %s, on 8080 in its container\n", "published on", a.addr)
	fmt.Fprintf(w, "    %-16s %s\n", "TLS", a.tlsLine())
	fmt.Fprintf(w, "    %-16s %s\n", "image", image)
	fmt.Fprintf(w, "    %-16s PostgreSQL 17, in the volume %s_pgdata\n", "database", r.composeName)
	fmt.Fprintf(w, "\n  Steps\n")
	n := 0
	for _, s := range r.steps {
		if s.skip != "" {
			fmt.Fprintf(w, "    -  %s: already done, %s\n", s.what, s.skip)
			continue
		}
		n++
		fmt.Fprintf(w, "    %d. %s\n", n, s.what)
	}
	if r.f.dryRun {
		if len(r.missing) > 0 {
			fmt.Fprintf(w, "\n  A real run also needs: -%s\n", strings.Join(r.missing, ", -"))
		}
		fmt.Fprintln(w, "\n  Dry run: nothing was changed.")
		return nil
	}
	if n > 0 && r.ask != nil {
		ok, err := r.ask.confirm("Write the compose project as planned above?",
			"Nothing has changed yet, and every step is safe to run again.", true)
		if err != nil {
			return err
		}
		if !ok {
			return errCancelled
		}
	}
	fmt.Fprintln(w)
	if err := r.execute(ctx); err != nil {
		r.undo()
		return err
	}
	pad := "                 "
	fmt.Fprintf(w, "\n  The compose project is written.\n\n")
	fmt.Fprintf(w, "  %-14s cd %s && docker compose up --detach --wait\n", "Start it", dir)
	fmt.Fprintf(w, "  %-14s docker compose logs setup, once it has started, prints the\n%sone-time link "+
		"for %s.\n", "First admin", pad, cmp.Or(a.email, "the first administrator"))
	fmt.Fprintf(w, "  %-14s %s\n", "Address", a.issuer)
	fmt.Fprintf(w, "  %-14s %s\n%sCopy it off this machine now: without it the signing keys and every\n"+
		"%ssealed secret are lost, whatever backup of the volume you hold.\n", "Root key", a.rootKeyFile, pad, pad)
	if r.f.printRootKey {
		if key := r.rootKey(); key != "" {
			fmt.Fprintf(w, "%sThe key, as -print-root-key asked: %s\n", pad, key)
		}
	}
	fmt.Fprintf(w, "  %-14s signari setup -check -compose %s\n", "Check it", dir)
	if a.tls == tlsProxy {
		fmt.Fprintf(w, "  %-14s a proxy on this machine ends it: have it send %s to\n%s%s. Signari believes "+
			"X-Forwarded-For from %s.\n", "TLS", a.issuer, pad, a.addr, a.trustedProxies)
	}
	fmt.Fprintf(w, "  %-14s signari uninstall -compose %s, which keeps the database's\n%svolume and the root "+
		"key unless given -drop-database and -delete-root-key.\n\n", "Remove it", dir, pad)
	return nil
}

// envHolds says whether the env file holds every one of want.
func (r *setupRun) envHolds(want map[string]string) bool {
	if !r.prior.exists {
		return false
	}
	for k := range want {
		if _, ok := r.prior.values[k]; !ok {
			return false
		}
	}
	return true
}

// writeCreated makes a file that is not there, for a failure to take back.
func (r *setupRun) writeCreated(path string, data []byte) error {
	if err := writeFileAtomic(path, data, true, r.h.euid, &r.madeDirs); err != nil {
		return err
	}
	r.createdFiles = append(r.createdFiles, path)
	return nil
}

// validImage holds an image reference to what .env and a shell can carry.
func validImage(s string) error {
	if s == "" || strings.ContainsAny(s, " \t'\"$\n") {
		return fmt.Errorf("%q is not an image reference such as signari:v0.2.0", s)
	}
	return nil
}

// composeCheck is `signari setup -check -compose`: the project's files, and
// then, inside the project, the check of what its setup service set up, which
// reaches the project's PostgreSQL where only the project's network can.
func composeCheck(ctx context.Context, stdout, out io.Writer, f setupFlags) error {
	for name := range f.given {
		switch name {
		case "check", "compose", "json", "timeout":
		default:
			return usageError{fmt.Errorf("-check -compose takes -json only, not -%s", name)}
		}
	}
	dir, err := filepath.Abs(f.compose)
	if err != nil {
		return err
	}
	missing := false
	for _, p := range []string{"compose.yaml", ".env", envFileName, rootKeyFileName} {
		path := filepath.Join(dir, p)
		info, err := os.Stat(path)
		switch {
		case err != nil:
			fmt.Fprintf(out, "  [missing] %s: run signari setup -compose %s\n", path, dir)
			missing = true
		case p != "compose.yaml" && info.Mode().Perm()&0o077 != 0:
			fmt.Fprintf(out, "  [missing] %s: its group or others may read it; chmod 600 it\n", path)
			missing = true
		default:
			fmt.Fprintf(out, "  [ok]      %s\n", path)
		}
	}
	if missing {
		if f.json {
			fmt.Fprintln(stdout, `{"complete":false,"error":"the compose project's files are not all there"}`)
		}
		return errIncomplete
	}
	args := []string{"compose", "--project-directory", dir, "run", "--rm", "--no-deps", "-T", "setup", "setup",
		"-check", "-env-file", filepath.Join(dir, envFileName)}
	if f.json {
		args = append(args, "-json")
	}
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- docker, in the project directory the operator named
	cmd.Stdout, cmd.Stderr = stdout, out
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exit) && exit.ExitCode() == 2:
		return errIncomplete
	}
	return fmt.Errorf("checking inside the project, with docker compose run: %w; is it started?", err)
}

// healthcheck is `signari healthcheck`: GET /readyz from the engine on this
// machine, for a container's healthcheck in an image with no shell and no
// curl. It reaches the port serve listens on, over HTTPS when serve has a
// certificate, trusting that certificate alone.
func healthcheck(ctx context.Context, w io.Writer, addr, tlsCert string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return usageError{fmt.Errorf("-addr %q: %w", addr, err)}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	transport := &http.Transport{Proxy: nil}
	scheme := "http"
	if tlsCert != "" {
		raw, err := os.ReadFile(tlsCert) // #nosec G304 G703 -- serve's own certificate, as SIGNARI_TLS_CERT names it
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return fmt.Errorf("%s holds no certificate", tlsCert)
		}
		name := ""
		if block, _ := pem.Decode(raw); block != nil {
			if leaf, err := x509.ParseCertificate(block.Bytes); err == nil && len(leaf.DNSNames) > 0 {
				name = leaf.DNSNames[0]
			}
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}
		scheme = "https"
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Only ever this machine's engine: the host is loopback unless -addr names
	// another of this machine's addresses, and the path is fixed.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(host, port)+"/readyz", nil) // #nosec G704 -- serve's own listen address, a fixed path
	if err != nil {
		return err
	}
	resp, err := client.Do(req) // #nosec G704 -- the request above, redirects refused
	if err != nil {
		return fmt.Errorf("the engine at %s did not answer: %w", net.JoinHostPort(host, port), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the engine at %s is not ready: /readyz answered %s", net.JoinHostPort(host, port), resp.Status)
	}
	fmt.Fprintln(w, "ready")
	return nil
}
