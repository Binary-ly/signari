package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"signari.dev/engine/internal/clientip"
)

// How setup answers the one question an https:// issuer raises: who ends TLS.
// The engine has no ACME client. It serves HTTPS itself from a certificate and
// key it is given (SIGNARI_TLS_CERT, SIGNARI_TLS_KEY), loaded when serve
// starts and not again while it runs (serve: http.Server.ServeTLS with the two
// files), or it serves plain HTTP on loopback to a proxy in front that ends
// TLS and says who the client was (SIGNARI_TRUSTED_PROXIES,
// SIGNARI_CLIENT_IP_SOURCE).
//
// Setup looks before it asks: a proxy already listening on 443 or 80 means a
// proxy in front, and a Let's Encrypt certificate for the issuer's host means
// those files. Their private key is root's alone, so it is copied to where
// the service can read it, with a certbot hook that copies a renewal and
// restarts the service, since serve would not read a new one by itself.

const (
	tlsProxy = "proxy"
	tlsFiles = "files"
	tlsNone  = "none"
)

func validTLSMode(s string) error {
	switch s {
	case tlsProxy, tlsFiles, tlsNone:
		return nil
	}
	return fmt.Errorf("%q is not proxy, files or none", s)
}

// validTrustedProxies holds the list to what serve would accept, read with
// the header setup has it read.
func validTrustedProxies(s string) error {
	if !envSafe(s) {
		return fmt.Errorf("%q holds a quote or a line break", s)
	}
	_, err := clientip.Parse(string(clientip.XForwardedFor), s)
	return err
}

// defaultTrustedProxies is a proxy on this machine, which reaches the engine
// on loopback.
const defaultTrustedProxies = "127.0.0.1,::1"

// issuerHost is the issuer's host name, and the port it implies.
func issuerHost(issuer string) (host, port string) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", ""
	}
	port = u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	return u.Hostname(), port
}

// listener is something listening on a TCP port of this machine.
type listener struct {
	port    int
	process string
}

// webListeners reads what listens on 443 and 80 from /proc/net/tcp and tcp6,
// and which process holds each socket from /proc/<pid>/fd, which only root can
// read for other users' processes; nothing is asked of the network.
func webListeners(proc string) []listener {
	inodes := map[string]int{}
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join(proc, "net", name)) // #nosec G304 G703 -- /proc, or a test's copy
		if err == nil {
			for inode, port := range listeningOn(string(b), 443, 80) {
				inodes[inode] = port
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	names := socketOwners(proc, inodes)
	var out []listener
	for inode, port := range inodes {
		out = append(out, listener{port: port, process: names[inode]})
	}
	// 443 first: a proxy there is the one ending TLS.
	for i := range out {
		if out[i].port == 443 {
			out[0], out[i] = out[i], out[0]
		}
	}
	return out
}

// listeningOn reads a /proc/net/tcp table: the inode of each socket in the
// LISTEN state (0A) on one of ports.
func listeningOn(table string, ports ...int) map[string]int {
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	out := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		_, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || !want[int(p)] {
			continue
		}
		out[f[9]] = int(p)
	}
	return out
}

// socketOwners names the process holding each socket inode, where it can see.
func socketOwners(proc string, inodes map[string]int) map[string]string {
	out := map[string]string{}
	pids, _ := os.ReadDir(proc)
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid.Name()); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(proc, pid.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(proc, pid.Name(), "fd", fd.Name()))
			inode, ok := strings.CutPrefix(link, "socket:[")
			if err != nil || !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if _, wanted := inodes[inode]; wanted && out[inode] == "" {
				comm, _ := os.ReadFile(filepath.Join(proc, pid.Name(), "comm")) // #nosec G304 G703 -- /proc
				out[inode] = strings.TrimSpace(string(comm))
			}
		}
	}
	return out
}

// letsEncryptFor is the certificate and key certbot keeps for host, when there
// are both: under live/<host>, links to the newest of each.
func letsEncryptFor(live, host string) (cert, key string, ok bool) {
	if host == "" || strings.ContainsAny(host, `/\`) {
		return "", "", false
	}
	cert, key = filepath.Join(live, host, "fullchain.pem"), filepath.Join(live, host, "privkey.pem")
	if _, err := os.Stat(cert); err != nil {
		return "", "", false
	}
	if _, err := os.Lstat(key); err != nil {
		return "", "", false
	}
	return cert, key, true
}

// certFacts is what setup read of a certificate.
type certFacts struct {
	notAfter time.Time
	names    []string
}

// tlsExpiryWarning is how close to expiry a certificate is said to be.
const tlsExpiryWarning = 14 * 24 * time.Hour

// checkTLSFiles holds a certificate and key to what serve needs of them for
// host: PEM that parses, a key that is the certificate's, a name that covers
// host, and a validity period that holds now. A certificate that expires
// within 14 days is let through with a warning.
func checkTLSFiles(cert, key, host string, now time.Time) (certFacts, string, error) {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return certFacts{}, "", fmt.Errorf("%s and %s do not make a certificate and its key: %w", cert, key, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return certFacts{}, "", fmt.Errorf("%s: %w", cert, err)
	}
	facts := certFacts{notAfter: leaf.NotAfter, names: leaf.DNSNames}
	for _, ip := range leaf.IPAddresses {
		facts.names = append(facts.names, ip.String())
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return facts, "", fmt.Errorf("%s is for %s, not %s, so every browser would refuse it", cert,
			strings.Join(facts.names, ", "), host)
	}
	switch {
	case now.After(leaf.NotAfter):
		return facts, "", fmt.Errorf("%s expired on %s: renew it, then run setup again", cert,
			leaf.NotAfter.UTC().Format("2 Jan 2006"))
	case now.Before(leaf.NotBefore):
		return facts, "", fmt.Errorf("%s is not valid until %s: check this machine's clock", cert,
			leaf.NotBefore.UTC().Format("2 Jan 2006 15:04 UTC"))
	case leaf.NotAfter.Sub(now) < tlsExpiryWarning:
		return facts, fmt.Sprintf("%s expires on %s, in under 14 days: renew it soon", cert,
			leaf.NotAfter.UTC().Format("2 Jan 2006")), nil
	}
	return facts, "", nil
}

// readableBy says whether uid, in group gid, may read path by its mode.
func readableBy(path string, uid, gid int) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	owner, group, ok := dirOwner(path)
	perm := info.Mode().Perm()
	switch {
	case !ok || uid == 0:
		return true
	case owner == uid:
		return perm&0o400 != 0
	case group == gid:
		return perm&0o040 != 0
	}
	return perm&0o004 != 0
}

//go:embed setupfiles/certbot-deploy-hook.sh
var certbotHookTemplate string

var certbotHook = template.Must(template.New("hook").Parse(certbotHookTemplate))

// certbotHookText is the deploy hook for the certificate in lineage, copying
// it into dir for the service's uid and gid.
func certbotHookText(lineage, dir string, uid, gid int) (string, error) {
	for _, s := range []string{lineage, dir} {
		if strings.ContainsAny(s, "\"'`$\\\n ") {
			return "", fmt.Errorf("%q cannot be written into a shell script as it is", s)
		}
	}
	var b bytes.Buffer
	err := certbotHook.Execute(&b, map[string]any{"Lineage": lineage, "Dir": dir, "UID": uid, "GID": gid})
	return b.String(), err
}

// bindDropIn is the systemd drop-in that lets the service listen below port
// 1024.
const bindDropIn = unitPath + ".d/signari-setup-bind.conf"

// bindDropInText adds the one capability a port below 1024 needs to the unit
// the installer wrote, which has none.
const bindDropInText = `# Written by signari setup: Signari serves HTTPS itself on a port below 1024,
# which needs this capability and no other.
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
`

// sameFile says whether path holds exactly data.
func sameFile(path string, data []byte) bool {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a file setup writes
	return err == nil && bytes.Equal(b, data)
}

// lowPort says whether addr's port is one only a privileged process may bind.
func lowPort(addr string) bool {
	_, p, err := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return err == nil && n > 0 && n < 1024
}

// detectTLS is what this machine suggests for issuer: a proxy in front when
// something listens on 443 or 80, else Signari's own HTTPS when Let's Encrypt
// has a certificate for the issuer's host, else a proxy in front, as nothing
// says otherwise. cert and key are that certificate's whenever there is one.
func (h setupHost) detectTLS(issuer string) (mode, why, cert, key string) {
	host, _ := issuerHost(issuer)
	le := false
	if h.leLive != "" {
		cert, key, le = letsEncryptFor(h.leLive, host)
	}
	if h.listeners != nil {
		for _, l := range h.listeners() {
			if l.process == "signari" {
				continue // an earlier run's, serving HTTPS itself
			}
			return tlsProxy, fmt.Sprintf("%s listens on port %d", cmp.Or(l.process, "a process"), l.port), cert, key
		}
	}
	if le {
		return tlsFiles, "Let's Encrypt has a certificate for " + host, cert, key
	}
	return tlsProxy, "", "", ""
}

var tlsQuestion = setupQuestion{"Who ends TLS: proxy, files, or none for now",
	"proxy: one in front of Signari; files: Signari serves HTTPS itself"}

// resolveTLS settles who ends TLS, as resolveAnswers settles the rest: a flag,
// the env file, the person at the terminal, then the default. Only an
// https:// issuer asks it; http://localhost has nobody to end TLS for.
func resolveTLS(f setupFlags, h setupHost, prior envFile, ask prompter, a *setupAnswers) error {
	names := []string{"tls", "tls-cert", "tls-key", "trusted-proxies"}
	flags := map[string]string{"tls": f.tls, "tls-cert": f.tlsCert, "tls-key": f.tlsKey,
		"trusted-proxies": f.trustedProxies}
	if u, err := url.Parse(a.issuer); err != nil || u.Scheme != "https" {
		for _, name := range names {
			if flags[name] != "" {
				return usageError{fmt.Errorf("-%s is for an https:// address, and %s is not one", name, a.issuer)}
			}
		}
		a.tls, a.from["tls"] = tlsNone, "default"
		return nil
	}
	// A certificate or a proxy list says which, when -tls does not.
	implied := ""
	switch {
	case flags["tls-cert"] != "" || flags["tls-key"] != "":
		implied = tlsFiles
	case flags["trusted-proxies"] != "":
		implied = tlsProxy
	}
	if implied != "" && flags["tls"] != "" && flags["tls"] != implied {
		return usageError{fmt.Errorf("-tls %s takes neither -tls-cert nor -tls-key nor -trusted-proxies "+
			"but its own: -tls-cert and -tls-key are for files, -trusted-proxies for proxy", flags["tls"])}
	}
	flags["tls"] = cmp.Or(flags["tls"], implied)
	priors := map[string]string{"tls-cert": prior.values["SIGNARI_TLS_CERT"],
		"tls-key": prior.values["SIGNARI_TLS_KEY"], "trusted-proxies": prior.values["SIGNARI_TRUSTED_PROXIES"]}
	switch {
	case priors["tls-cert"] != "":
		priors["tls"] = tlsFiles
	case priors["trusted-proxies"] != "":
		priors["tls"] = tlsProxy
	case prior.values["SIGNARI_ISSUER"] != "":
		// An earlier run settled the issuer and wrote neither: nothing ends
		// TLS here that setup knows of, and setup does not change that.
		priors["tls"] = tlsNone
	}
	set := map[string]*string{"tls": &a.tls, "tls-cert": &a.tlsCert, "tls-key": &a.tlsKey,
		"trusted-proxies": &a.trustedProxies}
	valid := map[string]func(string) error{"tls": validTLSMode, "tls-cert": validFilePath,
		"tls-key": validFilePath, "trusted-proxies": validTrustedProxies}
	detected, why, _, _ := h.detectTLS(a.issuer)
	defer func() {
		// What was found, when it is what was chosen, for the plan and summary.
		if a.tls == detected {
			a.tlsWhy = why
		}
	}()
	for _, name := range names {
		switch {
		case name != "tls" && (a.tls == tlsFiles) != (name != "trusted-proxies"):
			continue // the other mode's
		case name != "tls" && a.tls == tlsNone:
			continue
		}
		given, before := flags[name], priors[name]
		if given != "" && (name == "tls-cert" || name == "tls-key") {
			if abs, err := filepath.Abs(given); err == nil {
				given = abs
			}
		}
		switch {
		case given != "":
			if before != "" && before != given {
				return usageError{fmt.Errorf("-%s is %s, and %s, which an earlier run wrote, says %s. Setup "+
					"never changes what it settled: edit that file yourself", name, given, prior.path, before)}
			}
			if err := valid[name](given); err != nil {
				return usageError{fmt.Errorf("-%s: %w", name, err)}
			}
			*set[name], a.from[name] = given, "flag"
		case before != "":
			*set[name], a.from[name] = before, "env file"
		default:
			def := setupDefault(name, h, *a)
			switch {
			case ask != nil && name == "tls":
				hint := tlsQuestion.hint
				if why != "" {
					hint = "Found here: " + why + "."
				}
				v, err := ask.ask(tlsQuestion.label, hint, def, validTLSMode)
				if err != nil {
					return err
				}
				*set[name], a.from[name] = strings.TrimSpace(v), "asked"
			case ask != nil && name != "trusted-proxies":
				label := map[string]string{"tls-cert": "The certificate chain file (PEM)",
					"tls-key": "Its private key file (PEM)"}[name]
				v, err := ask.ask(label, "Signari reads it when it starts, as SIGNARI_TLS_CERT and _KEY do.",
					def, validFilePath)
				if err != nil {
					return err
				}
				*set[name], a.from[name] = strings.TrimSpace(v), "asked"
			case def != "":
				*set[name], a.from[name] = def, "default"
			default:
				return fmt.Errorf("give -tls-cert and -tls-key, the certificate and key Signari serves "+
					"HTTPS with: there is no Let's Encrypt certificate for %s here", a.issuer)
			}
		}
	}
	if a.tls == tlsFiles {
		host, _ := issuerHost(a.issuer)
		if dir := filepath.Join(h.leLive, host); h.leLive != "" && strings.HasPrefix(a.tlsCert, dir+string(filepath.Separator)) {
			a.lineage = dir
		} else if _, _, cert, _ := h.detectTLS(a.issuer); cert != "" &&
			filepath.Dir(a.tlsCert) == filepath.Join(setupConfigDir(h.euid, h.getenv, h.home), "tls") {
			// The copies an earlier run made, which renewals still come from.
			a.lineage = filepath.Dir(cert)
		}
	}
	return nil
}

// tlsCopyDir is where a Let's Encrypt certificate is copied for the service.
func (r *setupRun) tlsCopyDir() string {
	return filepath.Join(setupConfigDir(r.h.euid, r.h.getenv, r.h.home), "tls")
}

// serviceOwner is the user the service runs as, by the directory the
// installer made for it, and whether there is one other than root.
func (r *setupRun) serviceOwner() (uid, gid int, ok bool) {
	uid, gid, ok = dirOwner(setupConfigDir(r.h.euid, r.h.getenv, r.h.home))
	return uid, gid, ok && uid != 0
}

// inspectTLS reads the certificate and key the engine is to serve, refusing
// what serve could not use, and, for a Let's Encrypt certificate, settles
// the copies the service reads in their place.
func (r *setupRun) inspectTLS() error {
	a := &r.a
	if a.tls != tlsFiles {
		return nil
	}
	if a.lineage != "" && r.h.euid != 0 {
		return fmt.Errorf("the private key Let's Encrypt keeps for %s is root's alone: run setup as root, "+
			"which copies it to %s for the service, or give -tls-cert and -tls-key for files it can read",
			a.issuer, r.tlsCopyDir())
	}
	cert, key := a.tlsCert, a.tlsKey
	if a.lineage != "" {
		cert, key = filepath.Join(a.lineage, "fullchain.pem"), filepath.Join(a.lineage, "privkey.pem")
		if filepath.Dir(a.tlsCert) != r.tlsCopyDir() {
			a.tlsCert, a.tlsKey = filepath.Join(r.tlsCopyDir(), "fullchain.pem"), filepath.Join(r.tlsCopyDir(), "privkey.pem")
		}
	}
	host, _ := issuerHost(a.issuer)
	facts, warning, err := checkTLSFiles(cert, key, host, r.h.now())
	if err != nil {
		return err
	}
	r.cert, r.certWarning = facts, warning
	if uid, gid, ok := r.serviceOwner(); ok && r.h.unitInstalled && a.lineage == "" {
		for _, p := range []string{cert, key} {
			if !readableBy(p, uid, gid) {
				return fmt.Errorf("the Signari service cannot read %s, which serve needs when it starts: "+
					"chown it to the service's user, or copy it to %s, owned by that user", p, r.tlsCopyDir())
			}
		}
	}
	if lowPort(a.addr) && r.h.euid != 0 && !r.h.unitInstalled {
		r.certWarning = cmp.Or(r.certWarning, fmt.Sprintf("serve needs CAP_NET_BIND_SERVICE, or root, to "+
			"listen on %s", a.addr))
	}
	return nil
}

// tlsSteps are the steps serving HTTPS itself needs: the copies of a Let's
// Encrypt certificate and the hook that keeps them current, and, for a port
// below 1024 under the installer's unit, the capability to bind it.
func (r *setupRun) tlsSteps() []setupStep {
	a := r.a
	if a.tls != tlsFiles {
		return nil
	}
	var steps []setupStep
	if a.lineage != "" {
		host, _ := issuerHost(a.issuer)
		hook, _ := r.hookText()
		steps = append(steps,
			setupStep{name: "tls-files", what: fmt.Sprintf("copy the certificate for %s from %s to %s, "+
				"for the service to read", host, a.lineage, r.tlsCopyDir()), run: r.copyTLS,
				skip: when(sameFile(a.tlsCert, readOrNil(filepath.Join(a.lineage, "fullchain.pem"))) &&
					sameFile(a.tlsKey, readOrNil(filepath.Join(a.lineage, "privkey.pem"))), "the copies are current")},
			setupStep{name: "certbot-hook", what: "install the certbot hook " + r.hookPath() + ", which copies " +
				"a renewed certificate and restarts the service", run: r.writeHook,
				skip: when(hook != "" && sameFile(r.hookPath(), []byte(hook)), "it is there")})
	}
	if r.h.euid == 0 && r.h.unitInstalled && lowPort(a.addr) {
		steps = append(steps, setupStep{name: "unit-bind", what: "let the Signari service listen on " + a.addr +
			", below 1024, by " + bindDropIn, run: r.writeBindDropIn,
			skip: when(sameFile(bindDropIn, []byte(bindDropInText)), "that file says so")})
	}
	return steps
}

func readOrNil(path string) []byte {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a certificate setup copies
	if err != nil {
		return nil
	}
	return b
}

func (r *setupRun) hookPath() string {
	return filepath.Join(filepath.Dir(r.h.leLive), "renewal-hooks", "deploy", "signari")
}

func (r *setupRun) hookText() (string, error) {
	uid, gid, ok := r.serviceOwner()
	if !ok {
		uid, gid = 0, 0
	}
	return certbotHookText(r.a.lineage, r.tlsCopyDir(), uid, gid)
}

// copyTLS copies the certificate and key, which certbot keeps root's alone,
// to where the service reads them, owned by it.
func (r *setupRun) copyTLS(_ context.Context) error {
	dir := r.tlsCopyDir()
	if err := mkdirAllRecorded(dir, setupDirMode(r.h.euid), &r.madeDirs); err != nil {
		return err
	}
	// The copies take the owner of their directory (writeFileAtomic), so the
	// directory is the service's first.
	if uid, gid, ok := r.serviceOwner(); ok {
		if owner, _, _ := dirOwner(dir); owner != uid {
			if err := os.Chown(dir, uid, gid); err != nil {
				return fmt.Errorf("giving %s to the service's user: %w", dir, err)
			}
		}
	}
	for src, dst := range map[string]string{"fullchain.pem": r.a.tlsCert, "privkey.pem": r.a.tlsKey} {
		data, err := os.ReadFile(filepath.Join(r.a.lineage, src)) // #nosec G304 G703 -- certbot's own files
		if err != nil {
			return err
		}
		_, statErr := os.Stat(dst)
		if err := writeFileAtomic(dst, data, false, r.h.euid, &r.madeDirs); err != nil {
			return err
		}
		if statErr != nil {
			r.createdFiles = append(r.createdFiles, dst)
		}
	}
	return nil
}

// writeHook installs the certbot deploy hook, executable by root alone.
func (r *setupRun) writeHook(_ context.Context) error {
	text, err := r.hookText()
	if err != nil {
		return err
	}
	path := r.hookPath()
	_, statErr := os.Stat(path)
	if err := writeFileAtomic(path, []byte(text), false, r.h.euid, &r.madeDirs); err != nil {
		return err
	}
	if statErr != nil {
		r.createdFiles = append(r.createdFiles, path)
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- certbot runs only a hook it may execute; root's alone
}

// writeBindDropIn gives the installer's unit the one capability a port below
// 1024 needs, and has systemd read it.
func (r *setupRun) writeBindDropIn(ctx context.Context) error {
	_, statErr := os.Stat(bindDropIn)
	if err := writeFileAtomic(bindDropIn, []byte(bindDropInText), false, r.h.euid, &r.madeDirs); err != nil {
		return err
	}
	if statErr != nil {
		r.createdFiles = append(r.createdFiles, bindDropIn)
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// tlsEnv are the settings serve reads for the TLS chosen.
func (a setupAnswers) tlsEnv() map[string]string {
	switch a.tls {
	case tlsFiles:
		return map[string]string{"SIGNARI_TLS_CERT": a.tlsCert, "SIGNARI_TLS_KEY": a.tlsKey}
	case tlsProxy:
		return map[string]string{"SIGNARI_TRUSTED_PROXIES": a.trustedProxies,
			"SIGNARI_CLIENT_IP_SOURCE": string(clientip.XForwardedFor)}
	}
	return nil
}

// tlsLine is the plan's line for the TLS chosen.
func (a setupAnswers) tlsLine() string {
	switch a.tls {
	case tlsProxy:
		return "a proxy in front ends it" + map[bool]string{true: ": " + a.tlsWhy}[a.tlsWhy != ""]
	case tlsFiles:
		if a.lineage != "" {
			return "Signari serves HTTPS itself, with Let's Encrypt's certificate"
		}
		return "Signari serves HTTPS itself, with " + a.tlsCert
	}
	if strings.HasPrefix(a.issuer, "https://") {
		return "none yet"
	}
	return "none: " + a.issuer + " is for this machine alone"
}

// printTLS is the summary's line for the TLS chosen: what it is, and what is
// still to do.
func (r *setupRun) printTLS(w io.Writer, pad string) {
	a := r.a
	host, _ := issuerHost(a.issuer)
	switch a.tls {
	case tlsProxy:
		found := "point a proxy that ends TLS for " + host + " at it"
		if a.tlsWhy != "" {
			found = a.tlsWhy + ": have it send " + host + " to " + a.addr
		}
		fmt.Fprintf(w, "  %-14s a proxy in front ends it. Signari listens on %s in plain\n%sHTTP; %s.\n"+
			"%sIt believes X-Forwarded-For from %s alone (SIGNARI_TRUSTED_PROXIES).\n",
			"TLS", a.addr, pad, found, pad, a.trustedProxies)
	case tlsFiles:
		fmt.Fprintf(w, "  %-14s Signari serves HTTPS itself on %s, with %s,\n%svalid until %s.\n", "TLS", a.addr,
			a.tlsCert, pad, r.cert.notAfter.UTC().Format("2 Jan 2006"))
		if a.lineage != "" {
			fmt.Fprintf(w, "%sCopied from %s; the certbot hook copies each renewal\n%sand restarts the service, "+
				"which reads its certificate only when it starts.\n", pad, a.lineage, pad)
		} else {
			fmt.Fprintf(w, "%sserve reads it only when it starts: restart the service after renewing it.\n", pad)
		}
		if r.certWarning != "" {
			fmt.Fprintf(w, "%sWarning: %s.\n", pad, r.certWarning)
		}
	default:
		if strings.HasPrefix(a.issuer, "https://") {
			fmt.Fprintf(w, "  %-14s none yet. Signari listens on %s in plain HTTP, which no browser\n%s"+
				"uses for %s: add SIGNARI_TLS_CERT and SIGNARI_TLS_KEY to the env file,\n%sor a proxy in front "+
				"and SIGNARI_TRUSTED_PROXIES (docs/configuration.md).\n", "TLS", a.addr, pad, a.issuer, pad)
		}
	}
}
