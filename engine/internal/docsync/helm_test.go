package docsync

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// helmTemplate renders the chart with these --set values, or skips the test
// when helm is not installed.
func helmTemplate(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH")
	}
	args := []string{"template", "t", filepath.Join(repoRoot(t), "deploy", "helm", "signari"),
		"--set", "issuer=https://id.example.test", "--set", "secret.dsn=postgres://x",
		"--set", "secret.rootKey=eQ=="}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command(helm, args...).CombinedOutput()
	return string(out), err
}

// The chart installs (2.09): the migration Job runs the engine's own
// entrypoint, its Secret exists before it does, readiness asks /readyz, and
// the image is a pinned tag. It could not install at all: `command:` replaced
// the entrypoint, and the Secret was created after every pre-install hook.
func TestTheHelmChartCanInstall(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("the default chart does not render: %v\n%s", err, out)
	}
	if strings.Contains(out, "command:") {
		t.Error("a container sets command:, which replaces the image's /signari entrypoint")
	}
	for _, want := range []string{`args: ["migrate", "all"]`, `args: ["serve"]`, `path: /readyz`, `args: ["verify"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("the chart lacks %s", want)
		}
	}
	if strings.Contains(out, ":latest\"") {
		t.Error("the image is :latest; a moving tag runs different engines in one release")
	}
	weight := func(kind, name string) int {
		t.Helper()
		m := regexp.MustCompile(`(?s)kind: ` + kind + `\nmetadata:\n  name: t-signari` + name +
			`\n.*?"helm.sh/hook-weight": "(-?\d+)"`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("the %s t-signari%s is not a hook with a weight", kind, name)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	secret, migrate := weight("Secret", "-secrets"), weight("Job", "-migrate")
	if secret >= migrate {
		t.Errorf("the Secret's hook weight %d is not below the migration Job's %d, so the Job may start first",
			secret, migrate)
	}
	// `serve` refuses to start with no instance for its issuer, and an install made
	// none, so a fresh one migrated and never became ready (found on kind).
	if instance := weight("Job", "-instance"); instance <= migrate || instance >= 0 {
		t.Errorf("the instance Job's hook weight %d is not after the migration's %d and before the engine",
			instance, migrate)
	}
	if !strings.Contains(out, `args: ["instance", "create", "-issuer", "https://id.example.test"]`) {
		t.Error("no hook makes the instance the engine serves")
	}
}

// The pod outlives its own shutdown (2.10): the kubelet waits longer than the
// engine drains plus lets requests finish, whatever the operator sets. The
// chart set no grace period, so the engine's two settings and the kubelet's
// SIGKILL agreed only while both kept their defaults.
func TestTheHelmChartOutlivesItsShutdown(t *testing.T) {
	seconds := func(out, pattern string) int {
		t.Helper()
		m := regexp.MustCompile(pattern).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("the chart does not render %s", pattern)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	for _, sets := range [][]string{nil, {"shutdown.timeoutSeconds=60", "shutdown.drainSeconds=15"}} {
		out, err := helmTemplate(t, sets...)
		if err != nil {
			t.Fatalf("%v does not render: %v\n%s", sets, err, out)
		}
		grace := seconds(out, `terminationGracePeriodSeconds: (\d+)`)
		drain := seconds(out, `name: SIGNARI_SHUTDOWN_DRAIN\n\s+value: "(\d+)s"`)
		timeout := seconds(out, `name: SIGNARI_SHUTDOWN_TIMEOUT\n\s+value: "(\d+)s"`)
		if grace <= drain+timeout {
			t.Errorf("%v: the grace period %ds does not outlast a %ds drain and %ds of requests, so the kubelet kills requests mid-flight",
				sets, grace, drain, timeout)
		}
	}
	if out, err := helmTemplate(t, "extraEnv.SIGNARI_SHUTDOWN_TIMEOUT=90s"); err == nil || !strings.Contains(out, "not extraEnv") {
		t.Errorf("a shutdown timeout set past the grace period through extraEnv rendered (%v)", err)
	}
}

// Metrics, the ServiceMonitor, the NetworkPolicy and scheduled commands
// render when asked for (3.24), and the two configurations the engine or
// Prometheus would refuse are refused at render time.
func TestTheHelmChartRendersItsOptions(t *testing.T) {
	out, err := helmTemplate(t, "metrics.enabled=true", "metrics.serviceMonitor.enabled=true",
		"networkPolicy.enabled=true", "networkPolicy.metricsFrom[0].namespaceSelector.matchLabels.name=monitoring",
		"cronJobs[0].name=audit-verify", "cronJobs[0].schedule=0 3 * * *", "cronJobs[0].args={audit,verify}",
		"adminApi.enabled=true", "adminApi.insecure=true")
	if err != nil {
		t.Fatalf("the chart with every option does not render: %v\n%s", err, out)
	}
	for _, want := range []string{"kind: ServiceMonitor", "kind: NetworkPolicy", "kind: CronJob",
		"name: SIGNARI_METRICS_ADDR", "name: SIGNARI_ADMIN_INSECURE", "port: metrics", `args: ["audit","verify"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("with every option the chart lacks %s", want)
		}
	}
	for _, c := range []struct {
		sets []string
		want string
	}{
		{[]string{"adminApi.enabled=true"}, "needs tls.certSecretName"},
		{[]string{"metrics.serviceMonitor.enabled=true"}, "needs metrics.enabled"},
	} {
		if out, err := helmTemplate(t, c.sets...); err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%v rendered (%v); want it refused with %q", c.sets, err, c.want)
		}
	}
}

// The console renders beside the engine (3.25) as signari_admin and no wider role, by
// a pod name of its own: on the engine's labels it would sit behind the engine's
// Service, budget and policy, whose selectors cannot change on an upgrade. Its
// migration follows the engine's, and runs behind the image's own entrypoint.
func TestTheHelmChartRendersTheConsole(t *testing.T) {
	console := []string{"console.enabled=true", "console.url=https://console.example.test",
		"console.database.host=db", "console.secret.appKey=base64:eQ==", "console.secret.dbPassword=p",
		"adminApi.enabled=true", "adminApi.insecure=true"}
	out, err := helmTemplate(t, console...)
	if err != nil {
		t.Fatalf("the chart with the console does not render: %v\n%s", err, out)
	}
	for _, want := range []string{"DB_USERNAME: signari_admin", "app.kubernetes.io/name: signari-console",
		`args: ["php", "artisan", "migrate", "--force"]`, `SIGNARI_ADMIN_URL: "http://t-signari-admin:8090"`} {
		if !strings.Contains(out, want) {
			t.Errorf("with the console the chart lacks %s", want)
		}
	}
	if strings.Contains(out, "command:") {
		t.Error("a console container sets command:, which replaces the image's entrypoint")
	}
	for _, c := range []struct {
		drop string
		want string
	}{
		{"console.url=https://console.example.test", "needs console.url"},
		{"console.database.host=db", "needs console.database.host"},
		{"console.secret.dbPassword=p", "needs console.secret.appKey and console.secret.dbPassword"},
		{"adminApi.enabled=true", "writes through the Admin API"},
	} {
		var sets []string
		for _, s := range console {
			if s != c.drop {
				sets = append(sets, s)
			}
		}
		if out, err := helmTemplate(t, sets...); err == nil || !strings.Contains(out, c.want) {
			t.Errorf("without %s the console rendered (%v); want %q", c.drop, err, c.want)
		}
	}
}
