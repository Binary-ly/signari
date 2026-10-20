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
	weight := func(kind string) int {
		t.Helper()
		m := regexp.MustCompile(`(?s)kind: ` + kind + `\n.*?"helm.sh/hook-weight": "(-?\d+)"`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("the %s is not a hook with a weight", kind)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if s, j := weight("Secret"), weight("Job"); s >= j {
		t.Errorf("the Secret's hook weight %d is not below the migration Job's %d, so the Job may start first", s, j)
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
