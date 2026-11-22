// Command signari-operator keeps SignariConfig resources applied to a Signari
// engine through its Admin API (6.23, operator/README.md).
package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"signari.dev/operator/api/v1alpha1"
	"signari.dev/operator/internal/admin"
	"signari.dev/operator/internal/controller"
)

func main() {
	metricsAddr := flag.String("metrics-addr", "0", "where to serve metrics; 0 for nowhere")
	probeAddr := flag.String("probe-addr", ":8081", "where to serve /healthz and /readyz")
	leaderElect := flag.Bool("leader-elect", false, "run one active replica of several, chosen by a Lease")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("signari-operator")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		log.Error(err, "registering the core types")
		os.Exit(1)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		log.Error(err, "registering SignariConfig")
		os.Exit(1)
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// Secrets read from the API server each time, never cached: a cache would
		// list and watch every Secret in the cluster, and hold them all.
		Client:                 client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		Metrics:                metricsserver.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress: *probeAddr,
		LeaderElection:         *leaderElect,
		LeaderElectionID:       "signari-operator.signari.dev",
	})
	if err != nil {
		log.Error(err, "starting the manager")
		os.Exit(1)
	}
	if err := (&controller.Reconciler{Client: mgr.GetClient(), NewAdmin: admin.New}).SetupWithManager(mgr); err != nil {
		log.Error(err, "starting the SignariConfig controller")
		os.Exit(1)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "adding /healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "adding /readyz")
		os.Exit(1)
	}
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "running")
		os.Exit(1)
	}
}
