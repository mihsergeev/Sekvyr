package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/controller"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func managerOptions(namespace, lease, metrics, probes string) ctrl.Options {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	return ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{
			DefaultNamespaces:           map[string]cache.Config{namespace: {}},
			ReaderFailOnMissingInformer: true,
		},
		Client:                        client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		Metrics:                       metricsserver.Options{BindAddress: metrics},
		HealthProbeBindAddress:        probes,
		LeaderElection:                true,
		LeaderElectionNamespace:       namespace,
		LeaderElectionID:              lease,
		LeaderElectionReleaseOnCancel: true,
	}
}

func main() {
	var installationFile, namespace, serviceAccount, lease, metrics, probes string
	var leaderElect, enableSync, enableRollout bool
	var panelTokenFile string
	var podUID, podName, fencerTokenFile string
	flag.StringVar(&installationFile, "installation-file", "/etc/sekvyr/installation/installation.json", "Administrative bootstrap file")
	flag.StringVar(&namespace, "namespace", "", "Fixed installation namespace")
	flag.StringVar(&serviceAccount, "service-account", "", "Fixed installation ServiceAccount")
	flag.StringVar(&lease, "leader-election-id", "sekvyr-operator-leader", "Precreated namespaced Lease name")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Mandatory leader election")
	flag.BoolVar(&enableSync, "enable-sync", false, "Explicitly enable stage4 E2E2 checkpoint and Secret synchronization")
	flag.BoolVar(&enableRollout, "enable-rollout", false, "Explicitly enable stage5 authorized Deployment rollouts")
	flag.StringVar(&panelTokenFile, "panel-token-file", "/var/run/secrets/sekvyr-panel/token", "Fixed projected panel-audience ServiceAccount token")
	flag.StringVar(&podUID, "pod-uid", os.Getenv("SEKVYR_POD_UID"), "Fixed bound Pod UID for HA fencing")
	flag.StringVar(&podName, "pod-name", os.Getenv("SEKVYR_POD_NAME"), "Fixed Pod name for process leader identity")
	flag.StringVar(&fencerTokenFile, "fencer-token-file", "/var/run/secrets/sekvyr-fencer/token", "Projected fencing-audience ServiceAccount token")
	flag.StringVar(&metrics, "metrics-bind-address", "0", "Stage 2 metrics endpoint must remain disabled")
	flag.StringVar(&probes, "health-probe-bind-address", ":8081", "Process health probes, not source synchronization readiness")
	flag.Parse()
	c, err := installation.LoadFile(installationFile)
	if err != nil {
		stop(installation.Reason(err))
	}
	if namespace != c.Namespace || serviceAccount != c.ServiceAccount || !leaderElect || !installation.ValidName(lease) || metrics != "0" {
		stop("BootstrapMismatch")
	}
	if c.LeaderElectionLeaseName != "" && c.LeaderElectionLeaseName != lease {
		stop("BootstrapMismatch")
	}
	if enableRollout != c.RolloutEnabled || enableRollout && !enableSync {
		stop("BootstrapMismatch")
	}
	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		stop("KubernetesConfigUnavailable")
	}
	options := managerOptions(namespace, lease, metrics, probes)
	processIdentity := ""
	if c.HA != nil {
		if !enableSync || !installation.ValidUUID(podUID) || !installation.ValidName(podName) || fencerTokenFile == "" {
			stop("HAProfileInvalid")
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			stop("ProcessIdentityUnavailable")
		}
		processIdentity = podName + "_" + hex.EncodeToString(nonce)
		clients, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			stop("KubernetesConfigUnavailable")
		}
		lock, err := resourcelock.New(resourcelock.LeasesResourceLock, namespace, lease, clients.CoreV1(), clients.CoordinationV1(), resourcelock.ResourceLockConfig{Identity: processIdentity})
		if err != nil {
			stop("LeaderIdentityUnavailable")
		}
		options.LeaderElectionResourceLockInterface = lock
	}
	manager, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		stop("ManagerUnavailable")
	}
	r := &controller.Reconciler{Client: manager.GetClient(), APIReader: manager.GetAPIReader(), Installation: c, Namespace: namespace, ServiceAccount: serviceAccount}
	if enableSync {
		if len(c.AllowedTargetSecrets) == 0 || panelTokenFile == "" {
			stop("BootstrapMismatch")
		}
		r.Synchronizer = &syncer.Runtime{Config: c, Reader: manager.GetAPIReader(), Writer: manager.GetClient(), TokenFile: panelTokenFile, EnableRollout: enableRollout, PodUID: podUID, LeaseHolderIdentity: processIdentity, FencerTokenFile: fencerTokenFile}
	}
	if err := r.SetupWithManager(manager); err != nil {
		stop("ControllerUnavailable")
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		stop("HealthProbeUnavailable")
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		stop("HealthProbeUnavailable")
	}
	// Synchronization and workload rollout each require their explicit opt-in.
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		stop("ManagerStopped")
	}
}

func stop(reason string) { fmt.Fprintln(os.Stderr, reason); os.Exit(1) }
