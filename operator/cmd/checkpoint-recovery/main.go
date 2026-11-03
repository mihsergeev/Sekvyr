// checkpoint-recovery performs one independently authorized administrative
// recovery. Offline files contain ciphertext only; journal and witness stay live.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	api "github.com/mihsergeev/Sekvyr/operator/api/v1alpha1"
	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/installation"
	"github.com/mihsergeev/Sekvyr/operator/internal/recovery"
	"github.com/mihsergeev/Sekvyr/operator/internal/syncer"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func read(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("RecoveryFileUnavailable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(b) == 0 || len(b) > max {
		return nil, fmt.Errorf("RecoveryFileInvalid")
	}
	return b, nil
}
func main() {
	installationFile := flag.String("installation-file", "", "Independently pinned new bootstrap JSON")
	planFile := flag.String("plan", "", "Independently administrator-signed exact-cursor recovery plan")
	envelopeFile := flag.String("envelope", "", "Encrypted canonical envelope export")
	wrapFile := flag.String("reader-wrap", "", "Signed encrypted reader-key wrap export")
	trial := flag.Bool("allow-trial-canonical-ledger", false, "Authorize trial profile explicitly")
	rollout := flag.Bool("enable-rollout", false, "Honor explicit plan rollout authorization only for changed data")
	flag.Parse()
	if !*trial || flag.NArg() != 0 {
		stop("TrialProfileNotAuthorized")
	}
	cfg, err := installation.LoadFile(*installationFile)
	if err != nil || cfg.HA == nil {
		stop("RecoveryProfileInvalid")
	}
	if *rollout && !cfg.RolloutEnabled {
		stop("RecoveryProfileInvalid")
	}
	plan, err := read(*planFile, recovery.Limit)
	if err != nil {
		stop("RecoveryFileInvalid")
	}
	envelope, err := read(*envelopeFile, e2e2.MaxEnvelopeBytes)
	if err != nil {
		stop("RecoveryFileInvalid")
	}
	wrap, err := read(*wrapFile, e2e2.MaxReaderWrapBytes)
	if err != nil {
		stop("RecoveryFileInvalid")
	}
	kube, err := ctrl.GetConfig()
	if err != nil {
		stop("KubernetesConfigUnavailable")
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	direct, err := client.New(kube, client.Options{Scheme: scheme})
	if err != nil {
		stop("KubernetesClientUnavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := syncer.Runtime{Config: cfg, Reader: direct, Writer: direct, EnableRollout: *rollout}
	if err := r.RecoverFromFiles(ctx, plan, envelope, wrap); err != nil {
		stop(reason(err))
	}
	fmt.Fprintln(os.Stdout, "CheckpointRecoveryComplete")
}
func reason(err error) string {
	if e, ok := err.(*recovery.Error); ok {
		return e.Reason
	}
	return syncer.Reason(err)
}
func stop(reason string) { fmt.Fprintln(os.Stderr, reason); os.Exit(1) }
