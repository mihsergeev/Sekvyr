// Command fencer runs the explicit HA trial grant, barrier and admission service.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/fencing"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("fencer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFile := flags.String("config", "/etc/sekvyr/fencer/config.json", "read-only administrative fencer configuration")
	journalFile := flags.String("journal-config", "/etc/sekvyr/journal/client.json", "read-only mTLS journal client configuration")
	keyFile := flags.String("signing-key", "/etc/sekvyr/fencer-key/key.pem", "read-only Ed25519 PKCS8 PEM")
	certFile := flags.String("tls-cert", "/etc/sekvyr/fencer-tls/tls.crt", "HTTPS certificate")
	tlsKeyFile := flags.String("tls-key", "/etc/sekvyr/fencer-tls/tls.key", "HTTPS private key")
	listen := flags.String("listen", ":9443", "HTTPS listen address")
	trial := flags.Bool("allow-trial-fencing", false, "explicitly authorize trial-only fencing profile")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*trial {
		return errors.New("fencer: TrialArgumentsInvalid")
	}
	raw, err := read(*configFile, 256<<10)
	if err != nil {
		return err
	}
	config, err := fencing.DecodeConfig(raw)
	if err != nil {
		return errors.New("fencer: ConfigInvalid")
	}
	raw, err = read(*journalFile, 256<<10)
	if err != nil {
		return err
	}
	journalConfig, err := journal.DecodeClientConfig(raw)
	if err != nil {
		return errors.New("fencer: JournalConfigInvalid")
	}
	ledger, storageClient, err := journal.NewClient(journalConfig)
	if err != nil {
		return errors.New("fencer: JournalClientUnavailable")
	}
	defer storageClient.Close()
	raw, err = read(*keyFile, 16<<10)
	if err != nil {
		return err
	}
	defer clear(raw)
	block, restPEM := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(restPEM) != 0 {
		return errors.New("fencer: SigningKeyInvalid")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("fencer: SigningKeyInvalid")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return errors.New("fencer: SigningKeyInvalid")
	}
	defer clear(key)
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("fencer: KubernetesUnavailable")
	}
	kubeConfig.QPS = 20
	kubeConfig.Burst = 30
	kubeConfig.Timeout = 10 * time.Second
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return errors.New("fencer: KubernetesUnavailable")
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = coordinationv1.AddToScheme(scheme)
	direct, err := client.New(kubeConfig, client.Options{Scheme: scheme})
	if err != nil {
		return errors.New("fencer: KubernetesUnavailable")
	}
	service := &fencing.Service{Config: config, Journal: ledger, Reader: direct, Writer: direct, SigningKey: key,
		Auth: fencing.TokenAuthenticator{Client: kubeClient, Reader: direct}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	initial, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = service.Validate(initial)
	cancel()
	if err != nil {
		return bootstrapFailure(err)
	}
	semaphore := make(chan struct{}, 8)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			service.ServeHTTP(w, r)
			return
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			service.ServeHTTP(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"reason":"FencerBusy"}`))
		}
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServeTLS(*certFile, *tlsKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("fencer: HTTPSStopped")
	}
	return nil
}

// Expose only the service's fixed public reason, never Kubernetes errors,
// endpoint URLs, response bodies, file paths or credential material.
func bootstrapFailure(err error) error { return fmt.Errorf("fencer: %s", fencing.Reason(err)) }

func read(path string, max int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("fencer: FileUnavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("fencer: FileUnavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(max+1)))
	if err != nil || len(raw) == 0 || len(raw) > max {
		return nil, errors.New("fencer: FileBounds")
	}
	return raw, nil
}
