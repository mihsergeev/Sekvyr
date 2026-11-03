// Command journal-gateway is the append-only mTLS boundary to the trial S3
// backend. AWS credentials exist here only; this is not a transparent S3 proxy.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
func run(args []string) error {
	flags := flag.NewFlagSet("journal-gateway", flag.ContinueOnError)
	configFile := flags.String("config", "", "read-only trial gateway configuration")
	certificate := flags.String("tls-cert", "", "HTTPS certificate PEM")
	private := flags.String("tls-key", "", "HTTPS private key PEM")
	caFile := flags.String("client-ca", "", "independent client certificate CA PEM")
	listen := flags.String("listen", ":8443", "mTLS listen address")
	allow := flags.Bool("allow-trial-canonical-ledger", false, "authorize trial storage without production WORM claims")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !*allow {
		return errors.New("journal gateway: TrialProfileNotAuthorized")
	}
	raw, err := read(*configFile, 256<<10)
	if err != nil {
		return err
	}
	cfg, err := journal.DecodeGatewayConfig(raw)
	if err != nil {
		return err
	}
	ca, err := read(*caFile, 64<<10)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("journal gateway: ClientCAInvalid")
	}
	if *certificate == "" || *private == "" {
		return errors.New("journal gateway: TLSRequired")
	}
	startup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	storage, err := journal.NewS3Storage(startup, cfg.S3)
	cancel()
	if err != nil {
		return err
	}
	gateway, err := journal.NewGateway(storage, cfg.Registrations, cfg.Clients)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: gateway, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, ErrorLog: log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServeTLS(*certificate, *private); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("journal gateway: HTTPSStopped")
	}
	return nil
}
func read(path string, max int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("journal gateway: FileUnavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(raw) < 1 || len(raw) > max {
		return nil, errors.New("journal gateway: FileInvalid")
	}
	return raw, nil
}
