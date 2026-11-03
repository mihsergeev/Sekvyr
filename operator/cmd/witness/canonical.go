package main

import (
	"context"
	"crypto/ed25519"
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
	"github.com/mihsergeev/Sekvyr/operator/internal/transport"
	"github.com/mihsergeev/Sekvyr/operator/internal/witnessservice"
)

func runCanonical(args []string) error {
	flags := flag.NewFlagSet("witness canonical", flag.ContinueOnError)
	configFile := flags.String("config", "", "independent canonical witness JSON")
	allow := flags.Bool("allow-trial-canonical-ledger", false, "authorize non-production trial canonical journal")
	registrationFile := flags.String("registration", "", "offline signed full genesis record JSON")
	certFile := flags.String("tls-cert", "", "HTTPS certificate PEM")
	keyFile := flags.String("tls-key", "", "HTTPS private key PEM")
	clientCAFile := flags.String("client-ca", "", "CA for administrative/fencer mTLS clients")
	listen := flags.String("listen", ":8443", "HTTPS listen address")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !*allow {
		return errors.New("witness: TrialProfileNotAuthorized")
	}
	raw, err := read(*configFile, 256<<10)
	if err != nil {
		return err
	}
	cfg, err := witnessservice.DecodeCanonicalConfig(raw)
	if err != nil {
		return err
	}
	ca, err := read(cfg.Gateway.CAFile, 64<<10)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.Gateway.ClientCertFile, cfg.Gateway.ClientKeyFile)
	if err != nil {
		return errors.New("witness: GatewayIdentityInvalid")
	}
	storage, err := journal.NewAPIStorageClient(cfg.Gateway.Origin, ca, cert)
	if err != nil {
		return err
	}
	defer storage.Close()
	registrations := make([]journal.Registration, 0, len(cfg.Registrations))
	for _, entry := range cfg.Registrations {
		registrations = append(registrations, entry.Journal)
	}
	ledger, err := journal.New(storage, registrations, nil)
	if err != nil {
		return err
	}
	if args[0] == "canonical-init" {
		recordRaw, err := read(*registrationFile, journal.MaxRecordBytes)
		if err != nil {
			return err
		}
		record, err := journal.DecodeRecord(recordRaw)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		state, err := ledger.InitializeCAS(ctx, record.LogID, recordRaw)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, state.GenesisHash)
		return nil
	}
	var keys []ed25519.PrivateKey
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, path := range cfg.SigningKeyFiles {
		key, err := readSigningKey(path)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}
	startup, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	service, err := witnessservice.NewCanonical(startup, ledger, cfg, keys, func(state journal.CurrentState, registration witnessservice.CanonicalRegistration) (witnessservice.StagedFetcher, error) {
		var ca []byte
		if registration.PanelCAFile != "" {
			var err error
			ca, err = read(registration.PanelCAFile, 64<<10)
			if err != nil {
				return nil, err
			}
		}
		return transport.NewStagedFetcher(state.PanelOrigin, ca, registration.StagingTokenFile, []string{state.Scope.ViewID})
	})
	cancel()
	if err != nil {
		return err
	}
	defer service.Close()
	clientCA, err := read(*clientCAFile, 64<<10)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return errors.New("witness: ClientCAInvalid")
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("witness: TLSRequired")
	}
	server := &http.Server{Addr: *listen, Handler: service, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}, ErrorLog: log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServeTLS(*certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("witness: HTTPSStopped")
	}
	return nil
}
