// Command witness runs the development filesystem profile only. Production
// immutable storage, HA, authority rotation and restore workflows are separate.
package main

import (
	"bytes"
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
	"strings"
	"syscall"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/transport"
	"github.com/mihsergeev/Sekvyr/operator/internal/witnessservice"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("witness: CommandRequired")
	}
	if args[0] == "canonical-serve" || args[0] == "canonical-init" {
		return runCanonical(args)
	}
	flags := flag.NewFlagSet("witness", flag.ContinueOnError)
	root := flags.String("ledger-root", "", "independent existing development ledger volume")
	allow := flags.Bool("allow-development-filesystem-ledger", false, "explicitly authorize non-WORM development profile")
	config := flags.String("config", "", "independent runtime configuration JSON")
	key := flags.String("signing-key", "", "read-only unencrypted Ed25519 PKCS8 PEM")
	cert := flags.String("tls-cert", "", "HTTPS certificate PEM")
	tlsKey := flags.String("tls-key", "", "HTTPS private key PEM")
	listen := flags.String("listen", ":8443", "HTTPS listen address")
	registration := flags.String("registration", "", "signed genesis JSON for offline initialization")
	admin := flags.String("admin-public-key", "", "independent base64url Ed25519 administrator public key file")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("witness: ArgumentsInvalid")
	}
	if !*allow {
		return errors.New("witness: DevelopmentProfileNotAuthorized")
	}
	switch args[0] {
	case "init":
		raw, err := read(*registration, 64<<10)
		if err != nil {
			return err
		}
		publicRaw, err := read(*admin, 256)
		if err != nil {
			return err
		}
		public, err := e2e2.DecodeBase64(strings.TrimSpace(string(publicRaw)), 32)
		if err != nil {
			return errors.New("witness: AdminKeyInvalid")
		}
		hash, err := witnessservice.Initialize(*root, raw, public)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, hash)
		return nil
	case "serve":
		raw, err := read(*config, 64<<10)
		if err != nil {
			return err
		}
		cfg, err := witnessservice.DecodeConfig(raw)
		if err != nil {
			return err
		}
		private, err := readSigningKey(*key)
		if err != nil {
			return err
		}
		defer clear(private)
		service, err := witnessservice.New(*root, cfg, private, true, func(genesis witnessservice.GenesisBody, reg witnessservice.Registration) (witnessservice.StagedFetcher, error) {
			var ca []byte
			if reg.PanelCAFile != "" {
				var err error
				ca, err = read(reg.PanelCAFile, 64<<10)
				if err != nil {
					return nil, err
				}
			}
			return transport.NewStagedFetcher(genesis.PanelOrigin, ca, reg.StagingTokenFile, []string{genesis.ViewID})
		})
		if err != nil {
			return err
		}
		// No plaintext listener or runtime registration/delete/reset endpoint.
		if *cert == "" || *tlsKey == "" {
			return errors.New("witness: TLSRequired")
		}
		server := &http.Server{Addr: *listen, Handler: service, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ErrorLog: log.New(io.Discard, "", 0)}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdown)
		}()
		if err = server.ListenAndServeTLS(*cert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("witness: HTTPSStopped")
		}
		return nil
	default:
		return errors.New("witness: CommandInvalid")
	}
}
func read(path string, max int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("witness: FileUnavailable")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("witness: FileUnavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("witness: FileUnavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) == 0 || len(raw) > max {
		return nil, errors.New("witness: FileInvalid")
	}
	return raw, nil
}
func readSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := read(path, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	trim := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trim, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, errors.New("witness: SigningKeyInvalid")
	}
	block, rest := pem.Decode(trim)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("witness: SigningKeyInvalid")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("witness: SigningKeyInvalid")
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("witness: SigningKeyInvalid")
	}
	return private, nil
}
