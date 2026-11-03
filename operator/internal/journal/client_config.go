package journal

import (
	"crypto/tls"
	"io"
	"os"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

type ClientConfig struct {
	Format         string         `json:"format"`
	Origin         string         `json:"origin"`
	CAFile         string         `json:"ca_file"`
	ClientCertFile string         `json:"client_cert_file"`
	ClientKeyFile  string         `json:"client_key_file"`
	Registrations  []Registration `json:"registrations"`
}

func (ClientConfig) String() string   { return "journal client configuration [redacted]" }
func (ClientConfig) GoString() string { return "journal client configuration [redacted]" }
func DecodeClientConfig(raw []byte) (ClientConfig, error) {
	var c ClientConfig
	if e2e2.DecodeStrict(raw, &c, 256<<10) != nil || c.Format != "sekvyr-journal-client-config-v1" || c.CAFile == "" || c.ClientCertFile == "" || c.ClientKeyFile == "" {
		return c, Failure("ConfigInvalid")
	}
	return c, nil
}
func NewClient(cfg ClientConfig) (*Ledger, *APIStorageClient, error) {
	file, err := os.Open(cfg.CAFile)
	if err != nil {
		return nil, nil, Failure("StorageCAInvalid")
	}
	ca, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	_ = file.Close()
	if err != nil || len(ca) > 64<<10 {
		return nil, nil, Failure("StorageCAInvalid")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, nil, Failure("StorageIdentityInvalid")
	}
	client, err := NewAPIStorageClient(cfg.Origin, ca, cert)
	if err != nil {
		return nil, nil, err
	}
	ledger, err := New(client, cfg.Registrations, nil)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return ledger, client, nil
}
