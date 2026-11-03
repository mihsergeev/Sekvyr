package journal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

type GatewayClient struct {
	CommonName string   `json:"common_name"`
	Logs       []string `json:"logs"`
	WriteKinds []string `json:"write_kinds"`
}
type GatewayConfig struct {
	Format        string          `json:"format"`
	S3            S3Config        `json:"s3"`
	Registrations []Registration  `json:"registrations"`
	Clients       []GatewayClient `json:"clients"`
}
type Gateway struct {
	Storage Storage
	Ledger  *Ledger
	Clients map[string]GatewayClient
	slots   chan struct{}
}
type streamMeta struct {
	Format         string `json:"format"`
	Nonce          string `json:"nonce"`
	Count          int    `json:"count"`
	LastRecordHash string `json:"last_record_hash"`
}
type streamSlot struct {
	Sequence string           `json:"sequence"`
	Receipt  RetentionReceipt `json:"receipt"`
	Record   json.RawMessage  `json:"record"`
}

func DecodeGatewayConfig(raw []byte) (GatewayConfig, error) {
	var c GatewayConfig
	if DecodeStrict(raw, &c, 256<<10) != nil || c.Format != "sekvyr-journal-gateway-config-v1" || len(c.Clients) < 1 || len(c.Clients) > 64 {
		return c, Failure("ConfigInvalid")
	}
	return c, nil
}
func NewGateway(storage Storage, registrations []Registration, clients []GatewayClient) (*Gateway, error) {
	ledger, err := New(storage, registrations, nil)
	if err != nil {
		return nil, err
	}
	g := &Gateway{Storage: storage, Ledger: ledger, Clients: map[string]GatewayClient{}, slots: make(chan struct{}, 4)}
	for _, client := range clients {
		if client.CommonName == "" || len(client.CommonName) > 256 || len(client.Logs) < 1 || len(client.Logs) > 64 {
			return nil, Failure("ConfigInvalid")
		}
		if _, exists := g.Clients[client.CommonName]; exists {
			return nil, Failure("ConfigInvalid")
		}
		for _, log := range client.Logs {
			if _, err = ledger.registration(log); err != nil {
				return nil, err
			}
		}
		for _, kind := range client.WriteKinds {
			if kind != "genesis" && kind != "snapshot" && kind != "transition" && kind != "fence-grant" && kind != "fence-activation" {
				return nil, Failure("ConfigInvalid")
			}
		}
		g.Clients[client.CommonName] = client
	}
	return g, nil
}
func includes(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func writeError(w http.ResponseWriter, err error) {
	reason := Reason(err)
	code := http.StatusServiceUnavailable
	switch reason {
	case "CASConflict", "GrantCASConflict":
		code = 409
	case "AuthenticationDenied", "StorageDenied":
		code = 403
	case "LogUnknown", "SlotMissing", "RecordUnknown":
		code = 404
	case "RequestInvalid", "RecordInvalid", "TransitionInvalid", "GrantInvalid", "ActivationInvalid", "GenesisInvalid", "GenesisMismatch", "AuthorityEpochInvalid", "EnrollmentInvalid", "EnvelopeInvalid", "ActivationSnapshotRequired", "AuthorityTransitionRequired":
		code = 400
	case "JournalBusy":
		code = 429
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason})
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if g == nil || g.Ledger == nil || g.slots == nil {
		writeError(w, Failure("JournalUnavailable"))
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		writeError(w, Failure("AuthenticationDenied"))
		return
	}
	identity := r.TLS.PeerCertificates[0].Subject.CommonName
	principal, ok := g.Clients[identity]
	if !ok {
		writeError(w, Failure("AuthenticationDenied"))
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || len(parts) < 6 || parts[1] != "v1" || parts[2] != "storage" || parts[3] != "logs" || !validUUID(parts[4]) || !includes(principal.Logs, parts[4]) {
		writeError(w, Failure("AuthenticationDenied"))
		return
	}
	log := parts[4]
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		writeError(w, Failure("JournalBusy"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if r.Method == http.MethodGet && len(parts) == 6 && parts[5] == "journal" {
		g.stream(ctx, w, r, log)
		return
	}
	if r.Method != http.MethodPut || len(parts) != 7 || parts[5] != "slots" || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/json" {
		writeError(w, Failure("RequestInvalid"))
		return
	}
	sequence, err := e2e2.Counter(parts[6], true)
	if err != nil || sequence >= MaxRecords {
		writeError(w, Failure("RequestInvalid"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRecordBytes))
	if err != nil {
		writeError(w, Failure("RecordInvalid"))
		return
	}
	record, err := DecodeRecord(raw)
	if err != nil || record.LogID != log || record.JournalSequence != parts[6] || !includes(principal.WriteKinds, record.Kind) {
		writeError(w, Failure("AuthenticationDenied"))
		return
	}
	if sequence == 0 {
		if _, err = g.Ledger.InitializeCAS(ctx, log, raw); err != nil {
			writeError(w, err)
			return
		}
	} else {
		current, err := g.Ledger.ReadCurrent(ctx, log, Cursor{})
		if err != nil {
			writeError(w, err)
			return
		}
		next, _ := nextCounter(current.Cursor.JournalSequence)
		encoded, err := EncodeRecord(record)
		if err != nil {
			writeError(w, err)
			return
		}
		if record.PreviousRecordHash != current.Cursor.RecordHash || record.JournalSequence != next {
			slots, readErr := g.Ledger.slots(ctx, log)
			if readErr != nil {
				writeError(w, readErr)
				return
			}
			if sequence >= uint64(len(slots)) || !bytes.Equal(slots[sequence].Raw, encoded) {
				writeError(w, Failure("CASConflict"))
				return
			}
		} else {
			if _, err = Apply(current, record); err != nil {
				writeError(w, err)
				return
			}
			if _, err = g.Storage.PutIfAbsent(ctx, log, sequence, encoded); err != nil {
				if Reason(err) != "CASConflict" && Reason(err) != "StorageUnavailable" {
					writeError(w, err)
					return
				}
				slots, readErr := g.Ledger.slots(ctx, log)
				if readErr != nil || sequence >= uint64(len(slots)) || !bytes.Equal(slots[sequence].Raw, encoded) {
					writeError(w, err)
					return
				}
			}
		}
	}
	slots, err := g.Ledger.slots(ctx, log)
	if err != nil || sequence >= uint64(len(slots)) {
		writeError(w, Failure("StorageUnavailable"))
		return
	}
	receipt := slots[sequence].Receipt
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}
func (g *Gateway) stream(ctx context.Context, w http.ResponseWriter, r *http.Request, log string) {
	nonce := r.Header.Get("X-Sekvyr-Journal-Nonce")
	if _, err := e2e2.DecodeBase64(nonce, 32); err != nil {
		writeError(w, Failure("RequestInvalid"))
		return
	}
	slots, err := g.Storage.ReadAll(ctx, log)
	if err != nil {
		writeError(w, err)
		return
	}
	hash := ZeroHash
	if len(slots) > 0 {
		reg, _ := g.Ledger.registration(log)
		s, err := Replay(reg, slots)
		if err != nil {
			writeError(w, err)
			return
		}
		if _, err = g.Ledger.ReadCurrent(ctx, log, reg.MinimumCursor); err != nil {
			writeError(w, err)
			return
		}
		hash = s.Cursor.RecordHash
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	meta := streamMeta{Format: "sekvyr-journal-stream-begin-v1", Nonce: nonce, Count: len(slots), LastRecordHash: hash}
	if encoder.Encode(meta) != nil {
		return
	}
	for n, slot := range slots {
		if encoder.Encode(streamSlot{Sequence: strconv.Itoa(n), Receipt: slot.Receipt, Record: json.RawMessage(slot.Raw)}) != nil {
			return
		}
	}
	meta.Format = "sekvyr-journal-stream-end-v1"
	_ = encoder.Encode(meta)
}

// APIStorageClient has no AWS credentials. Its only capability is the pinned
// mTLS gateway's bounded online read/conditional slot API.
type APIStorageClient struct {
	origin string
	http   *http.Client
}

func (*APIStorageClient) String() string   { return "journal gateway client [redacted]" }
func (*APIStorageClient) GoString() string { return "journal gateway client [redacted]" }
func NewAPIStorageClient(origin string, ca []byte, cert tls.Certificate) (*APIStorageClient, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(cert.Certificate) == 0 {
		return nil, Failure("StorageConfigInvalid")
	}
	pool := x509.NewCertPool()
	if len(ca) == 0 || len(ca) > 64<<10 || !pool.AppendCertsFromPEM(ca) {
		return nil, Failure("StorageCAInvalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}
	return &APIStorageClient{origin: origin, http: &http.Client{Transport: transport, Timeout: 65 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *APIStorageClient) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *APIStorageClient) ReadAll(ctx context.Context, log string) ([]StoredSlot, error) {
	if c == nil || !validUUID(log) {
		return nil, Failure("LogUnknown")
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, Failure("RandomUnavailable")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/v1/storage/logs/"+log+"/journal", nil)
	if err != nil {
		return nil, Failure("RequestInvalid")
	}
	request.Header.Set("X-Sekvyr-Journal-Nonce", nonce)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, Failure("StorageUnavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, gatewayStatus(response.StatusCode)
	}
	reader := bufio.NewReaderSize(io.LimitReader(response.Body, MaxReplayBytes+(MaxRecords*4096)+1), 64<<10)
	line := func(max int) ([]byte, error) {
		var out []byte
		for {
			chunk, prefix, err := reader.ReadLine()
			if err != nil {
				return nil, Failure("StorageStreamInvalid")
			}
			if len(chunk) > max-len(out) {
				return nil, Failure("StorageStreamInvalid")
			}
			out = append(out, chunk...)
			if !prefix {
				return out, nil
			}
		}
	}
	raw, err := line(2048)
	if err != nil {
		return nil, err
	}
	var begin streamMeta
	if DecodeStrict(raw, &begin, 2048) != nil || begin.Format != "sekvyr-journal-stream-begin-v1" || begin.Nonce != nonce || begin.Count < 0 || begin.Count > MaxRecords || !validHash(begin.LastRecordHash, true) {
		return nil, Failure("StorageStreamInvalid")
	}
	slots := make([]StoredSlot, 0, begin.Count)
	total := 0
	last := ZeroHash
	for n := 0; n < begin.Count; n++ {
		raw, err = line(MaxRecordBytes + 4096)
		if err != nil {
			return nil, err
		}
		var wire streamSlot
		if DecodeStrict(raw, &wire, MaxRecordBytes+4096) != nil || wire.Sequence != strconv.Itoa(n) || len(wire.Record) < 1 || len(wire.Record) > MaxRecordBytes || len(wire.Record) > MaxReplayBytes-total {
			return nil, Failure("StorageStreamInvalid")
		}
		record, err := DecodeRecord(wire.Record)
		if err != nil {
			return nil, err
		}
		last, err = RecordHash(record)
		if err != nil {
			return nil, err
		}
		total += len(wire.Record)
		slots = append(slots, StoredSlot{Raw: append([]byte(nil), wire.Record...), Receipt: wire.Receipt})
	}
	raw, err = line(2048)
	if err != nil {
		return nil, err
	}
	var end streamMeta
	if DecodeStrict(raw, &end, 2048) != nil || end.Format != "sekvyr-journal-stream-end-v1" || end.Nonce != nonce || end.Count != begin.Count || end.LastRecordHash != begin.LastRecordHash || last != begin.LastRecordHash {
		return nil, Failure("StorageStreamInvalid")
	}
	if extra, err := reader.ReadByte(); err != io.EOF || extra != 0 {
		return nil, Failure("StorageStreamInvalid")
	}
	return slots, nil
}
func gatewayStatus(code int) error {
	switch code {
	case 409:
		return Failure("CASConflict")
	case 403, 401:
		return Failure("StorageDenied")
	case 404:
		return Failure("SlotMissing")
	case 429:
		return Failure("JournalBusy")
	}
	return Failure("StorageUnavailable")
}
func (c *APIStorageClient) PutIfAbsent(ctx context.Context, log string, sequence uint64, raw []byte) (RetentionReceipt, error) {
	if c == nil || !validUUID(log) || sequence >= MaxRecords || len(raw) < 1 || len(raw) > MaxRecordBytes {
		return RetentionReceipt{}, Failure("RecordInvalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.origin+"/v1/storage/logs/"+log+"/slots/"+strconv.FormatUint(sequence, 10), bytes.NewReader(raw))
	if err != nil {
		return RetentionReceipt{}, Failure("RequestInvalid")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-None-Match", "*")
	response, err := c.http.Do(request)
	if err != nil {
		return RetentionReceipt{}, Failure("StorageUnavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return RetentionReceipt{}, gatewayStatus(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var receipt RetentionReceipt
	if err != nil || len(body) > 4096 || DecodeStrict(body, &receipt, 4096) != nil {
		return receipt, Failure("StorageResponseInvalid")
	}
	return receipt, nil
}
