package witnessservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

type GatewayConnection struct {
	Origin         string `json:"origin"`
	CAFile         string `json:"ca_file"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
}
type CanonicalRegistration struct {
	Journal          journal.Registration `json:"journal"`
	StagingTokenFile string               `json:"staging_token_file"`
	PanelCAFile      string               `json:"panel_ca_file"`
}
type CanonicalConfig struct {
	Format          string                  `json:"format"`
	Gateway         GatewayConnection       `json:"gateway"`
	Registrations   []CanonicalRegistration `json:"registrations"`
	SigningKeyFiles []string                `json:"signing_key_files"`
	Clients         []journal.GatewayClient `json:"clients"`
}
type CanonicalFetcherFactory func(journal.CurrentState, CanonicalRegistration) (StagedFetcher, error)
type CanonicalService struct {
	Ledger   *journal.Ledger
	clients  map[string]journal.GatewayClient
	signing  map[string]ed25519.PrivateKey
	fetchers map[string]StagedFetcher
	slots    chan struct{}
}

func (*CanonicalService) String() string   { return "trial canonical witness service [redacted]" }
func (*CanonicalService) GoString() string { return "trial canonical witness service [redacted]" }
func DecodeCanonicalConfig(raw []byte) (CanonicalConfig, error) {
	var cfg CanonicalConfig
	if journal.DecodeStrict(raw, &cfg, 256<<10) != nil || cfg.Format != "sekvyr-witness-canonical-config-v1" || len(cfg.Registrations) < 1 || len(cfg.Registrations) > 64 || len(cfg.SigningKeyFiles) < 1 || len(cfg.SigningKeyFiles) > 16 || len(cfg.Clients) < 1 || len(cfg.Clients) > 64 {
		return cfg, journal.Failure("ConfigInvalid")
	}
	return cfg, nil
}
func NewCanonical(ctx context.Context, ledger *journal.Ledger, cfg CanonicalConfig, keys []ed25519.PrivateKey, factory CanonicalFetcherFactory) (*CanonicalService, error) {
	if ledger == nil || factory == nil {
		return nil, journal.Failure("ConfigInvalid")
	}
	service := &CanonicalService{Ledger: ledger, clients: map[string]journal.GatewayClient{}, signing: map[string]ed25519.PrivateKey{}, fetchers: map[string]StagedFetcher{}, slots: make(chan struct{}, 4)}
	for _, private := range keys {
		if len(private) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(private[:32]).Equal(private) {
			return nil, journal.Failure("SigningKeyInvalid")
		}
		pub := private.Public().(ed25519.PublicKey)
		if !e2e2.ValidEd25519PublicKey(pub) {
			return nil, journal.Failure("SigningKeyInvalid")
		}
		service.signing[e2e2.KeyID(pub)] = append(ed25519.PrivateKey(nil), private...)
	}
	for _, registration := range cfg.Registrations {
		state, err := ledger.ReadCurrent(ctx, registration.Journal.LogID, journal.Cursor{})
		if err != nil {
			return nil, err
		}
		if _, ok := service.signing[state.Authority.WitnessKey.KeyID]; !ok {
			return nil, journal.Failure("SigningKeyUnavailable")
		}
		fetcher, err := factory(state, registration)
		if err != nil || fetcher == nil {
			return nil, journal.Failure("StagingFetcherInvalid")
		}
		service.fetchers[registration.Journal.LogID] = fetcher
	}
	for _, client := range cfg.Clients {
		if client.CommonName == "" || len(client.CommonName) > 256 || len(client.Logs) < 1 {
			return nil, journal.Failure("ConfigInvalid")
		}
		if _, exists := service.clients[client.CommonName]; exists {
			return nil, journal.Failure("ConfigInvalid")
		}
		for _, log := range client.Logs {
			if _, ok := ledger.Registrations[log]; !ok {
				return nil, journal.Failure("ConfigInvalid")
			}
		}
		service.clients[client.CommonName] = client
	}
	return service, nil
}
func (s *CanonicalService) Close() {
	if s != nil {
		for _, key := range s.signing {
			clear(key)
		}
	}
}
func (s *CanonicalService) Head(ctx context.Context, log string, request HeadRequest) ([]byte, error) {
	if s == nil {
		return nil, journal.Failure("ServiceUnavailable")
	}
	nonce, err := e2e2.DecodeBase64(request.RequestNonce, 32)
	if err != nil || !validCheckpoint(Checkpoint{request.FloorSequence, request.FloorHash}) {
		return nil, journal.Failure("ChallengeInvalid")
	}
	state, err := s.Ledger.ReadCurrent(ctx, log, journal.Cursor{})
	if err != nil {
		return nil, err
	}
	if state.History[request.FloorSequence] != request.FloorHash {
		return nil, journal.Failure("FloorUnknownOrFork")
	}
	private, ok := s.signing[state.Authority.WitnessKey.KeyID]
	if !ok {
		return nil, journal.Failure("SigningKeyUnavailable")
	}
	head := state.Head()
	body := e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: state.Scope, WitnessEpoch: head.WitnessEpoch, Sequence: head.Sequence, EnvelopeHash: head.EnvelopeHash, ReadKeyEpoch: head.ReadKeyEpoch, PublisherPolicyEpoch: head.PublisherPolicyEpoch, RequestNonce: base64.RawURLEncoding.EncodeToString(nonce), WitnessKeyID: state.Authority.WitnessKey.KeyID, FloorSequence: request.FloorSequence, FloorHash: request.FloorHash}
	raw, err := canonical(body, e2e2.MaxHeadProofBytes)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, journal.Failure("Cancelled")
	}
	signature := ed25519.Sign(private, append(e2e2.Domain("sekvyr-e2e2/head/v1"), raw...))
	return canonical(e2e2.HeadProof{Body: body, Signature: base64.RawURLEncoding.EncodeToString(signature)}, e2e2.MaxHeadProofBytes)
}

type CanonicalCommitRequest struct {
	Expected     journal.Cursor `json:"expected"`
	EnvelopeHash string         `json:"envelope_hash"`
}
type FenceGrantRequest struct {
	Expected journal.Cursor           `json:"expected"`
	Grant    journal.SignedFenceGrant `json:"grant"`
}
type FenceActivationRequest struct {
	Expected   journal.Cursor                `json:"expected"`
	Activation journal.SignedFenceActivation `json:"activation"`
}
type AuthorityChallengeRequest struct {
	RequestNonce string         `json:"request_nonce"`
	Floor        journal.Cursor `json:"floor"`
}

func (s *CanonicalService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if s == nil || s.Ledger == nil || s.slots == nil {
		canonicalFailure(w, journal.Failure("ServiceUnavailable"))
		return
	}
	if r.URL.RawPath != "" || r.URL.RawQuery != "" {
		canonicalFailure(w, journal.Failure("RequestInvalid"))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/capabilities" {
		_ = json.NewEncoder(w).Encode(map[string]any{"format": "sekvyr-witness-capabilities-v1", "profile": journal.Profile, "production_ready": false, "ledger": "conditional-canonical-slots-full-version-replay", "authority_rotation": true})
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 || parts[0] != "" || parts[2] != "logs" || !validLog(parts[3]) {
		canonicalFailure(w, journal.Failure("RequestInvalid"))
		return
	}
	log := parts[3]
	operation := parts[4]
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		canonicalFailure(w, journal.Failure("JournalBusy"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if parts[1] == "v1" && r.Method == http.MethodPost && len(parts) == 5 && operation == "head-challenge" {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		if err != nil {
			canonicalFailure(w, journal.Failure("RequestInvalid"))
			return
		}
		request, err := decodeHead(raw)
		if err != nil {
			canonicalFailure(w, journal.Failure("RequestInvalid"))
			return
		}
		proof, err := s.Head(ctx, log, request)
		if err != nil {
			canonicalFailure(w, err)
			return
		}
		_, _ = w.Write(proof)
		return
	}
	if parts[1] != "v2" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		canonicalFailure(w, journal.Failure("AuthenticationDenied"))
		return
	}
	principal, ok := s.clients[r.TLS.PeerCertificates[0].Subject.CommonName]
	if !ok || !includesLog(principal.Logs, log) {
		canonicalFailure(w, journal.Failure("AuthenticationDenied"))
		return
	}
	if r.Method == http.MethodPost && len(parts) == 5 && operation == "authority-challenge" {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		var request AuthorityChallengeRequest
		if err != nil || journal.DecodeStrict(raw, &request, 2048) != nil {
			canonicalFailure(w, journal.Failure("RequestInvalid"))
			return
		}
		state, err := s.Ledger.ReadCurrent(ctx, log, request.Floor)
		if err != nil {
			canonicalFailure(w, err)
			return
		}
		private, exists := s.signing[state.Authority.WitnessKey.KeyID]
		if !exists {
			canonicalFailure(w, journal.Failure("SigningKeyUnavailable"))
			return
		}
		proof, err := journal.SignAuthorityProof(journal.AuthorityProofBody{Format: "sekvyr-authority-proof-v2", State: state.AuthorityView(), RequestNonce: request.RequestNonce, Floor: request.Floor}, private)
		if err != nil {
			canonicalFailure(w, err)
			return
		}
		_, _ = w.Write(proof)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 5 && operation == "authority" {
		state, err := s.Ledger.ReadCurrent(ctx, log, journal.Cursor{})
		if err != nil {
			canonicalFailure(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(state)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 6 && operation == "records" {
		raw, err := s.Ledger.ReadRecord(ctx, log, parts[5])
		if err != nil {
			canonicalFailure(w, err)
			return
		}
		_, _ = w.Write(raw)
		return
	}
	allowedKind := map[string]string{"commits": "snapshot", "transitions": "transition", "fence-grants": "fence-grant", "fence-activations": "fence-activation"}[operation]
	if r.Method != http.MethodPost || len(parts) != 5 || allowedKind == "" || !includesLog(principal.WriteKinds, allowedKind) || r.Header.Get("Content-Type") != "application/json" {
		canonicalFailure(w, journal.Failure("AuthenticationDenied"))
		return
	}
	maximum := 96 << 10
	if operation == "transitions" {
		maximum = journal.MaxRecordBytes
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(maximum)))
	if err != nil {
		canonicalFailure(w, journal.Failure("RequestInvalid"))
		return
	}
	var state journal.CurrentState
	switch operation {
	case "commits":
		var request CanonicalCommitRequest
		if journal.DecodeStrict(raw, &request, maximum) != nil || !validHash(request.EnvelopeHash, false) {
			err = journal.Failure("RequestInvalid")
			break
		}
		current, readErr := s.Ledger.ReadCurrent(ctx, log, journal.Cursor{})
		if readErr != nil {
			err = readErr
			break
		}
		fetcher, exists := s.fetchers[log]
		if !exists {
			err = journal.Failure("StagedEnvelopeUnavailable")
			break
		}
		envelope, fetchErr := fetcher.Fetch(ctx, current.Scope, request.EnvelopeHash)
		if fetchErr != nil {
			err = journal.Failure("StagedEnvelopeUnavailable")
			break
		}
		hash, hashErr := e2e2.EnvelopeHash(envelope)
		if hashErr != nil || hash != request.EnvelopeHash {
			err = journal.Failure("StagedEnvelopeHashMismatch")
			break
		}
		state, err = s.Ledger.AppendSnapshotCAS(ctx, log, request.Expected, envelope)
	case "transitions":
		var request journal.SignedTransition
		if journal.DecodeStrict(raw, &request, maximum) != nil {
			err = journal.Failure("RequestInvalid")
			break
		}
		state, err = s.Ledger.AppendTransitionCAS(ctx, log, request.Body.Expected, raw)
	case "fence-grants":
		var request FenceGrantRequest
		if journal.DecodeStrict(raw, &request, maximum) != nil {
			err = journal.Failure("RequestInvalid")
			break
		}
		body, _ := json.Marshal(request.Grant)
		state, err = s.Ledger.AppendFenceGrantCAS(ctx, log, request.Expected, body)
	case "fence-activations":
		var request FenceActivationRequest
		if journal.DecodeStrict(raw, &request, maximum) != nil {
			err = journal.Failure("RequestInvalid")
			break
		}
		body, _ := json.Marshal(request.Activation)
		state, err = s.Ledger.AppendFenceActivationCAS(ctx, log, request.Expected, body)
	}
	if err != nil {
		canonicalFailure(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(state)
}
func includesLog(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func canonicalFailure(w http.ResponseWriter, err error) {
	reason := journal.Reason(err)
	status := 503
	switch reason {
	case "CASConflict", "GrantCASConflict":
		status = 409
	case "AuthenticationDenied", "StorageDenied":
		status = 403
	case "LogUnknown", "RecordUnknown":
		status = 404
	case "JournalBusy":
		status = 429
	case "RequestInvalid", "ChallengeInvalid", "FloorUnknownOrFork", "TransitionInvalid", "GrantInvalid", "ActivationInvalid", "AuthorityEpochInvalid", "EnvelopeInvalid", "EnvelopeFork", "EnrollmentInvalid", "ActivationSnapshotRequired", "AuthorityTransitionRequired":
		status = 400
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason})
}
