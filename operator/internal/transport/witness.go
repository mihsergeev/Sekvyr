package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
)

type WitnessClient struct {
	origin string
	http   *http.Client
}

func (WitnessClient) String() string   { return "witness wire client [redacted]" }
func (WitnessClient) GoString() string { return "witness wire client [redacted]" }
func NewWitnessClient(origin string, allowed []string, caPEM []byte) (*WitnessClient, error) {
	canonical, err := allowedOrigin(origin, allowed)
	if err != nil {
		return nil, err
	}
	client, err := secureClient(caPEM)
	if err != nil {
		return nil, err
	}
	return &WitnessClient{canonical, client}, nil
}
func (c *WitnessClient) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *WitnessClient) Head(ctx context.Context, challenge witness.Challenge) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, failure("Cancelled")
	}
	if c == nil || c.http == nil || !e2e2.ValidScope(e2e2.Scope{RealmID: challenge.Scope.RealmID, ProjectID: challenge.Scope.ProjectID, EnvironmentID: challenge.Scope.EnvironmentID, ViewID: challenge.Scope.ViewID, LogID: challenge.Scope.LogID}) || len(challenge.Nonce) != 32 {
		return nil, failure("ChallengeInvalid")
	}
	seq, err := e2e2.Counter(challenge.Floor.Sequence, true)
	if err != nil || !hash(challenge.Floor.EnvelopeHash, true) || (seq == 0) != (challenge.Floor.EnvelopeHash == e2e2.ZeroHash) {
		return nil, failure("ChallengeInvalid")
	}
	body, _ := json.Marshal(struct {
		RequestNonce  string `json:"request_nonce"`
		FloorSequence string `json:"floor_sequence"`
		FloorHash     string `json:"floor_hash"`
	}{base64.RawURLEncoding.EncodeToString(challenge.Nonce), challenge.Floor.Sequence, challenge.Floor.EnvelopeHash})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/v1/logs/"+challenge.Scope.LogID+"/head-challenge", bytes.NewReader(body))
	if err != nil {
		return nil, failure("RequestInvalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sekvyr-operator/development")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, failure("WitnessUnavailable")
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		if res.StatusCode >= 300 && res.StatusCode < 400 {
			return nil, failure("RedirectDenied")
		}
		return nil, failure("WitnessUnavailable")
	}
	return readBounded(res, e2e2.MaxHeadProofBytes)
}

type Capabilities struct {
	Format            string `json:"format"`
	Profile           string `json:"profile"`
	ProductionReady   bool   `json:"production_ready"`
	Ledger            string `json:"ledger"`
	AuthorityRotation bool   `json:"authority_rotation"`
}

// DevCapabilities reports a signed-key-independent diagnostic only. It is not
// authenticated head state and cannot authorize values or a production profile.
func (c *WitnessClient) DevCapabilities(ctx context.Context) (Capabilities, error) {
	if ctx == nil || ctx.Err() != nil {
		return Capabilities{}, failure("Cancelled")
	}
	if c == nil || c.http == nil {
		return Capabilities{}, failure("WitnessUnavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/v1/capabilities", nil)
	if err != nil {
		return Capabilities{}, failure("RequestInvalid")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return Capabilities{}, failure("WitnessUnavailable")
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return Capabilities{}, failure("WitnessUnavailable")
	}
	raw, err := readBounded(res, 2048)
	if err != nil {
		return Capabilities{}, err
	}
	var caps Capabilities
	if e2e2.DecodeStrict(raw, &caps, 2048) != nil || caps.Format != "sekvyr-witness-capabilities-v1" || caps.Profile != "development-filesystem-not-worm" || caps.ProductionReady || caps.AuthorityRotation || caps.Ledger != "full-replay-exclusive-cas-fsync" {
		return Capabilities{}, failure("CapabilitiesInvalid")
	}
	return caps, nil
}
