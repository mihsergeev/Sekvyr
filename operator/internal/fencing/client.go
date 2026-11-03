package fencing

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
)

type ClientConfig struct {
	Origin                      string
	AllowedOrigins              []string
	CustomCAPEM                 []byte
	TokenFile                   string
	PodUID                      string
	InstallationID              string
	LogID                       string
	MinimumCursor               journal.Cursor
	ExpectedLeaseHolderIdentity string
	Journal                     Ledger
}

type Client struct {
	config ClientConfig
	origin string
	http   *http.Client
}

func (*Client) String() string   { return "fencer client [redacted]" }
func (*Client) GoString() string { return "fencer client [redacted]" }

func NewClient(config ClientConfig) (*Client, error) {
	origin, err := panelauth.CanonicalOrigin(config.Origin)
	if err != nil {
		return nil, fail("OriginInvalid")
	}
	allowed := false
	for _, candidate := range config.AllowedOrigins {
		value, e := panelauth.CanonicalOrigin(candidate)
		if e != nil {
			return nil, fail("OriginInvalid")
		}
		allowed = allowed || value == origin
	}
	if !allowed || config.Journal == nil || config.TokenFile == "" || !validUUID(config.PodUID) || !validUUID(config.InstallationID) || !validUUID(config.LogID) || config.ExpectedLeaseHolderIdentity == "" {
		return nil, fail("ClientConfigInvalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(config.CustomCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(config.CustomCAPEM) {
			return nil, fail("CAInvalid")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, DisableCompression: true, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	config.AllowedOrigins = append([]string(nil), config.AllowedOrigins...)
	config.CustomCAPEM = append([]byte(nil), config.CustomCAPEM...)
	return &Client{config: config, origin: origin, http: &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

type response struct {
	Grant     journal.SignedFenceGrant `json:"grant"`
	GrantHash string                   `json:"grant_hash"`
	Active    bool                     `json:"active"`
}
type acquireRequest struct {
	BootstrapGeneration         int64  `json:"bootstrap_generation"`
	ExpectedLeaseHolderIdentity string `json:"expected_lease_holder_identity"`
}
type hashRequest struct {
	GrantHash string `json:"grant_hash"`
}

func (c *Client) request(ctx context.Context, operation string, body any) (response, error) {
	var output response
	if c == nil || ctx == nil || ctx.Err() != nil {
		return output, fail("Cancelled")
	}
	file, err := os.Open(c.config.TokenFile)
	if err != nil {
		return output, fail("ProjectedTokenUnavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	file.Close()
	if err != nil || len(raw) > 16384 {
		return output, fail("ProjectedTokenInvalid")
	}
	token := strings.TrimSpace(string(raw))
	clear(raw)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return output, fail("ProjectedTokenInvalid")
	}
	encoded, err := encodeWire(body)
	if err != nil {
		return output, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/v1/installations/"+c.config.InstallationID+"/"+operation, bytes.NewReader(encoded))
	if err != nil {
		return output, fail("RequestInvalid")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		if operation == "ready" && ctx.Err() != nil {
			return output, fail("Cancelled")
		}
		return output, fail("FencerUnavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return output, fail("RedirectDenied")
	}
	if res.StatusCode != http.StatusOK {
		if operation == "ready" {
			return output, readyServiceFailure(res.Body)
		}
		return output, fail("FencerDenied")
	}
	raw, err = io.ReadAll(io.LimitReader(res.Body, maxWireBytes+1))
	if err != nil || len(raw) > maxWireBytes || journal.DecodeStrict(raw, &output, maxWireBytes) != nil {
		return response{}, fail("ResponseInvalid")
	}
	return output, nil
}

// Only fixed service reasons may cross the untrusted HTTP response boundary.
// Never include a body, URL, upstream error or arbitrary reason in diagnostics.
func readyServiceFailure(body io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(body, 4097))
	var remote struct {
		Reason string `json:"reason"`
	}
	if err != nil || len(raw) > 4096 || journal.DecodeStrict(raw, &remote, 4096) != nil {
		return fail("FencerDenied")
	}
	switch remote.Reason {
	case "JournalUnavailable", "IdentityRoleCollision", "EnrollmentMismatch",
		"LeaseUnavailable", "LeaseMismatch", "LeaseExpired", "AuthenticationDenied",
		"IdentityMismatch", "BoundPodRequired", "NamespaceReplaced", "ServiceAccountReplaced",
		"PodReplaced", "GrantUnavailable", "GrantInvalid", "BarriersIncomplete",
		"GrantChanged", "ObjectDenied", "ObjectMissing", "ObjectReplaced", "FencerBusy":
		return fail(remote.Reason)
	default:
		return fail("FencerDenied")
	}
}

func (c *Client) verify(ctx context.Context, remote response, active bool) (*Session, error) {
	state, err := c.config.Journal.ReadCurrent(ctx, c.config.LogID, c.config.MinimumCursor)
	if err != nil {
		return nil, fail("JournalUnavailable")
	}
	session, err := sessionFrom(state, c.config.InstallationID, active)
	if err != nil {
		return nil, err
	}
	remoteHash, err := journal.FenceGrantHash(remote.Grant.Body)
	if err != nil || remoteHash != session.hash || remote.GrantHash != session.hash || journal.VerifyFenceGrant(remote.Grant, state.Authority) != nil ||
		session.grant.Body.OwnerPodUID != c.config.PodUID || session.grant.Body.LeaseHolderIdentity != c.config.ExpectedLeaseHolderIdentity ||
		session.grant.Body.Scope.LogID != c.config.LogID || active && !remote.Active {
		return nil, fail("GrantChanged")
	}
	return session, nil
}

func (c *Client) Acquire(ctx context.Context, installation string, generation int64) (*Session, error) {
	if c == nil || installation != c.config.InstallationID || generation < 1 {
		return nil, fail("BootstrapMismatch")
	}
	remote, err := c.request(ctx, "acquire", acquireRequest{BootstrapGeneration: generation, ExpectedLeaseHolderIdentity: c.config.ExpectedLeaseHolderIdentity})
	if err != nil {
		return nil, err
	}
	session, err := c.verify(ctx, remote, remote.Active)
	if err != nil || session.grant.Body.BootstrapGeneration != generation {
		return nil, fail("GrantChanged")
	}
	return session, nil
}

func (c *Client) Barriers(ctx context.Context, session *Session) (*Session, error) {
	if session == nil {
		return nil, fail("GrantInvalid")
	}
	remote, err := c.request(ctx, "barriers", hashRequest{GrantHash: session.hash})
	if err != nil {
		return nil, err
	}
	current, err := c.verify(ctx, remote, true)
	if err != nil || current.hash != session.hash {
		return nil, fail("GrantChanged")
	}
	return current, nil
}

func (c *Client) Ready(ctx context.Context, session *Session) error {
	if session == nil || !session.ready {
		return fail("BarriersIncomplete")
	}
	remote, err := c.request(ctx, "ready", hashRequest{GrantHash: session.hash})
	if err != nil {
		return err
	}
	current, err := c.verify(ctx, remote, true)
	if err != nil {
		if ctx.Err() != nil {
			return fail("Cancelled")
		}
		return err
	}
	if current.hash != session.hash {
		return fail("GrantChanged")
	}
	return nil
}
