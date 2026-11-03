package panelauth

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// ReportNodeKey sends only the already pinned public key, never applied values.
func (c *Client) ReportNodeKey(ctx context.Context, s Session, public []byte) error {
	if _, err := ecdh.P256().NewPublicKey(public); err != nil || len(public) != 65 {
		return failure("NodeKeyInvalid")
	}
	if s.token == "" || s.origin != c.origin || !c.now().Before(s.ExpiresAt) {
		return failure("SessionInvalid")
	}
	body, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(public), "agent_version": "sekvyr-operator-stage4"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/v1/machine/report", bytes.NewReader(body))
	if err != nil {
		return failure("RequestInvalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	res, err := c.http.Do(req)
	if err != nil {
		return failure("PanelUnavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return failure("RedirectDenied")
	}
	if res.StatusCode == 401 {
		return failure("AuthenticationDenied")
	}
	if res.StatusCode == 403 {
		return failure("AccessDenied")
	}
	if res.StatusCode >= 500 {
		return failure("PanelUnavailable")
	}
	if res.StatusCode != 200 {
		return failure("NodeReportDenied")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32769))
	if err != nil || len(raw) > 32768 {
		return failure("ResponseBounds")
	}
	return nil
}

func uuid(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range []byte(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", rune(c)) {
			return false
		}
	}
	return true
}
func hash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !strings.ContainsRune("0123456789abcdef", rune(c)) {
			return false
		}
	}
	return true
}

// Bearer sessions are attached only to these fixed same-origin read paths.
func (c *Client) E2E2Envelope(ctx context.Context, s Session, view, digest string) ([]byte, error) {
	if !uuid(view) || !hash(digest) {
		return nil, failure("RequestInvalid")
	}
	return c.boundedGET(ctx, s, "/api/v1/machine/e2e2/views/"+view+"/envelopes/"+digest, 16<<20)
}
func (c *Client) E2E2ReaderWrap(ctx context.Context, s Session, view, digest string) ([]byte, error) {
	if !uuid(view) || !hash(digest) {
		return nil, failure("RequestInvalid")
	}
	return c.boundedGET(ctx, s, "/api/v1/machine/e2e2/views/"+view+"/reader-wrap?envelope_hash="+digest, 16<<10)
}
func (c *Client) E2E2Capabilities(ctx context.Context, s Session) ([]byte, error) {
	return c.boundedGET(ctx, s, "/api/v1/machine/capabilities", 16<<10)
}
func (c *Client) boundedGET(ctx context.Context, s Session, path string, maximum int64) ([]byte, error) {
	if s.token == "" || s.origin != c.origin || !c.now().Before(s.ExpiresAt) {
		return nil, failure("SessionInvalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return nil, failure("RequestInvalid")
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sekvyr-operator/stage4")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, failure("PanelUnavailable")
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return nil, failure("RedirectDenied")
	case response.StatusCode == 401:
		return nil, failure("AuthenticationDenied")
	case response.StatusCode == 403:
		return nil, failure("AccessDenied")
	case response.StatusCode == 404:
		return nil, failure("CanonicalSnapshotUnavailable")
	case response.StatusCode == 409 || response.StatusCode == 426:
		return nil, failure("UpgradeRequired")
	case response.StatusCode == 429:
		return nil, failure("RateLimited")
	case response.StatusCode >= 500:
		return nil, failure("PanelUnavailable")
	case response.StatusCode != 200:
		return nil, failure("PanelResponseInvalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, failure("ResponseBounds")
	}
	return raw, nil
}
