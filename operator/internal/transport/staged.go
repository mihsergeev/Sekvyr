package transport

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
)

type StagedFetcher struct {
	origin, tokenFile string
	allowedViews      map[string]bool
	http              *http.Client
}

func (StagedFetcher) String() string   { return "staged ciphertext fetcher [redacted]" }
func (StagedFetcher) GoString() string { return "staged ciphertext fetcher [redacted]" }
func NewStagedFetcher(origin string, caPEM []byte, tokenFile string, allowedViews []string) (*StagedFetcher, error) {
	canonical, err := panelauth.CanonicalOrigin(origin)
	if err != nil {
		return nil, failure("OriginInvalid")
	}
	if !filepath.IsAbs(tokenFile) || len(allowedViews) == 0 || len(allowedViews) > 64 {
		return nil, failure("FetchConfigInvalid")
	}
	views := map[string]bool{}
	for _, id := range allowedViews {
		if !validID(id) || views[id] {
			return nil, failure("FetchConfigInvalid")
		}
		views[id] = true
	}
	client, err := secureClient(caPEM)
	if err != nil {
		return nil, err
	}
	return &StagedFetcher{origin: canonical, tokenFile: tokenFile, allowedViews: views, http: client}, nil
}
func (f *StagedFetcher) Close() {
	if f != nil && f.http != nil {
		f.http.CloseIdleConnections()
	}
}
func (f *StagedFetcher) Fetch(ctx context.Context, scope e2e2.Scope, envelopeHash string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, failure("Cancelled")
	}
	if f == nil || f.http == nil || !e2e2.ValidScope(scope) || !f.allowedViews[scope.ViewID] || !hash(envelopeHash, false) {
		return nil, failure("FetchScopeDenied")
	}
	info, err := os.Stat(f.tokenFile)
	if err != nil || !info.Mode().IsRegular() {
		return nil, failure("FetchCredentialUnavailable")
	}
	file, err := os.Open(f.tokenFile)
	if err != nil {
		return nil, failure("FetchCredentialUnavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8001))
	file.Close()
	defer clear(raw)
	if err != nil || len(raw) > 8000 {
		return nil, failure("FetchCredentialInvalid")
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || len(token) > 8000 {
		return nil, failure("FetchCredentialInvalid")
	}
	for _, c := range []byte(token) {
		if c < 33 || c > 126 {
			return nil, failure("FetchCredentialInvalid")
		}
	}
	url := f.origin + "/api/e2e2/witness/views/" + scope.ViewID + "/envelopes/" + envelopeHash
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, failure("RequestInvalid")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sekvyr-witness/development")
	res, err := f.http.Do(req)
	if err != nil {
		return nil, failure("StagingUnavailable")
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		if res.StatusCode >= 300 && res.StatusCode < 400 {
			return nil, failure("RedirectDenied")
		}
		return nil, failure("StagingUnavailable")
	}
	return readBounded(res, e2e2.MaxEnvelopeBytes)
}
func validID(id string) bool {
	return e2e2.ValidScope(e2e2.Scope{RealmID: id, ProjectID: id, EnvironmentID: id, ViewID: id, LogID: id})
}
