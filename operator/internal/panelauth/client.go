// Package panelauth exchanges a fixed projected ServiceAccount token for a
// short-lived machine session. It does not fetch values or establish E2E2 trust.
package panelauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxTokenBytes = 8000
const maxResponseBytes = 32 << 10

// Error carries a stable public reason. Upstream bodies, URLs, tokens and
// underlying transport errors must never become condition messages or logs.
type Error struct{ Reason string }

func (e *Error) Error() string        { return "panel authentication: " + e.Reason }
func (e *Error) SourceReason() string { return e.Reason }
func failure(reason string) error     { return &Error{Reason: reason} }

type Config struct {
	Origin         string
	AllowedOrigins []string
	TokenFile      string
	Namespace      string
	ServiceAccount string
	Audience       string
	// CustomCAPEM replaces the system trust store when supplied. Authorization
	// of these exact certificates (ConfigMap UID and DER pins) belongs to the
	// installation gate, before constructing this client.
	CustomCAPEM []byte
}

type Client struct {
	origin                                                  string
	tokenFile, subject, namespace, serviceAccount, audience string
	http                                                    *http.Client
	now                                                     func() time.Time
}

// CanonicalOrigin accepts an HTTPS origin, with an optional single root slash.
// No credentials, query, fragment, path escaping, trailing dot or implicit
// environment proxy is allowed. DNS is still an administrator/network boundary.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(raw, "\\\t\r\n ") {
		return "", failure("OriginInvalid")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return "", failure("OriginInvalid")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return "", failure("OriginInvalid")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", failure("OriginInvalid")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", failure("OriginInvalid")
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		p, e := strconv.Atoi(port)
		if e != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return "", failure("OriginInvalid")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", failure("OriginInvalid")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != "443" {
		host += ":" + port
	}
	return "https://" + host, nil
}

func New(cfg Config) (*Client, error) {
	origin, err := CanonicalOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, candidate := range cfg.AllowedOrigins {
		a, e := CanonicalOrigin(candidate)
		if e != nil {
			return nil, e
		}
		allowed = allowed || a == origin
	}
	if !allowed {
		return nil, failure("OriginDenied")
	}
	if cfg.TokenFile == "" || cfg.Namespace == "" || cfg.ServiceAccount == "" || cfg.Audience == "" || len(cfg.Audience) > 120 {
		return nil, failure("IdentityInvalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(cfg.CustomCAPEM) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.CustomCAPEM) {
			return nil, failure("CAInvalid")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           4, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	return &Client{
		origin: origin, tokenFile: cfg.TokenFile,
		subject:   "system:serviceaccount:" + cfg.Namespace + ":" + cfg.ServiceAccount,
		namespace: cfg.Namespace, serviceAccount: cfg.ServiceAccount, audience: cfg.Audience,
		http: &http.Client{Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now: time.Now,
	}, nil
}

// Close releases pooled connections. No token is persisted or cached.
func (c *Client) Close() { c.http.CloseIdleConnections() }

type Session struct {
	token     string
	origin    string
	ExpiresAt time.Time
}

func (Session) String() string   { return "panel session [redacted]" }
func (Session) GoString() string { return "panel session [redacted]" }

// CheckIdentity performs only the existing read-only machine/whoami request.
// The session cannot be exported or attached to an arbitrary HTTP client that
// might forward a bearer token on redirects. This is not an E2E2 capability test.
func (c *Client) CheckIdentity(ctx context.Context, s Session) error {
	if s.token == "" || !c.now().Before(s.ExpiresAt) || s.origin != c.origin {
		return failure("SessionInvalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/api/v1/machine/whoami", nil)
	if err != nil {
		return failure("RequestInvalid")
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sekvyr-operator/stage2")
	res, err := c.http.Do(req)
	if err != nil {
		return failure("PanelUnavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return failure("RedirectDenied")
	}
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return failure("AccessDenied")
	}
	if res.StatusCode != http.StatusOK {
		return failure("IdentityCheckFailed")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return failure("ResponseInvalid")
	}
	var out struct {
		Name         string   `json:"name"`
		ClientID     string   `json:"client_id"`
		Environments []string `json:"environments"`
		ExpiresAt    string   `json:"expires_at"`
	}
	if decodeStrict(raw, &out) != nil || out.ClientID == "" {
		return failure("ResponseInvalid")
	}
	return nil
}

// Login reopens the projected token file on EVERY attempt, so kubelet rotation
// is observed. No background refresh or infinite retry is performed.
func (c *Client) Login(ctx context.Context) (Session, error) {
	f, err := os.Open(c.tokenFile)
	if err != nil {
		return Session{}, failure("ProjectedTokenUnavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	f.Close()
	if err != nil || len(raw) > maxTokenBytes {
		return Session{}, failure("ProjectedTokenInvalid")
	}
	token := strings.TrimSpace(string(raw))
	if err := c.checkClaims(token); err != nil {
		return Session{}, err
	}
	body, _ := json.Marshal(struct {
		Token string `json:"kubernetes_token"`
	}{token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/v1/machine/token", bytes.NewReader(body))
	if err != nil {
		return Session{}, failure("RequestInvalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sekvyr-operator/stage2")
	started := c.now()
	res, err := c.http.Do(req)
	if err != nil {
		return Session{}, failure("PanelUnavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		switch {
		case res.StatusCode >= 300 && res.StatusCode < 400:
			return Session{}, failure("RedirectDenied")
		case res.StatusCode == 401:
			return Session{}, failure("AuthenticationDenied")
		case res.StatusCode == 403:
			return Session{}, failure("AccessDenied")
		case res.StatusCode == 429:
			return Session{}, failure("RateLimited")
		case res.StatusCode >= 500:
			return Session{}, failure("PanelUnavailable")
		default:
			return Session{}, failure("AuthenticationFailed")
		}
	}
	raw, err = io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return Session{}, failure("ResponseInvalid")
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Name        string `json:"name"`
	}
	if decodeStrict(raw, &result) != nil || result.TokenType != "Bearer" || result.ExpiresIn < 1 || result.ExpiresIn > 3600 ||
		len(result.AccessToken) == 0 || len(result.AccessToken) > maxTokenBytes || strings.ContainsAny(result.AccessToken, " \t\r\n") {
		return Session{}, failure("ResponseInvalid")
	}
	expires := started.Add(time.Duration(result.ExpiresIn) * time.Second)
	if !c.now().Before(expires) {
		return Session{}, failure("SessionExpired")
	}
	return Session{token: result.AccessToken, origin: c.origin, ExpiresAt: expires}, nil
}

// These unverified claim checks prevent accidentally sending another projected
// identity/audience to the panel. They DO NOT authenticate the JWT: the panel
// must validate its signature, issuer, audience, expiry and registered grants
// against independently configured cluster JWKS. Offline JWKS validation does
// not detect pod deletion immediately; expiry bounds the stolen token lifetime.
func (c *Client) checkClaims(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return failure("ProjectedTokenInvalid")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return failure("ProjectedTokenInvalid")
	}
	var claims struct {
		Subject    string          `json:"sub"`
		Audience   json.RawMessage `json:"aud"`
		Expires    json.Number     `json:"exp"`
		NotBefore  json.Number     `json:"nbf"`
		Kubernetes struct {
			Namespace      string `json:"namespace"`
			ServiceAccount struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"serviceaccount"`
			Pod struct {
				UID string `json:"uid"`
			} `json:"pod"`
		} `json:"kubernetes.io"`
	}
	// Unknown JWT claims are allowed, duplicate JSON keys are not.
	if decodeNoDuplicates(raw) != nil || json.Unmarshal(raw, &claims) != nil {
		return failure("ProjectedTokenInvalid")
	}
	var audiences []string
	if json.Unmarshal(claims.Audience, &audiences) != nil {
		var audience string
		if json.Unmarshal(claims.Audience, &audience) != nil {
			return failure("ProjectedTokenInvalid")
		}
		audiences = []string{audience}
	}
	expires, err := claims.Expires.Int64()
	if err != nil || expires <= c.now().Unix() {
		return failure("ProjectedTokenExpired")
	}
	if claims.NotBefore != "" {
		nbf, e := claims.NotBefore.Int64()
		if e != nil || nbf > c.now().Unix() {
			return failure("ProjectedTokenInvalid")
		}
	}
	k := claims.Kubernetes
	if claims.Subject != c.subject || len(audiences) != 1 || audiences[0] != c.audience ||
		k.Namespace != c.namespace || k.ServiceAccount.Name != c.serviceAccount || k.ServiceAccount.UID == "" || k.Pod.UID == "" {
		return failure("ProjectedIdentityMismatch")
	}
	return nil
}

func decodeStrict(raw []byte, out any) error {
	if err := decodeNoDuplicates(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// Reject duplicate keys, including nested ones, and trailing JSON documents.
func decodeNoDuplicates(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate key")
				}
				seen[key] = true
				if e = value(); e != nil {
					return e
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err = value(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
