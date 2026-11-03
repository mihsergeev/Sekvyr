// Package transport contains bounded HTTPS-only untrusted wire clients.
// Incoming bytes still require independent signature and context verification.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
)

type Error struct{ Reason string }

func (e *Error) SourceReason() string { return e.Reason }

func (e *Error) Error() string    { return "secure transport: " + e.Reason }
func failure(reason string) error { return &Error{Reason: reason} }

func secureClient(caPEM []byte) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		if len(caPEM) > 64<<10 {
			return nil, failure("CAInvalid")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, failure("CAInvalid")
		}
		tlsConfig.RootCAs = roots
	}
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	return &http.Client{Transport: t, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// readBounded owns and closes the response body, including on refusal. It never
// returns an upstream error string or accepts compressed amplification.
func readBounded(response *http.Response, max int) ([]byte, error) {
	defer response.Body.Close()
	if max < 1 || response.ContentLength > int64(max) || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return nil, failure("ResponseBounds")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
	if err != nil || len(raw) == 0 || len(raw) > max {
		return nil, failure("ResponseBounds")
	}
	return raw, nil
}
func allowedOrigin(origin string, allowed []string) (string, error) {
	canonical, err := panelauth.CanonicalOrigin(origin)
	if err != nil {
		return "", failure("OriginInvalid")
	}
	for _, value := range allowed {
		pin, e := panelauth.CanonicalOrigin(value)
		if e == nil && pin == canonical {
			return canonical, nil
		}
	}
	return "", failure("OriginDenied")
}
func hash(value string, allowZero bool) bool {
	if len(value) != 64 {
		return false
	}
	nonzero := false
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		if c != '0' {
			nonzero = true
		}
	}
	return allowZero || nonzero
}
