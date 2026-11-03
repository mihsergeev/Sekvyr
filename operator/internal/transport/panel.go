package transport

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mihsergeev/Sekvyr/operator/internal/panelauth"
	"github.com/mihsergeev/Sekvyr/operator/internal/witness"
	"sync"
	"time"
)

// PanelSource is scoped to one authorized view and one reconciliation.
type PanelSource struct {
	mu        sync.Mutex
	auth      *panelauth.Client
	scope     witness.Scope
	session   panelauth.Session
	retryUsed bool
	capable   bool
	publicKey []byte
	reported  bool
}

func (*PanelSource) String() string   { return "panel source [redacted]" }
func (*PanelSource) GoString() string { return "panel source [redacted]" }
func (s *PanelSource) SetNodePublicKey(public []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicKey = append([]byte(nil), public...)
}
func NewPanelSource(cfg panelauth.Config, scope witness.Scope) (*PanelSource, error) {
	c, err := panelauth.New(cfg)
	if err != nil {
		return nil, err
	}
	return &PanelSource{auth: c, scope: scope}, nil
}
func (s *PanelSource) Close() { s.auth.Close() }
func (s *PanelSource) ready(ctx context.Context) error {
	if s.session.ExpiresAt.Before(time.Now().Add(5 * time.Second)) {
		session, err := s.auth.Login(ctx)
		if err != nil {
			return err
		}
		s.session = session
	}
	if !s.capable {
		raw, err := s.auth.E2E2Capabilities(ctx, s.session)
		if err != nil {
			return err
		}
		var c struct {
			Protocols []string `json:"protocols"`
		}
		if json.Unmarshal(raw, &c) != nil {
			return failure("UpgradeRequired")
		}
		for _, p := range c.Protocols {
			if p == "e2e2" {
				s.capable = true
			}
		}
		if !s.capable {
			return failure("UpgradeRequired")
		}
	}
	if !s.reported && len(s.publicKey) != 0 {
		if err := s.auth.ReportNodeKey(ctx, s.session, s.publicKey); err != nil {
			return err
		}
		s.reported = true
	}
	return nil
}
func (s *PanelSource) get(ctx context.Context, wrap bool, scope witness.Scope, hash string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if scope != s.scope {
		return nil, failure("ScopeDenied")
	}
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	read := func() ([]byte, error) {
		if wrap {
			return s.auth.E2E2ReaderWrap(ctx, s.session, scope.ViewID, hash)
		}
		return s.auth.E2E2Envelope(ctx, s.session, scope.ViewID, hash)
	}
	raw, err := read()
	if err != nil && !s.retryUsed {
		var e *panelauth.Error
		if errors.As(err, &e) && (e.Reason == "AuthenticationDenied" || e.Reason == "SessionInvalid") {
			s.retryUsed = true
			s.session = panelauth.Session{}
			s.capable = false
			if err = s.ready(ctx); err != nil {
				return nil, err
			}
			return read()
		}
	}
	return raw, err
}
func (s *PanelSource) EnvelopeByHash(ctx context.Context, scope witness.Scope, hash string) ([]byte, error) {
	return s.get(ctx, false, scope, hash)
}
func (s *PanelSource) ReaderWrap(ctx context.Context, scope witness.Scope, hash, read, policy, recipient string) ([]byte, error) {
	return s.get(ctx, true, scope, hash)
}
