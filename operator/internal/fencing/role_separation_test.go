package fencing

import (
	"context"
	"errors"
	"testing"
)

func TestFencerAndBootstrapCannotAdoptOperatorIdentity(t *testing.T) {
	f := newFixture(t)
	config := f.service.Config
	config.FencerServiceAccountUID = config.OperatorServiceAccountUID
	raw, _ := encodeWire(config)
	if _, err := DecodeConfig(raw); err == nil {
		t.Fatal("same operator/fencer UID accepted")
	}
	config = f.service.Config
	config.BootstrapSubjects = append(config.BootstrapSubjects, Subject{Username: f.operator().Username, UID: config.OperatorServiceAccountUID})
	raw, _ = encodeWire(config)
	if _, err := DecodeConfig(raw); err == nil {
		t.Fatal("operator may be bootstrap administrator")
	}
	// Even a directly constructed invalid service must not turn an ordinary
	// operator token into an outage-independent bootstrap bypass.
	f.service.Config = config
	old := f.secret(t)
	next := old.DeepCopy()
	f.ledger.failure = errors.New("synthetic offline journal")
	if f.service.Admit(context.Background(), requestFor(old, next, f.operator())).Allowed {
		t.Fatal("bootstrap identity collision bypassed fencing")
	}
}
