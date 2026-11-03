package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

type fixture struct {
	trust     Trust
	challenge Challenge
	proof     e2e2.HeadProof
	private   ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("key generation failed")
	}
	scope := Scope{"10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002", "10000000-0000-4000-8000-000000000003", "10000000-0000-4000-8000-000000000004", "10000000-0000-4000-8000-000000000005"}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal("nonce generation failed")
	}
	hash1, hash2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	trust := Trust{Scope: scope, WitnessEpoch: "1", KeyID: e2e2.KeyID(pub), PublicKey: pub, PublisherPolicyEpoch: "1", Checkpoint: Floor{"1", hash1}}
	local := Head{Scope: scope, WitnessEpoch: "1", Sequence: "1", EnvelopeHash: hash1, ReadKeyEpoch: "1", PublisherPolicyEpoch: "1"}
	challenge := Challenge{Scope: scope, Nonce: nonce, Floor: trust.Checkpoint, HighWatermark: &local}
	proof := e2e2.HeadProof{Body: e2e2.HeadBody{Format: "sekvyr-e2e2-head-v1", Scope: e2e2.Scope{RealmID: scope.RealmID, ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID, ViewID: scope.ViewID, LogID: scope.LogID}, WitnessEpoch: "1", Sequence: "2", EnvelopeHash: hash2, ReadKeyEpoch: "2", PublisherPolicyEpoch: "1", RequestNonce: base64.RawURLEncoding.EncodeToString(nonce), WitnessKeyID: trust.KeyID, FloorSequence: "1", FloorHash: hash1}}
	return fixture{trust, challenge, proof, priv}
}

func signProof(t *testing.T, f fixture, domain string) []byte {
	t.Helper()
	raw, err := json.Marshal(f.proof.Body)
	if err != nil {
		t.Fatal("body encoding failed")
	}
	body, err := e2e2.Canonical(raw, e2e2.MaxHeadProofBytes)
	if err != nil {
		t.Fatal("body canonicalization failed")
	}
	f.proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.private, append(e2e2.Domain(domain), body...)))
	raw, err = json.Marshal(f.proof)
	if err != nil {
		t.Fatal("proof encoding failed")
	}
	return raw
}

func verifyFixture(t *testing.T, f fixture, raw []byte) (Head, error) {
	t.Helper()
	verifier, err := NewPinnedVerifier(f.trust)
	if err != nil {
		t.Fatal("valid fixture trust rejected")
	}
	return verifier.VerifyHead(context.Background(), f.challenge, raw)
}

func wantRejected(t *testing.T, head Head, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe proof accepted")
	}
	if head != (Head{}) {
		t.Fatal("rejection returned metadata")
	}
	var safe *Error
	if !errors.As(err, &safe) {
		t.Fatal("non-sanitized error type")
	}
}

func TestPinnedHeadValidAndUnchanged(t *testing.T) {
	f := newFixture(t)
	head, err := verifyFixture(t, f, signProof(t, f, headDomain))
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != "2" || head.Scope != f.trust.Scope || head.EnvelopeHash != f.proof.Body.EnvelopeHash {
		t.Fatal("wrong verified metadata")
	}
	// An unchanged head is valid with a new nonce and exact historical floor.
	f.challenge.HighWatermark = &head
	f.challenge.Floor = Floor{head.Sequence, head.EnvelopeHash}
	if _, err = rand.Read(f.challenge.Nonce); err != nil {
		t.Fatal("nonce generation failed")
	}
	f.proof.Body.RequestNonce = base64.RawURLEncoding.EncodeToString(f.challenge.Nonce)
	f.proof.Body.FloorSequence = head.Sequence
	f.proof.Body.FloorHash = head.EnvelopeHash
	if _, err = verifyFixture(t, f, signProof(t, f, headDomain)); err != nil {
		t.Fatal(err)
	}
}

func TestSignedProofRejectsUntrustedClaims(t *testing.T) {
	tests := map[string]func(*fixture){
		"wrong nonce": func(f *fixture) {
			f.proof.Body.RequestNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
		},
		"wrong realm":              func(f *fixture) { f.proof.Body.RealmID = "20000000-0000-4000-8000-000000000001" },
		"wrong project":            func(f *fixture) { f.proof.Body.ProjectID = f.proof.Body.RealmID },
		"wrong environment":        func(f *fixture) { f.proof.Body.EnvironmentID = f.proof.Body.RealmID },
		"wrong view":               func(f *fixture) { f.proof.Body.ViewID = f.proof.Body.RealmID },
		"wrong log":                func(f *fixture) { f.proof.Body.LogID = f.proof.Body.RealmID },
		"wrong witness epoch":      func(f *fixture) { f.proof.Body.WitnessEpoch = "2" },
		"wrong key ID":             func(f *fixture) { f.proof.Body.WitnessKeyID = "ed25519-sha256:" + strings.Repeat("a", 64) },
		"wrong policy":             func(f *fixture) { f.proof.Body.PublisherPolicyEpoch = "2" },
		"forged historical floor":  func(f *fixture) { f.proof.Body.FloorHash = strings.Repeat("f", 64) },
		"omitted historical floor": func(f *fixture) { f.proof.Body.FloorSequence = "0"; f.proof.Body.FloorHash = zeroHash },
		"old head": func(f *fixture) {
			f.proof.Body.Sequence = "0"
			f.proof.Body.EnvelopeHash = zeroHash
			f.proof.Body.ReadKeyEpoch = "0"
			f.proof.Body.PublisherPolicyEpoch = "0"
		},
		"same sequence fork":        func(f *fixture) { f.proof.Body.Sequence = "1" },
		"local read epoch rollback": func(f *fixture) { f.challenge.HighWatermark.ReadKeyEpoch = "3" },
		"same sequence epoch fork": func(f *fixture) {
			f.proof.Body.Sequence = "1"
			f.proof.Body.EnvelopeHash = f.trust.Checkpoint.EnvelopeHash
			f.proof.Body.ReadKeyEpoch = "2"
		},
		"head zero read epoch":   func(f *fixture) { f.proof.Body.ReadKeyEpoch = "0" },
		"head zero policy epoch": func(f *fixture) { f.proof.Body.PublisherPolicyEpoch = "0" },
		"positive zero hash":     func(f *fixture) { f.proof.Body.EnvelopeHash = zeroHash },
		"wrong format":           func(f *fixture) { f.proof.Body.Format = "sekvyr-e2e2-commit-v1" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(&f)
			head, err := verifyFixture(t, f, signProof(t, f, headDomain))
			wantRejected(t, head, err)
		})
	}
}

func TestNonceAndSignatureReplay(t *testing.T) {
	for _, domain := range []string{"head", "sekvyr-e2e2/publish/v1", "sekvyr-e2e2/reader-wrap-sign/v1", headDomain + "\x00"} {
		t.Run(domain, func(t *testing.T) {
			f := newFixture(t)
			head, err := verifyFixture(t, f, signProof(t, f, domain))
			wantRejected(t, head, err)
		})
	}
	f := newFixture(t)
	raw := signProof(t, f, headDomain)
	f.challenge.Nonce = bytes.Repeat([]byte{7}, 32)
	head, err := verifyFixture(t, f, raw)
	wantRejected(t, head, err)
	f = newFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("key generation failed")
	}
	_ = pub
	f.private = priv
	head, err = verifyFixture(t, f, signProof(t, f, headDomain))
	wantRejected(t, head, err)
}

func TestChallengeCannotWeakenPinsOrLocalFloor(t *testing.T) {
	tests := map[string]func(*fixture){
		"short nonce":   func(f *fixture) { f.challenge.Nonce = f.challenge.Nonce[:31] },
		"long nonce":    func(f *fixture) { f.challenge.Nonce = append(f.challenge.Nonce, 0) },
		"missing nonce": func(f *fixture) { f.challenge.Nonce = nil },
		"wrong scope":   func(f *fixture) { f.challenge.Scope.ViewID = f.challenge.Scope.RealmID },
		"below pin":     func(f *fixture) { f.challenge.Floor = Floor{"0", zeroHash} },
		"elevated unanchored floor": func(f *fixture) {
			f.challenge.Floor = Floor{"2", strings.Repeat("2", 64)}
			f.proof.Body.FloorSequence = "2"
			f.proof.Body.FloorHash = f.challenge.Floor.EnvelopeHash
		},
		"pin fork": func(f *fixture) { f.challenge.Floor.EnvelopeHash = strings.Repeat("f", 64) },
		"below local": func(f *fixture) {
			f.challenge.HighWatermark.Sequence = "2"
			f.challenge.HighWatermark.EnvelopeHash = strings.Repeat("2", 64)
		},
		"local pin fork":        func(f *fixture) { f.challenge.HighWatermark.EnvelopeHash = strings.Repeat("f", 64) },
		"local scope mismatch":  func(f *fixture) { f.challenge.HighWatermark.Scope.LogID = f.trust.Scope.RealmID },
		"local epoch mismatch":  func(f *fixture) { f.challenge.HighWatermark.WitnessEpoch = "2" },
		"local policy mismatch": func(f *fixture) { f.challenge.HighWatermark.PublisherPolicyEpoch = "2" },
		"local invalid counter": func(f *fixture) { f.challenge.HighWatermark.ReadKeyEpoch = "18446744073709551616" },
		"invalid floor genesis": func(f *fixture) { f.challenge.Floor = Floor{"0", strings.Repeat("1", 64)} },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(&f)
			head, err := verifyFixture(t, f, signProof(t, f, headDomain))
			wantRejected(t, head, err)
		})
	}
}

func TestCountersAndGenesis(t *testing.T) {
	for _, bad := range []string{"", "01", "-1", "1.0", "1e1", "18446744073709551616"} {
		for _, field := range []string{"head", "floor", "read", "policy", "witness"} {
			t.Run(field+bad, func(t *testing.T) {
				f := newFixture(t)
				switch field {
				case "head":
					f.proof.Body.Sequence = bad
				case "floor":
					f.proof.Body.FloorSequence = bad
				case "read":
					f.proof.Body.ReadKeyEpoch = bad
				case "policy":
					f.proof.Body.PublisherPolicyEpoch = bad
				case "witness":
					f.proof.Body.WitnessEpoch = bad
				}
				head, err := verifyFixture(t, f, signProof(t, f, headDomain))
				wantRejected(t, head, err)
			})
		}
	}
	f := newFixture(t)
	f.proof.Body.Sequence = "18446744073709551615"
	f.proof.Body.ReadKeyEpoch = "18446744073709551615"
	if _, err := verifyFixture(t, f, signProof(t, f, headDomain)); err != nil {
		t.Fatal("uint64 maximum rejected", err)
	}
	f = newFixture(t)
	f.trust.Checkpoint = Floor{"0", zeroHash}
	f.challenge.Floor = f.trust.Checkpoint
	f.challenge.HighWatermark = nil
	f.proof.Body.Sequence = "0"
	f.proof.Body.EnvelopeHash = zeroHash
	f.proof.Body.ReadKeyEpoch = "0"
	f.proof.Body.PublisherPolicyEpoch = "0"
	f.proof.Body.FloorSequence = "0"
	f.proof.Body.FloorHash = zeroHash
	if _, err := verifyFixture(t, f, signProof(t, f, headDomain)); err != nil {
		t.Fatal("proper pinned genesis rejected", err)
	}
	for _, field := range []string{"hash", "read", "policy"} {
		t.Run("invalid genesis "+field, func(t *testing.T) {
			g := f
			switch field {
			case "hash":
				g.proof.Body.EnvelopeHash = strings.Repeat("1", 64)
			case "read":
				g.proof.Body.ReadKeyEpoch = "1"
			case "policy":
				g.proof.Body.PublisherPolicyEpoch = "1"
			}
			head, err := verifyFixture(t, g, signProof(t, g, headDomain))
			wantRejected(t, head, err)
		})
	}
}

func TestNewBootstrapCanAdvanceOlderLocalCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.trust.Checkpoint = Floor{"2", strings.Repeat("2", 64)}
	f.challenge.Floor = f.trust.Checkpoint
	f.proof.Body.FloorSequence = "2"
	f.proof.Body.FloorHash = f.trust.Checkpoint.EnvelopeHash
	if _, err := verifyFixture(t, f, signProof(t, f, headDomain)); err != nil {
		t.Fatal("a stronger bootstrap floor rejected an older valid local constraint", err)
	}
	// A higher bootstrap floor never removes the older local epoch constraint.
	f.challenge.HighWatermark.ReadKeyEpoch = "3"
	head, err := verifyFixture(t, f, signProof(t, f, headDomain))
	wantRejected(t, head, err)
}

func TestUnsignedMutationAndSignatureEncoding(t *testing.T) {
	f := newFixture(t)
	raw := signProof(t, f, headDomain)
	for name, altered := range map[string][]byte{
		"signature bit":     bytes.Replace(raw, []byte(`"signature":"`), []byte(`"signature":"A`), 1),
		"unsigned context":  bytes.Replace(raw, []byte(f.trust.Scope.ViewID), []byte(f.trust.Scope.RealmID), 1),
		"unsigned head":     bytes.Replace(raw, []byte(`"sequence":"2"`), []byte(`"sequence":"3"`), 1),
		"missing signature": bytes.Replace(raw, []byte(`"signature":`), []byte(`"Signature":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			head, err := verifyFixture(t, f, altered)
			wantRejected(t, head, err)
		})
	}
}

func TestStrictWireAndSanitizedErrors(t *testing.T) {
	f := newFixture(t)
	raw := signProof(t, f, headDomain)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown top": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`{"body":`), []byte(`{"private_value":"never-expose","body":`), 1)
		},
		"duplicate top": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`{"body":`), []byte(`{"signature":"duplicate","body":`), 1)
		},
		"unknown nested": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"format":`), []byte(`"private_value":"never-expose","format":`), 1)
		},
		"duplicate nested": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"format":`), []byte(`"sequence":"1","format":`), 1)
		},
		"case collision": func(b []byte) []byte { return bytes.Replace(b, []byte(`"format":`), []byte(`"Format":`), 1) },
		"null body":      func(b []byte) []byte { return []byte(`{"body":null,"signature":"never-expose"}`) },
		"trailing json":  func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"oversize":       func(b []byte) []byte { return bytes.Repeat([]byte{' '}, e2e2.MaxHeadProofBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			head, err := verifyFixture(t, f, mutate(raw))
			wantRejected(t, head, err)
			if strings.Contains(err.Error(), "never-expose") || strings.Contains(err.Error(), f.proof.Body.RequestNonce) {
				t.Fatal("error contains input")
			}
		})
	}
}

func TestTrustPinnedAndImmutable(t *testing.T) {
	for name, change := range map[string]func(*Trust){
		"missing key": func(t *Trust) { t.PublicKey = nil },
		"zero key":    func(t *Trust) { t.PublicKey = make(ed25519.PublicKey, 32); t.KeyID = e2e2.KeyID(t.PublicKey) },
		"identity key": func(t *Trust) {
			t.PublicKey = make(ed25519.PublicKey, 32)
			t.PublicKey[0] = 1
			t.KeyID = e2e2.KeyID(t.PublicKey)
		},
		"wrong key id":                  func(t *Trust) { t.KeyID = "ed25519-sha256:" + strings.Repeat("a", 64) },
		"zero epoch":                    func(t *Trust) { t.WitnessEpoch = "0" },
		"overflow epoch":                func(t *Trust) { t.WitnessEpoch = "18446744073709551616" },
		"zero policy":                   func(t *Trust) { t.PublisherPolicyEpoch = "0" },
		"invalid scope":                 func(t *Trust) { t.Scope.LogID = "not-a-uuid" },
		"no checkpoint":                 func(t *Trust) { t.Checkpoint = Floor{} },
		"zero hash positive checkpoint": func(t *Trust) { t.Checkpoint.EnvelopeHash = zeroHash },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(&f.trust)
			if _, err := NewPinnedVerifier(f.trust); err == nil {
				t.Fatal("untrusted bootstrap accepted")
			}
		})
	}
	f := newFixture(t)
	raw := signProof(t, f, headDomain)
	v, err := NewPinnedVerifier(f.trust)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.trust.PublicKey {
		f.trust.PublicKey[i] = 0
	}
	if _, err = v.VerifyHead(context.Background(), f.challenge, raw); err != nil {
		t.Fatal("caller mutation changed pinned key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	head, err := v.VerifyHead(ctx, f.challenge, raw)
	wantRejected(t, head, err)
	var zero PinnedVerifier
	head, err = zero.VerifyHead(context.Background(), f.challenge, raw)
	wantRejected(t, head, err)
}
