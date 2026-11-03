package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

// All seeds and signatures in this test are deterministic PUBLIC reference
// material. They cannot be used as installation or runtime trust credentials.
func TestPublicPythonAuthorityProofV2Interoperability(t *testing.T) {
	var corpus struct {
		Format        string     `json:"format"`
		Scope         e2e2.Scope `json:"scope"`
		GenesisHash   string     `json:"genesis_hash"`
		PinnedWitness Key        `json:"pinned_witness"`
		WitnessEpoch  string     `json:"witness_epoch"`
		RequestNonce  string     `json:"request_nonce"`
		Floor         Cursor     `json:"floor"`
		Cases         []struct {
			Name  string          `json:"name"`
			Valid bool            `json:"go_valid"`
			Proof json.RawMessage `json:"proof"`
			Raw   string          `json:"raw_base64url"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile("../../tests/e2e2/public-authority-proof-corpus.json")
	if err != nil || json.Unmarshal(raw, &corpus) != nil || corpus.Format != "sekvyr-stage7-PUBLIC-authority-corpus-v1" || len(corpus.Cases) < 30 {
		t.Fatal("public authority fixture unavailable")
	}
	seed := sha256.Sum256([]byte("sekvyr-stage7-PUBLIC-authority-vector/witness"))
	private := ed25519.NewKeyFromSeed(seed[:])
	if e2e2.KeyID(private.Public().(ed25519.PublicKey)) != corpus.PinnedWitness.KeyID {
		t.Fatal("public independent pin differs")
	}
	seen := map[string]bool{}
	for _, item := range corpus.Cases {
		if seen[item.Name] || item.Name == "" {
			t.Fatal("public corpus has duplicate names")
		}
		seen[item.Name] = true
		t.Run(item.Name, func(t *testing.T) {
			raw := []byte(item.Proof)
			if item.Raw != "" {
				var err error
				raw, err = base64.RawURLEncoding.Strict().DecodeString(item.Raw)
				if err != nil {
					t.Fatal("public raw fixture encoding invalid")
				}
			}
			view, err := VerifyAuthorityProof(raw, corpus.Scope, corpus.GenesisHash, corpus.PinnedWitness, corpus.RequestNonce, corpus.Floor)
			accepted := err == nil && view.Authority.WitnessEpoch == corpus.WitnessEpoch
			if accepted != item.Valid {
				t.Fatalf("authority acceptance differs: accepted=%v, expected=%v", accepted, item.Valid)
			}
			if !accepted {
				return
			}
			var proof SignedAuthorityProof
			if DecodeStrict(raw, &proof, MaxAuthorityProofBytes) != nil {
				t.Fatal("accepted fixture cannot be decoded")
			}
			resigned, err := SignAuthorityProof(proof.Body, private)
			canonical, canonicalErr := e2e2.Canonical(raw, MaxAuthorityProofBytes)
			if err != nil || canonicalErr != nil || !bytes.Equal(resigned, canonical) {
				t.Fatal("Go/Python canonical signature bytes differ")
			}
		})
	}
}
