package e2e2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
)

func TestPinnedEd25519PrimeSubgroup(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidEd25519PublicKey(public) {
		t.Fatal("real generated key rejected")
	}
	v := fixtureVector(t)
	vector, _ := DecodeBase64(v.Publisher, 32)
	if !ValidEd25519PublicKey(ed25519.PublicKey(vector)) {
		t.Fatal("public reference key rejected")
	}
	identity := make([]byte, 32)
	identity[0] = 1
	orderTwo := bytes.Repeat([]byte{0xff}, 32)
	orderTwo[0] = 0xec
	orderTwo[31] = 0x7f
	noncanonical := bytes.Repeat([]byte{0xff}, 32)
	noncanonical[0] = 0xed
	noncanonical[31] = 0x7f
	negativeZero := append([]byte(nil), identity...)
	negativeZero[31] = 0x80
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 32), identity, orderTwo, noncanonical, negativeZero} {
		if ValidEd25519PublicKey(ed25519.PublicKey(bad)) {
			t.Fatal("invalid/noncanonical/small-order public key accepted")
		}
	}
	point, err := new(edwards25519.Point).SetBytes(public)
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(orderTwo)
	if err != nil {
		t.Fatal(err)
	}
	mixed := new(edwards25519.Point).Add(point, torsion).Bytes()
	if ValidEd25519PublicKey(ed25519.PublicKey(mixed)) {
		t.Fatal("mixed-torsion trust key accepted")
	}
}
func TestHeadProofGenesisAndEpochRules(t *testing.T) {
	proof := fixtureVector(t).Proof
	for _, change := range []func(*HeadProof){
		func(p *HeadProof) { p.Body.WitnessEpoch = "0" }, func(p *HeadProof) { p.Body.ReadKeyEpoch = "0" }, func(p *HeadProof) { p.Body.PublisherPolicyEpoch = "0" }, func(p *HeadProof) { p.Body.FloorSequence = "3" }, func(p *HeadProof) { p.Body.FloorSequence = p.Body.Sequence; p.Body.FloorHash = ZeroHash }, func(p *HeadProof) { p.Body.Sequence = "18446744073709551616" },
	} {
		copy := proof
		change(&copy)
		if ValidateHeadProof(copy) == nil {
			t.Fatal("invalid head metadata accepted")
		}
	}
	proof.Body.Sequence = "0"
	proof.Body.EnvelopeHash = ZeroHash
	proof.Body.ReadKeyEpoch = "0"
	proof.Body.PublisherPolicyEpoch = "0"
	proof.Body.FloorSequence = "0"
	proof.Body.FloorHash = ZeroHash
	if err := ValidateHeadProof(proof); err != nil {
		t.Fatal("valid registration genesis refused", err)
	}
	proof.Body.ReadKeyEpoch = "1"
	if ValidateHeadProof(proof) == nil {
		t.Fatal("genesis with nonzero read epoch accepted")
	}
}
