package journal

import (
	"crypto/ed25519"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

const MaxAuthorityProofBytes = (1 << 20) + (64 << 10)
const AuthorityProofDomain = "sekvyr-e2e2/authority-proof/v2"

type AuthorityView struct {
	Scope           e2e2.Scope            `json:"scope"`
	GenesisHash     string                `json:"genesis_hash"`
	Cursor          Cursor                `json:"cursor"`
	Snapshot        Snapshot              `json:"snapshot"`
	Authority       Authority             `json:"authority"`
	AuthorityDigest string                `json:"authority_digest"`
	Enrollments     map[string]Enrollment `json:"enrollments"`
}
type AuthorityProofBody struct {
	Format       string        `json:"format"`
	State        AuthorityView `json:"state"`
	RequestNonce string        `json:"request_nonce"`
	Floor        Cursor        `json:"floor"`
}
type SignedAuthorityProof struct {
	Body      AuthorityProofBody `json:"body"`
	KeyID     string             `json:"key_id"`
	Signature string             `json:"signature"`
}

func (s CurrentState) AuthorityView() AuthorityView {
	return AuthorityView{Scope: s.Scope, GenesisHash: s.GenesisHash, Cursor: s.Cursor, Snapshot: s.Snapshot, Authority: s.Authority, AuthorityDigest: s.AuthorityDigest, Enrollments: s.Enrollments}
}
func SignAuthorityProof(body AuthorityProofBody, private ed25519.PrivateKey) ([]byte, error) {
	if !validProofBody(body) || len(private) != ed25519.PrivateKeySize || body.State.Authority.WitnessKey.KeyID != e2e2.KeyID(private.Public().(ed25519.PublicKey)) {
		return nil, Failure("SigningKeyMismatch")
	}
	signature, err := signValue(AuthorityProofDomain, body, private, MaxAuthorityProofBytes)
	if err != nil {
		return nil, err
	}
	return canonical(SignedAuthorityProof{Body: body, KeyID: body.State.Authority.WitnessKey.KeyID, Signature: signature}, MaxAuthorityProofBytes)
}
func validProofBody(body AuthorityProofBody) bool {
	view := body.State
	if body.Format != "sekvyr-authority-proof-v2" || !e2e2.ValidScope(view.Scope) || !validHash(view.GenesisHash, false) || !validCursor(view.Cursor) || !validCursor(body.Floor) || !validAuthority(view.Authority) || view.Enrollments == nil || len(view.Enrollments) > 64 {
		return false
	}
	if _, err := e2e2.DecodeBase64(body.RequestNonce, 32); err != nil {
		return false
	}
	for id, enrollment := range view.Enrollments {
		if id != enrollment.InstallationID || !validEnrollment(enrollment) {
			return false
		}
	}
	state := CurrentState{Scope: view.Scope, GenesisHash: view.GenesisHash, Authority: view.Authority, Enrollments: view.Enrollments}
	digest, err := authorityDigest(state)
	if err != nil || digest != view.AuthorityDigest {
		return false
	}
	seq, err := e2e2.Counter(view.Snapshot.Sequence, true)
	if err != nil || !validHash(view.Snapshot.EnvelopeHash, true) || (seq == 0) != (view.Snapshot.EnvelopeHash == ZeroHash) {
		return false
	}
	if seq == 0 {
		return view.Snapshot.ReadKeyEpoch == "0" && view.Snapshot.PublisherPolicyEpoch == "0"
	}
	return view.Snapshot.ReadKeyEpoch == view.Authority.ReadKeyEpoch && view.Snapshot.PublisherPolicyEpoch == view.Authority.PublisherPolicyEpoch
}
func VerifyAuthorityProof(raw []byte, scope e2e2.Scope, genesisHash string, pinnedWitness Key, nonce string, floor Cursor) (AuthorityView, error) {
	var proof SignedAuthorityProof
	if DecodeStrict(raw, &proof, MaxAuthorityProofBytes) != nil || !validProofBody(proof.Body) || proof.Body.State.Scope != scope || proof.Body.State.GenesisHash != genesisHash || proof.Body.State.Authority.WitnessKey != pinnedWitness || proof.Body.RequestNonce != nonce || proof.Body.Floor != floor || verifyValue(AuthorityProofDomain, proof.Body, proof.KeyID, proof.Signature, pinnedWitness, MaxAuthorityProofBytes) != nil {
		return AuthorityView{}, Failure("AuthorityProofInvalid")
	}
	seq, _ := e2e2.Counter(proof.Body.State.Cursor.JournalSequence, true)
	minimum, err := e2e2.Counter(floor.JournalSequence, true)
	if err != nil || seq < minimum || seq == minimum && proof.Body.State.Cursor.RecordHash != floor.RecordHash {
		return AuthorityView{}, Failure("AuthorityProofRollback")
	}
	return proof.Body.State, nil
}
