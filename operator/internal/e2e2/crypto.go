package e2e2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

type Expected struct {
	Scope                Scope
	Sequence             string
	EnvelopeHash         string
	ReadKeyEpoch         string
	PublisherPolicyEpoch string
	PublisherKeys        map[string]ed25519.PublicKey
}

// VerifiedEnvelope has no exported fields or successful zero value. It carries
// only a fully signature/context/hash-checked immutable envelope, not freshness.
// The caller must obtain Expected from independent verified witness authority.
type VerifiedEnvelope struct {
	verified        bool
	envelope        Envelope
	hash            string
	canonicalHeader []byte
	ciphertext      []byte
	nonce           []byte
	publisherKeys   map[string]ed25519.PublicKey
}

func (v *VerifiedEnvelope) Hash() string {
	if v == nil || !v.verified {
		return ""
	}
	return v.hash
}
func (v *VerifiedEnvelope) Header() Header {
	if v == nil || !v.verified {
		return Header{}
	}
	h := v.envelope.Body.Header
	h.Parents = append([]Parent{}, h.Parents...)
	if h.RestoredFrom != nil {
		copy := *h.RestoredFrom
		h.RestoredFrom = &copy
	}
	return h
}

func derive(key, salt []byte, name string, context []byte) ([]byte, error) {
	info := append(Domain(name), context...)
	derived, err := hkdf.Key(sha256.New, key, salt, string(info), 32)
	if err != nil {
		return nil, fail("CiphertextInvalid")
	}
	return derived, nil
}
func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fail("InvalidReadKey")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fail("CiphertextInvalid")
	}
	result, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fail("CiphertextInvalid")
	}
	return result, nil
}
func random(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, fail("RandomUnavailable")
	}
	return out, nil
}
func validPrivate(key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key)
}
func pinned(keys map[string]ed25519.PublicKey, id string) (ed25519.PublicKey, error) {
	public, ok := keys[id]
	if !ok || !ValidEd25519PublicKey(public) || KeyID(public) != id {
		return nil, fail("SignatureInvalid")
	}
	return public, nil
}

func EnvelopeHash(raw []byte) (string, error) {
	var envelope Envelope
	if err := DecodeStrict(raw, &envelope, MaxEnvelopeBytes); err != nil {
		return "", err
	}
	if err := validateEnvelopeShape(envelope); err != nil {
		return "", err
	}
	return hashEnvelope(envelope)
}
func hashEnvelope(envelope Envelope) (string, error) {
	canonical, err := marshal(envelope, MaxEnvelopeBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append(Domain("sekvyr-e2e2/envelope-hash/v1"), canonical...))
	return hex.EncodeToString(sum[:]), nil
}
func validateEnvelopeShape(envelope Envelope) error {
	if err := ValidateHeader(envelope.Body.Header); err != nil {
		return err
	}
	if _, err := DecodeBase64(envelope.Body.Nonce, 12); err != nil {
		return err
	}
	if _, err := DecodeBase64(envelope.Signature, 64); err != nil {
		return err
	}
	if len(envelope.Body.Ciphertext) > 12000000 {
		return fail("ResponseTooLarge")
	}
	raw, err := DecodeBase64(envelope.Body.Ciphertext, -1)
	if err != nil || len(raw) < 16 || len(raw) > MaxPlaintextBytes+16 {
		return fail("CiphertextInvalid")
	}
	return nil
}

func VerifyEnvelope(raw []byte, expected Expected) (*VerifiedEnvelope, error) {
	if !ValidScope(expected.Scope) || !nonzeroHash(expected.EnvelopeHash) {
		return nil, fail("ContextMismatch")
	}
	for _, value := range []string{expected.Sequence, expected.ReadKeyEpoch, expected.PublisherPolicyEpoch} {
		if _, err := Counter(value, false); err != nil {
			return nil, err
		}
	}
	var envelope Envelope
	if err := DecodeStrict(raw, &envelope, MaxEnvelopeBytes); err != nil {
		return nil, err
	}
	if err := validateEnvelopeShape(envelope); err != nil {
		return nil, err
	}
	h := envelope.Body.Header
	if h.Scope != expected.Scope || h.Sequence != expected.Sequence || h.ReadKeyEpoch != expected.ReadKeyEpoch || h.PublisherPolicyEpoch != expected.PublisherPolicyEpoch {
		return nil, fail("ContextMismatch")
	}
	public, err := pinned(expected.PublisherKeys, h.PublisherKeyID)
	if err != nil {
		return nil, err
	}
	body, err := marshal(envelope.Body, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	signature, _ := DecodeBase64(envelope.Signature, 64)
	if !ed25519.Verify(public, append(Domain("sekvyr-e2e2/publish/v1"), body...), signature) {
		return nil, fail("SignatureInvalid")
	}
	hash, err := hashEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if hash != expected.EnvelopeHash {
		return nil, fail("CanonicalSnapshotMismatch")
	}
	header, err := marshal(h, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	nonce, _ := DecodeBase64(envelope.Body.Nonce, 12)
	ciphertext, _ := DecodeBase64(envelope.Body.Ciphertext, -1)
	keys := make(map[string]ed25519.PublicKey, len(expected.PublisherKeys))
	for id, key := range expected.PublisherKeys {
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &VerifiedEnvelope{verified: true, envelope: envelope, hash: hash, canonicalHeader: header, ciphertext: ciphertext, nonce: nonce, publisherKeys: keys}, nil
}

func (v *VerifiedEnvelope) Decrypt(readKey []byte) (Plaintext, error) {
	if v == nil || !v.verified {
		return Plaintext{}, fail("VerificationRequired")
	}
	if len(readKey) != 32 {
		return Plaintext{}, fail("InvalidReadKey")
	}
	salt, _ := DecodeBase64(v.envelope.Body.Header.SnapshotSalt, 32)
	key, err := derive(readKey, salt, "sekvyr-e2e2/snapshot-key/v1", v.canonicalHeader)
	if err != nil {
		return Plaintext{}, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return Plaintext{}, err
	}
	raw, err := aead.Open(nil, v.nonce, v.ciphertext, append(Domain("sekvyr-e2e2/snapshot-aad/v1"), v.canonicalHeader...))
	if err != nil {
		return Plaintext{}, fail("CiphertextInvalid")
	}
	defer clear(raw)
	var plain Plaintext
	if err := DecodeStrict(raw, &plain, MaxPlaintextBytes); err != nil {
		return Plaintext{}, fail("InvalidPlaintext")
	}
	canonical, err := marshal(plain, MaxPlaintextBytes)
	if err != nil {
		return Plaintext{}, fail("InvalidPlaintext")
	}
	defer clear(canonical)
	if !bytes.Equal(raw, canonical) {
		return Plaintext{}, fail("InvalidPlaintext")
	}
	if err := ValidatePlaintext(plain); err != nil {
		return Plaintext{}, err
	}
	if plain.Context != v.envelope.Body.Header.Scope || len(plain.Entries) != v.envelope.Body.Header.EntryCount {
		return Plaintext{}, fail("SourceIncomplete")
	}
	return plain, nil
}

// SealSnapshot signs only the explicitly supplied reviewed full view. It never
// fetches a base, chooses a new revision, rebases or commits to a witness.
// Every call generates a new salt and nonce; staging retries must reuse its exact result.
func SealSnapshot(header Header, reviewed Plaintext, readKey []byte, publisher ed25519.PrivateKey) ([]byte, error) {
	if !validPrivate(publisher) {
		return nil, fail("InvalidPublisherKey")
	}
	if len(readKey) != 32 {
		return nil, fail("InvalidReadKey")
	}
	if err := ValidatePlaintext(reviewed); err != nil {
		return nil, err
	}
	if reviewed.Context != header.Scope || len(reviewed.Entries) != header.EntryCount || header.PublisherKeyID != KeyID(publisher.Public().(ed25519.PublicKey)) {
		return nil, fail("ContextMismatch")
	}
	salt, err := random(32)
	if err != nil {
		return nil, err
	}
	nonce, err := random(12)
	if err != nil {
		return nil, err
	}
	header.SnapshotSalt = encodeBase64(salt)
	if err := ValidateHeader(header); err != nil {
		return nil, err
	}
	headerRaw, err := marshal(header, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	plain, err := marshal(reviewed, MaxPlaintextBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	key, err := derive(readKey, salt, "sekvyr-e2e2/snapshot-key/v1", headerRaw)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, append(Domain("sekvyr-e2e2/snapshot-aad/v1"), headerRaw...))
	body := EnvelopeBody{Header: header, Nonce: encodeBase64(nonce), Ciphertext: encodeBase64(ciphertext)}
	bodyRaw, err := marshal(body, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(publisher, append(Domain("sekvyr-e2e2/publish/v1"), bodyRaw...))
	return marshal(Envelope{Body: body, Signature: encodeBase64(signature)}, MaxEnvelopeBytes)
}

// WrapReader binds the read key to the exact recipient, view, epochs and publisher.
// Recipient public-key approval and publication authority are explicit caller responsibilities.
func WrapReader(context WrapContext, readKey []byte, recipient *ecdh.PublicKey, publisher ed25519.PrivateKey) ([]byte, error) {
	if !validPrivate(publisher) || recipient == nil {
		return nil, fail("InvalidPublisherKey")
	}
	if len(readKey) != 32 {
		return nil, fail("InvalidReadKey")
	}
	if len(recipient.Bytes()) != 65 || recipient.Curve() != ecdh.P256() || context.RecipientFingerprint != RecipientFingerprint(recipient.Bytes()) || context.PublisherKeyID != KeyID(publisher.Public().(ed25519.PublicKey)) {
		return nil, fail("ContextMismatch")
	}
	if err := ValidateWrapContext(context); err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fail("RandomUnavailable")
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fail("InvalidReaderWrap")
	}
	defer clear(shared)
	salt, err := random(32)
	if err != nil {
		return nil, err
	}
	nonce, err := random(12)
	if err != nil {
		return nil, err
	}
	ctx, err := marshal(context, MaxReaderWrapBytes)
	if err != nil {
		return nil, err
	}
	key, err := derive(shared, salt, "sekvyr-e2e2/reader-wrap-key/v1", ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := marshal(ReaderPayload{Format: "sekvyr-e2e2-read-key-v1", Context: context, ReadKey: encodeBase64(readKey)}, MaxReaderPayloadBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	body := ReaderWrapBody{Context: context, EphemeralPublic: encodeBase64(ephemeral.PublicKey().Bytes()), Salt: encodeBase64(salt), Nonce: encodeBase64(nonce), Ciphertext: encodeBase64(aead.Seal(nil, nonce, plain, append(Domain("sekvyr-e2e2/reader-wrap-aad/v1"), ctx...)))}
	bodyRaw, err := marshal(body, MaxReaderWrapBytes)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(publisher, append(Domain("sekvyr-e2e2/reader-wrap-sign/v1"), bodyRaw...))
	return marshal(ReaderWrap{Body: body, Signature: encodeBase64(signature)}, MaxReaderWrapBytes)
}

func UnwrapReader(raw []byte, node *ecdh.PrivateKey, envelope *VerifiedEnvelope) ([]byte, error) {
	if envelope == nil || !envelope.verified {
		return nil, fail("VerificationRequired")
	}
	if node == nil || node.Curve() != ecdh.P256() || len(node.PublicKey().Bytes()) != 65 {
		return nil, fail("InvalidNodeKey")
	}
	var wrap ReaderWrap
	if err := DecodeStrict(raw, &wrap, MaxReaderWrapBytes); err != nil {
		return nil, err
	}
	if err := ValidateReaderWrap(wrap); err != nil {
		return nil, err
	}
	c := wrap.Body.Context
	h := envelope.envelope.Body.Header
	if c.Scope != h.Scope || c.ReadKeyEpoch != h.ReadKeyEpoch || c.PublisherPolicyEpoch != h.PublisherPolicyEpoch || c.RecipientFingerprint != RecipientFingerprint(node.PublicKey().Bytes()) {
		return nil, fail("ContextMismatch")
	}
	public, err := pinned(envelope.publisherKeys, c.PublisherKeyID)
	if err != nil {
		return nil, err
	}
	body, err := marshal(wrap.Body, MaxReaderWrapBytes)
	if err != nil {
		return nil, err
	}
	signature, _ := DecodeBase64(wrap.Signature, 64)
	if !ed25519.Verify(public, append(Domain("sekvyr-e2e2/reader-wrap-sign/v1"), body...), signature) {
		return nil, fail("SignatureInvalid")
	}
	// No ECDH or AES operation occurs until policy, recipient and signed context match.
	pubBytes, _ := DecodeBase64(wrap.Body.EphemeralPublic, 65)
	ephemeral, err := ecdh.P256().NewPublicKey(pubBytes)
	if err != nil {
		return nil, fail("InvalidReaderWrap")
	}
	shared, err := node.ECDH(ephemeral)
	if err != nil {
		return nil, fail("InvalidReaderWrap")
	}
	defer clear(shared)
	salt, _ := DecodeBase64(wrap.Body.Salt, 32)
	nonce, _ := DecodeBase64(wrap.Body.Nonce, 12)
	ciphertext, _ := DecodeBase64(wrap.Body.Ciphertext, -1)
	context, err := marshal(c, MaxReaderWrapBytes)
	if err != nil {
		return nil, err
	}
	key, err := derive(shared, salt, "sekvyr-e2e2/reader-wrap-key/v1", context)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, append(Domain("sekvyr-e2e2/reader-wrap-aad/v1"), context...))
	if err != nil || len(plain) > MaxReaderPayloadBytes {
		return nil, fail("CiphertextInvalid")
	}
	defer clear(plain)
	var payload ReaderPayload
	if err := DecodeStrict(plain, &payload, MaxReaderPayloadBytes); err != nil {
		return nil, fail("InvalidReaderWrap")
	}
	canonical, err := marshal(payload, MaxReaderPayloadBytes)
	if err != nil {
		return nil, fail("InvalidReaderWrap")
	}
	defer clear(canonical)
	if payload.Format != "sekvyr-e2e2-read-key-v1" || payload.Context != c || !bytes.Equal(plain, canonical) {
		return nil, fail("ContextMismatch")
	}
	readKey, err := DecodeBase64(payload.ReadKey, 32)
	if err != nil {
		return nil, fail("InvalidReadKey")
	}
	return readKey, nil
}
