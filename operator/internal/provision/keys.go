package provision

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
	"github.com/mihsergeev/Sekvyr/operator/internal/journal"
)

func edRole(role string) bool {
	return role == "admin" || role == "publisher" || role == "witness" || role == "fencer"
}
func descriptor(role string, key any) (PublicKey, error) {
	result := PublicKey{Format: "sekvyr-provision-public-key-v1", Role: role}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if !edRole(role) || len(k) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(k[:32]), k) {
			return result, ErrInvalid
		}
		pub := k.Public().(ed25519.PublicKey)
		if !e2e2.ValidEd25519PublicKey(pub) {
			return result, ErrInvalid
		}
		result.KeyID = e2e2.KeyID(pub)
		result.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	case *ecdh.PrivateKey:
		if role != "node" || k.Curve() != ecdh.P256() {
			return result, ErrInvalid
		}
		result.KeyID = e2e2.RecipientFingerprint(k.PublicKey().Bytes())
		result.PublicKey = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	default:
		return result, ErrInvalid
	}
	return result, nil
}
func parsePrivate(raw []byte) (any, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, ErrInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalid
	}
	if k, ok := key.(*ecdsa.PrivateKey); ok {
		converted, err := k.ECDH()
		if err != nil || converted.Curve() != ecdh.P256() {
			return nil, ErrInvalid
		}
		return converted, nil
	}
	return key, nil
}
func edKey(f files, path string) (ed25519.PrivateKey, error) {
	b, err := f.ReadFile(path, 16<<10)
	if err != nil {
		return nil, ErrFiles
	}
	defer clear(b)
	k, err := parsePrivate(b)
	if err != nil {
		return nil, err
	}
	p, ok := k.(ed25519.PrivateKey)
	if !ok || len(p) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(p[:32]), p) {
		return nil, ErrInvalid
	}
	return p, nil
}
func publicFile(f files, path, role string) (PublicKey, error) {
	var d PublicKey
	if decodeFile(f, path, &d, 4096) != nil || d.Format != "sekvyr-provision-public-key-v1" || d.Role != role {
		return d, ErrInvalid
	}
	if role == "node" {
		raw, err := e2e2.DecodeBase64(d.PublicKey, 65)
		if err != nil {
			return d, ErrInvalid
		}
		p, err := ecdh.P256().NewPublicKey(raw)
		if err != nil || e2e2.RecipientFingerprint(p.Bytes()) != d.KeyID {
			return d, ErrInvalid
		}
	} else {
		raw, err := e2e2.DecodeBase64(d.PublicKey, 32)
		if !edRole(role) || err != nil || !e2e2.ValidEd25519PublicKey(raw) || e2e2.KeyID(raw) != d.KeyID {
			return d, ErrInvalid
		}
	}
	return d, nil
}
func (d PublicKey) journalKey() journal.Key {
	return journal.Key{KeyID: d.KeyID, PublicKey: d.PublicKey}
}
func keygen(role string) (artifacts, error) {
	if role == "read" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, ErrInvalid
		}
		return artifacts{"read-key.bin": key}, nil
	}
	var key any
	if edRole(role) {
		_, p, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, ErrInvalid
		}
		key = p
	} else if role == "node" {
		p, e := ecdh.P256().GenerateKey(rand.Reader)
		if e != nil {
			return nil, ErrInvalid
		}
		key = p
	} else {
		return nil, ErrInvalid
	}
	d, err := descriptor(role, key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(der)
	pub, err := encode(d, 4096)
	if err != nil {
		return nil, err
	}
	return artifacts{"private.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "public.json": pub}, nil
}
func publicArtifact(f files, r PublicRequest) (artifacts, error) {
	b, err := f.ReadFile(r.PrivateFile, 16<<10)
	if err != nil {
		return nil, ErrFiles
	}
	defer clear(b)
	k, err := parsePrivate(b)
	if err != nil {
		return nil, err
	}
	d, err := descriptor(r.Role, k)
	if err != nil {
		return nil, err
	}
	pub, err := encode(d, 4096)
	if err != nil {
		return nil, err
	}
	return artifacts{"public.json": pub}, nil
}
