package main

import (
	"crypto/ecdh"
	"path/filepath"
	"testing"
)

func TestConcurrentNodeKeyInitializationKeepsOneIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SEKVYR_NODE_KEY", filepath.Join(dir, "node.key"))
	config := filepath.Join(dir, "agent.json")
	type result struct {
		key *ecdh.PrivateKey
		err error
	}
	const callers = 32
	start := make(chan struct{})
	results := make(chan result, callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			key, err := nodeKey(config)
			results <- result{key, err}
		}()
	}
	close(start)
	var keys []*ecdh.PrivateKey
	for i := 0; i < callers; i++ {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		keys = append(keys, got.key)
	}
	stored, err := nodeKey(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !key.Equal(stored) {
			t.Fatal("a caller used a different node key from the persisted identity")
		}
	}
}
