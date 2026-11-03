package main

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestNamespaceAndSecretCacheIsolation(t *testing.T) {
	options := managerOptions("test-system", "test-leader", "0", ":8081")
	if len(options.Cache.DefaultNamespaces) != 1 {
		t.Fatal("namespace cache scope missing")
	}
	if _, ok := options.Cache.DefaultNamespaces["test-system"]; !ok {
		t.Fatal("wrong cache namespace")
	}
	if !options.Cache.ReaderFailOnMissingInformer {
		t.Fatal("automatic informer creation enabled")
	}
	if options.Client.Cache == nil || len(options.Client.Cache.DisableFor) != 1 {
		t.Fatal("Secret cache not disabled")
	}
	if _, ok := options.Client.Cache.DisableFor[0].(*corev1.Secret); !ok {
		t.Fatal("Secret cache not disabled")
	}
	if !options.LeaderElection || options.LeaderElectionNamespace != "test-system" || options.LeaderElectionID != "test-leader" {
		t.Fatal("leader Lease scope missing")
	}
	if options.Metrics.BindAddress != "0" {
		t.Fatal("metrics unexpectedly exposed")
	}
}
