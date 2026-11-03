//go:build linux

package provision

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExclusivePrivateFilesAndSafeReceipt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"role":"admin"}`)
	if os.WriteFile(filepath.Join(root, "request.json"), input, 0600) != nil {
		t.Fatal("request")
	}
	r, err := Run(context.Background(), "keygen", root, "request.json", "new-key", time.Now())
	if err != nil || !r.OfflineOnly || !r.OnlineVerificationRequired || r.Artifacts != 2 {
		t.Fatal("exclusive key generation", err)
	}
	path := filepath.Join(root, "new-key", "private.pem")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private mode")
	}
	if _, err = Run(context.Background(), "keygen", root, "request.json", "new-key", time.Now()); err == nil {
		t.Fatal("overwrite permitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("original key changed")
	}
}
func TestInputAndOutputFilesystemConfinement(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	input := filepath.Join(root, "request.json")
	os.WriteFile(input, []byte(`{"role":"node"}`), 0600)
	store, err := openFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.ReadFile("request.json", 2); err == nil {
		t.Fatal("oversized input accepted")
	}
	for _, p := range []string{"../escape", "/absolute", "a/../request.json", "a//request.json", "./request.json", "a\\request.json"} {
		if _, e := store.ReadFile(p, 100); e == nil {
			t.Fatal("path accepted")
		}
	}
	if err = os.Symlink(input, filepath.Join(root, "symlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ReadFile("symlink.json", 100); err == nil {
		t.Fatal("symlink input accepted")
	}
	if err = os.Link(input, filepath.Join(root, "hardlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ReadFile("request.json", 100); err == nil {
		t.Fatal("hardlinked original accepted")
	}
	if _, err = store.ReadFile("hardlink.json", 100); err == nil {
		t.Fatal("hardlinked input accepted")
	}
	os.Remove(filepath.Join(root, "hardlink.json"))
	os.Chmod(input, 0644)
	if _, err = store.ReadFile("request.json", 100); err == nil {
		t.Fatal("public readable private input")
	}
	os.Chmod(input, 0600)
	outside := t.TempDir()
	os.Chmod(outside, 0700)
	os.Symlink(outside, filepath.Join(root, "parent-link"))
	if err = store.WriteNew("parent-link/escape", artifacts{"key": []byte("synthetic")}); err == nil {
		t.Fatal("symlink parent output")
	}
	if _, err = os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatal("escaped output exists")
	}
	if err = store.WriteNew("../escape", artifacts{"key": []byte("synthetic")}); err == nil {
		t.Fatal("parent escape output")
	}
	if err = unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ReadFile("pipe", 100); err == nil {
		t.Fatal("FIFO accepted")
	}
	link := filepath.Join(t.TempDir(), "work-link")
	os.Symlink(root, link)
	if fs, e := openFiles(link); e == nil {
		fs.Close()
		t.Fatal("work root symlink accepted")
	}
}
