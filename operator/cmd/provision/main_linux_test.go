//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/provision"
)

func TestCLIKeygenAndPublicUseExclusiveSecureFiles(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private directory")
	}
	if os.WriteFile(filepath.Join(root, "request"), []byte(`{"role":"node"}`), 0600) != nil {
		t.Fatal("request")
	}
	var output bytes.Buffer
	if err := run([]string{"keygen", "--work-dir", root, "--input", "request", "--output", "node"}, &output); err != nil {
		t.Fatal(err)
	}
	var receipt provision.Receipt
	if json.Unmarshal(output.Bytes(), &receipt) != nil || !receipt.OfflineOnly || receipt.Operation != "keygen" || receipt.Artifacts != 2 {
		t.Fatal("unsafe receipt")
	}
	if strings.Contains(output.String(), "PRIVATE KEY") || strings.Contains(output.String(), root) {
		t.Fatal("private output")
	}
	if os.WriteFile(filepath.Join(root, "public-request"), []byte(`{"role":"node","private_file":"node/private.pem"}`), 0600) != nil {
		t.Fatal("request")
	}
	output.Reset()
	if err := run([]string{"public", "--work-dir", root, "--input", "public-request", "--output", "public-copy"}, &output); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(filepath.Join(root, "node", "public.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "public-copy", "public.json"))
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("public descriptor roundtrip")
	}
	output.Reset()
	if run([]string{"keygen", "--work-dir", root, "--input", "request", "--output", "node"}, &output) == nil || output.Len() != 0 {
		t.Fatal("overwrite/error disclosure")
	}
}
