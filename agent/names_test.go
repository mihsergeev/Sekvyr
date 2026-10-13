package main

import (
	"strings"
	"testing"
)

func TestBadName(t *testing.T) {
	for _, name := range []string{"DB_URL", "spring.datasource.url", "dash-key", "ключ", "1START"} {
		if badName(name) {
			t.Errorf("%q should be allowed: docker compose reads it", name)
		}
	}
	for _, name := range []string{"", "KEY WITH SPACE", "TAB\tKEY", "A=B", "LINE\nBREAK", "#COMMENT", "NUL\x00"} {
		if !badName(name) {
			t.Errorf("%q should be refused: it breaks the file", name)
		}
	}
}

func TestRenderSkipsBadNames(t *testing.T) {
	text, skipped := renderEnv([]value{
		{Name: "GOOD", Value: "1", Path: "/"},
		{Name: "BAD NAME", Value: "2", Path: "/"},
		{Name: "INJECTED\nEVIL", Value: "3", Path: "/"},
	})
	if text != "GOOD=1\n" {
		t.Fatalf("got %q", text)
	}
	if len(skipped) != 2 || !strings.Contains(strings.Join(skipped, ","), "BAD NAME") {
		t.Fatalf("skipped %q", skipped)
	}
}
