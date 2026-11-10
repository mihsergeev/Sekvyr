package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/provision"
)

func TestNoArgumentOrErrorDisclosure(t *testing.T) {
	for _, args := range [][]string{{}, {"keygen", "--private-key=synthetic-secret-canary"}, {"discover", "--work-dir=/unused", "--input=x", "--output=y"}} {
		var out bytes.Buffer
		err := run(args, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "synthetic-secret-canary") {
			t.Fatal("argument/error disclosure")
		}
	}
	var out bytes.Buffer
	if run([]string{"version"}, &out) != nil || out.String() != provision.Version+"\n" {
		t.Fatal("version")
	}
}
