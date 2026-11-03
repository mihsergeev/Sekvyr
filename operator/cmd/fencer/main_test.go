package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/mihsergeev/Sekvyr/operator/internal/fencing"
)

func TestBootstrapFailureReportsSafeReasonAndRedactsUpstream(t *testing.T) {
	if got := bootstrapFailure(&fencing.Error{Reason: "MaterialReplaced"}).Error(); got != "fencer: MaterialReplaced" {
		t.Fatal("public reason lost")
	}
	upstream := strings.Repeat("sensitive-upstream-", 4)
	if got := bootstrapFailure(errors.New(upstream)).Error(); got != "fencer: FencingUnavailable" || strings.Contains(got, upstream) {
		t.Fatal("raw upstream details leaked")
	}
}
