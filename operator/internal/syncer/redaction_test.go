package syncer

import (
	"fmt"
	"strings"
	"testing"
)

func TestVerifiedRolloutValuesCannotEscapeThroughFormatting(t *testing.T) {
	marker := "synthetic-private-config-value"
	guard := &rolloutGuard{data: map[string][]byte{"CONFIG": []byte(marker)}}
	result := Result{RolloutGuard: guard}
	for _, value := range []any{guard, *guard, result, &result} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, value)
			for _, forbidden := range []string{marker, fmt.Sprintf("%v", []byte(marker)), fmt.Sprintf("%#v", []byte(marker))} {
				if strings.Contains(printed, forbidden) {
					t.Fatal("verified configuration escaped result redaction")
				}
			}
			if !strings.Contains(printed, "[redacted]") {
				t.Fatal("missing guard/result redaction")
			}
		}
	}
}
