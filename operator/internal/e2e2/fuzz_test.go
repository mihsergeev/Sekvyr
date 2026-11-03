package e2e2_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/mihsergeev/Sekvyr/operator/internal/e2e2"
)

// The parser consumes hostile wire bytes. Successful canonicalization must be
// valid scalar UTF-8 JSON and idempotent under this restricted profile.
func FuzzCanonicalRestricted(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`{"value":"<>&\u2028\u2029\ud834\udd1e","count":1}`), []byte(`{"x":1,"\u0078":2}`), []byte(`{"value":"\ud800"}`), []byte(`{"count":1e0}`), []byte(`{"count":18446744073709551616}`), []byte(`[{"a":[true,null,"text"]}]`), {0xff, 0xfe}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		canonical, err := e2e2.Canonical(raw, 64<<10)
		if err != nil {
			return
		}
		if !utf8.Valid(canonical) || !json.Valid(canonical) {
			t.Fatal("canonical output is not scalar UTF-8 JSON")
		}
		again, err := e2e2.Canonical(canonical, 64<<10)
		if err != nil || !bytes.Equal(canonical, again) {
			t.Fatal("canonicalization changed its own output")
		}
	})
}
