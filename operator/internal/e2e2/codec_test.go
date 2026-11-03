package e2e2

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRestrictedCanonicalScalars(t *testing.T) {
	raw, err := os.ReadFile("../../tests/e2e2/public-reader-wrap-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Unicode   json.RawMessage `json:"unicode_case"`
		Canonical string          `json:"unicode_canonical_base64url"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid public fixture")
	}
	want, err := DecodeBase64(vector.Canonical, -1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Canonical(vector.Unicode, 4096)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("Unicode scalar JCS differs from independent reference")
	}
	for _, raw := range []string{`{"b":"<>&\u2028\u2029","a":"\ud834\udd1e"}`, `{"a":"𝄞","b":"<>&` + "\u2028\u2029" + `"}`} {
		got, err := Canonical([]byte(raw), 4096)
		if err != nil || !bytes.Equal(got, []byte(`{"a":"𝄞","b":"<>&`+"\u2028\u2029"+`"}`)) {
			t.Fatal("canonical Unicode escaped differently")
		}
	}
}
func TestRestrictedJSONRejectsAmbiguity(t *testing.T) {
	for _, raw := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud800\u0061"}`, `{"a":"\udc00\ud800"}`,
		`{"a":1.0}`, `{"a":1e0}`, `{"a":-0}`, `{"a":-1}`, `{"a":NaN}`, `{"a":9007199254740992}`, `{"a":01}`,
		`{"é":1}`, `{"a":1} {"b":2}`, "\xef\xbb\xbf{}", "{\"a\":\"\xff\"}", strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1),
	} {
		if _, err := Canonical([]byte(raw), 65536); err == nil {
			t.Fatal("ambiguous/non-profile JSON accepted")
		}
	}
	if _, err := Canonical([]byte(`{"a":1}`), 2); err == nil {
		t.Fatal("oversized JSON accepted")
	}
}
func TestStrictRequiredCaseAndNullable(t *testing.T) {
	valid := `{"format":"sekvyr-e2e2-values-v1","context":{"realm_id":"r","project_id":"p","environment_id":"e","view_id":"v","log_id":"l"},"entries":[]}`
	var p Plaintext
	if DecodeStrict([]byte(valid), &p, 4096) != nil {
		t.Fatal("typed shape refused before semantic validation")
	}
	for _, bad := range []string{
		strings.Replace(valid, `"format"`, `"Format"`, 1), strings.Replace(valid, `"entries":[]`, `"entries":null`, 1), strings.Replace(valid, `"entries":[]`, `"entries":"[]"`, 1), strings.Replace(valid, `,"entries":[]`, "", 1), strings.Replace(valid, `"log_id":"l"`, `"other_id":"l"`, 1), strings.Replace(valid, `"log_id":"l"`, `"log_id":null`, 1), strings.Replace(valid, `"entries":[]`, `"entries":[],"other":1`, 1),
	} {
		if DecodeStrict([]byte(bad), &p, 4096) == nil {
			t.Fatal("unknown/missing/null/wrong-type field accepted")
		}
	}
}
func TestCanonicalCountersAndBinary(t *testing.T) {
	for _, s := range []string{"1", "18446744073709551615"} {
		if _, err := Counter(s, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"", "0", "01", "+1", "1e0", "1.0", "18446744073709551616", " 1"} {
		if _, err := Counter(s, false); err == nil {
			t.Fatal("invalid counter accepted")
		}
	}
	if n, err := Counter("0", true); err != nil || n != 0 {
		t.Fatal("genesis zero refused")
	}
	for _, s := range []string{"AA=", "AA\n", "AA ", "AB", "A+", "A/", "A"} {
		if _, err := DecodeBase64(s, 1); err == nil {
			t.Fatal("noncanonical base64url accepted")
		}
	}
	if raw, err := DecodeBase64("AA", 1); err != nil || !bytes.Equal(raw, []byte{0}) {
		t.Fatal("canonical base64url refused")
	}
}
