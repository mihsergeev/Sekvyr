// Package e2e2 implements the explicitly selected whole-view protocol only.
// It performs no network requests, persistence, publication retries or trust discovery.
package e2e2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxEnvelopeBytes      = 16 * 1024 * 1024
	MaxPlaintextBytes     = 8 * 1024 * 1024
	MaxReaderWrapBytes    = 16 * 1024
	MaxReaderPayloadBytes = 2048
	MaxHeadProofBytes     = 16 * 1024
	MaxEntries            = 1024
	MaxParents            = 16
	MaxDepth              = 16
)

// Error exposes a fixed reason only, never input, values, keys or upstream bodies.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }
func fail(reason string) error { return &Error{Reason: reason} }

// Domain appends the protocol's mandatory NUL separator.
func Domain(name string) []byte { return append([]byte(name), 0) }

// DecodeBase64 accepts only canonical unpadded Base64url. size < 0 permits a bounded caller-validated length.
func DecodeBase64(raw string, size int) ([]byte, error) {
	for _, c := range []byte(raw) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, fail("InvalidEncoding")
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || (size >= 0 && len(decoded) != size) || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, fail("InvalidEncoding")
	}
	return decoded, nil
}
func encodeBase64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func Counter(raw string, allowZero bool) (uint64, error) {
	if len(raw) == 0 || len(raw) > 20 || (len(raw) > 1 && raw[0] == '0') {
		return 0, fail("InvalidCounter")
	}
	for _, c := range []byte(raw) {
		if c < '0' || c > '9' {
			return 0, fail("InvalidCounter")
		}
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || (!allowZero && value == 0) {
		return 0, fail("InvalidCounter")
	}
	return value, nil
}

// Canonical implements the restricted JCS profile: fixed ASCII property names,
// scalar Unicode strings, booleans/null and nonnegative safe integer JSON numbers.
// Typed protocol decoders additionally enforce exact known shape and semantics.
func Canonical(raw []byte, max int) ([]byte, error) {
	value, err := parse(raw, max)
	if err != nil {
		return nil, err
	}
	return emit(nil, value), nil
}

func marshal(value any, max int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fail("InvalidJSON")
	}
	return Canonical(raw, max)
}

// DecodeStrict requires every field, exact case, exact types and no unknown fields.
// Only Header.restored_from is nullable. This function does not replace semantic validation.
func DecodeStrict(raw []byte, out any, max int) error {
	value, err := parse(raw, max)
	if err != nil {
		return err
	}
	typeOf := reflect.TypeOf(out)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return fail("InvalidShape")
	}
	if !shape(value, typeOf.Elem(), false) {
		return fail("InvalidShape")
	}
	if json.Unmarshal(emit(nil, value), out) != nil {
		return fail("InvalidShape")
	}
	return nil
}

func shape(value any, expected reflect.Type, nullable bool) bool {
	if expected.Kind() == reflect.Pointer {
		if value == nil {
			return nullable
		}
		return shape(value, expected.Elem(), false)
	}
	if value == nil {
		return false
	}
	switch expected.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.StructField{}
		if !structFields(expected, fields) || len(object) != len(fields) {
			return false
		}
		for name, field := range fields {
			v, exists := object[name]
			if !exists || !shape(v, field.Type, name == "restored_from" && expected == reflect.TypeOf(Header{})) {
				return false
			}
		}
		return true
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, v := range array {
			if !shape(v, expected.Elem(), false) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint32, reflect.Uint64:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}
func structFields(t reflect.Type, fields map[string]reflect.StructField) bool {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			if f.Type.Kind() != reflect.Struct || !structFields(f.Type, fields) {
				return false
			}
			continue
		}
		if tag == "" || fields[tag].Name != "" {
			return false
		}
		fields[tag] = f
	}
	return true
}

func parse(raw []byte, max int) (any, error) {
	if max <= 0 || len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, fail("InvalidJSON")
	}
	if !scalarStrings(raw) {
		return nil, fail("InvalidJSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > MaxDepth || nodes > 16384 {
			return nil, fail("InvalidJSON")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, fail("InvalidJSON")
		}
		if number, ok := token.(json.Number); ok {
			v, err := Counter(string(number), true)
			if err != nil || v > 9007199254740991 {
				return nil, fail("InvalidJSON")
			}
			return number, nil
		}
		delim, nested := token.(json.Delim)
		if !nested {
			return token, nil
		}
		switch delim {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fail("InvalidJSON")
				}
				key, ok := keyToken.(string)
				if !ok || len(object) >= 64 {
					return nil, fail("InvalidJSON")
				}
				for _, r := range key {
					if r < 0x20 || r > 0x7e {
						return nil, fail("InvalidJSON")
					}
				}
				if _, exists := object[key]; exists {
					return nil, fail("InvalidJSON")
				}
				v, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = v
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fail("InvalidJSON")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= 4096 {
					return nil, fail("InvalidJSON")
				}
				v, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, v)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fail("InvalidJSON")
			}
			return array, nil
		default:
			return nil, fail("InvalidJSON")
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fail("InvalidJSON")
	}
	return value, nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them before decoding.
func scalarStrings(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for ; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return false
			}
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return false
			}
			v, ok := hex4(raw[i+1 : i+5])
			if !ok {
				return false
			}
			i += 4
			if v >= 0xd800 && v <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low, ok := hex4(raw[i+3 : i+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			} else if v >= 0xdc00 && v <= 0xdfff {
				return false
			}
		}
		if i >= len(raw) {
			return false
		}
	}
	return true
}
func hex4(raw []byte) (uint16, bool) {
	var value uint16
	for _, c := range raw {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			value += uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}

func emit(out []byte, value any) []byte {
	switch v := value.(type) {
	case nil:
		return append(out, "null"...)
	case bool:
		if v {
			return append(out, "true"...)
		}
		return append(out, "false"...)
	case string:
		return emitString(out, v)
	case json.Number:
		return append(out, string(v)...)
	case []any:
		out = append(out, '[')
		for i, item := range v {
			if i > 0 {
				out = append(out, ',')
			}
			out = emit(out, item)
		}
		return append(out, ']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out = append(out, '{')
		for i, key := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			out = emitString(out, key)
			out = append(out, ':')
			out = emit(out, v[key])
		}
		return append(out, '}')
	default:
		panic("unreachable canonical node")
	}
}
func emitString(out []byte, value string) []byte {
	const digits = "0123456789abcdef"
	out = append(out, '"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out = append(out, '\\', byte(r))
		case '\b':
			out = append(out, '\\', 'b')
		case '\t':
			out = append(out, '\\', 't')
		case '\n':
			out = append(out, '\\', 'n')
		case '\f':
			out = append(out, '\\', 'f')
		case '\r':
			out = append(out, '\\', 'r')
		default:
			if r < 0x20 {
				out = append(out, '\\', 'u', '0', '0', digits[byte(r)>>4], digits[byte(r)&15])
			} else {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return append(out, '"')
}
