// Package canon implements the subset of RFC 8785 (JSON Canonicalization
// Scheme) that replay packs use: strings, booleans, null, arrays, objects and
// integers in the IEEE-754 safe range. Fractional or exponent numbers are
// rejected rather than guessed at, so two implementations cannot disagree.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf16"
)

const maxSafe = 1<<53 - 1

// Canonicalize parses JSON and returns its JCS form.
func Canonicalize(in []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return Encode(v)
}

// Marshal encodes v with encoding/json, then canonicalises the result.
func Marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(b)
}

// Encode writes the JCS form of a value decoded with UseNumber (or built from
// map[string]any, []any, string, bool, nil, json.Number and Go integers).
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := canonInt(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case int:
		return encode(buf, json.Number(fmt.Sprint(t)))
	case int64:
		return encode(buf, json.Number(fmt.Sprint(t)))
	case uint64:
		return encode(buf, json.Number(fmt.Sprint(t)))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

func canonInt(s string) (string, error) {
	if strings.ContainsAny(s, ".eE") {
		return "", fmt.Errorf("canon: non-integer number %q not allowed", s)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return "", fmt.Errorf("canon: bad number %q", s)
	}
	if n.CmpAbs(big.NewInt(maxSafe)) > 0 {
		return "", fmt.Errorf("canon: integer %s outside safe range", s)
	}
	return n.String(), nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexdigits = "0123456789abcdef"

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexdigits[r>>4])
				buf.WriteByte(hexdigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
