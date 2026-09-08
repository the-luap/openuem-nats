// Package strictjson decodes unambiguous bounded protocol documents.
// Callers enforce document-size limits before calling Unmarshal.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid protocol JSON")

// JSON field ambiguity is rejected even when the duplicate repeats the same
// value. This keeps signing tools, the console and endpoint parsers consistent.
func Unmarshal(data []byte, target any) error {
	if !utf8.Valid(data) {
		return ErrInvalid
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(scan, 0); err != nil {
		return ErrInvalid
	}
	if _, err := scan.Token(); err != io.EOF {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	return nil
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || !canonicalField(name) || keys[name] {
				return ErrInvalid
			}
			keys[name] = true
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	_, err = decoder.Token()
	return err
}

func canonicalField(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
