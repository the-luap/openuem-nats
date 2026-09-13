package netbirdcommand

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// All protocol fields are required, including explicitly empty strings and
// false booleans. Reject duplicate/case-alias keys, null, unknown fields, invalid
// UTF-8 and trailing documents before the typed decoder can normalize them.
func decode(data []byte, fields []string, out any) error {
	if len(data) == 0 || len(data) > MaxMessage || !utf8.Valid(data) {
		return ErrInvalid
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return ErrInvalid
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrInvalid
		}
	}
	if len(seen) != len(fields) {
		return ErrInvalid
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalid
	}
	if err = json.Unmarshal(data, out); err != nil {
		return ErrInvalid
	}
	return nil
}

func Decode(data []byte) (Command, error) {
	var c Command
	// The preliminary read selects a schema only. The complete strict decoder
	// below still rejects duplicate/aliased versions and every unknown field.
	var header struct {
		Version int `json:"version"`
	}
	if len(data) > MaxMessage || json.Unmarshal(data, &header) != nil {
		return Command{}, ErrInvalid
	}
	fields := []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "management_url", "profile", "issued_at", "expires_at"}
	if header.Version == RegistrationVersion {
		fields = append(fields, "setup_key")
	}
	if err := decode(data, fields, &c); err != nil || !c.Valid() {
		return Command{}, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

func DecodeReceipt(data []byte) (Receipt, error) {
	var r Receipt
	if err := decode(data, []string{"version", "request_id", "device_id", "revision", "command_hash", "operation", "status"}, &r); err != nil || !r.Valid() {
		return Receipt{}, ErrInvalid
	}
	return r, nil
}
