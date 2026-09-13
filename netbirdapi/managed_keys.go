package netbirdapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const ManagedKeyLifetime = 24 * time.Hour
const MaxManagedGroups = 100

type ManagedKeyRequest struct {
	RequestID string
	Groups    []string
	ExtraDNS  bool
}

func (r ManagedKeyRequest) payload() (setupRequest, error) {
	id, err := uuid.Parse(r.RequestID)
	if err != nil || id == uuid.Nil || id.String() != r.RequestID || len(r.Groups) > MaxManagedGroups {
		return setupRequest{}, ErrUnavailable
	}
	groups := append([]string{}, r.Groups...)
	slices.Sort(groups)
	for i, id := range groups {
		if !identifier(id) || i > 0 && groups[i-1] == id {
			return setupRequest{}, ErrUnavailable
		}
	}
	return setupRequest{"OpenUEM registration " + r.RequestID, "one-off", int(ManagedKeyLifetime / time.Second), groups, 1, false, r.ExtraDNS}, nil
}

// Digest identifies the exact fixed-policy JSON creation body, without tokens.
func (r ManagedKeyRequest) Digest() (string, error) {
	payload, err := r.payload()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", ErrUnavailable
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

type ManagedKeyMetadata struct {
	ID, Name, Type                      string
	ExpiresAt                           time.Time
	Groups                              []string
	UsageLimit, UsedTimes               int
	ExtraDNS, Ephemeral, Valid, Revoked bool
}

// SameOwnership compares the returned identity and creation policy, excluding
// mutable usage/revocation state. Names alone never establish ownership.
func (k ManagedKeyMetadata) SameOwnership(other ManagedKeyMetadata) bool {
	a, b := append([]string{}, k.Groups...), append([]string{}, other.Groups...)
	slices.Sort(a)
	slices.Sort(b)
	return identifier(k.ID) && k.ID == other.ID && k.Name == other.Name && k.Type == other.Type && k.ExpiresAt.Equal(other.ExpiresAt) && k.UsageLimit == other.UsageLimit && k.ExtraDNS == other.ExtraDNS && k.Ephemeral == other.Ephemeral && slices.Equal(a, b)
}

type ManagedKey struct {
	ManagedKeyMetadata
	Secret string
}

func (k ManagedKey) String() string   { return "NetBird setup key (credential redacted)" }
func (k ManagedKey) GoString() string { return k.String() }

func managedKeyFields(body []byte) (map[string]json.RawMessage, error) {
	if len(body) == 0 || len(body) > MaxResponse || !utf8.Valid(body) {
		return nil, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrUnavailable
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, ErrUnavailable
		}
		key, ok := token.(string)
		if !ok || len(key) > 256 || len(fields) >= 128 {
			return nil, ErrUnavailable
		}
		if _, ok = fields[key]; ok {
			return nil, ErrUnavailable
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrUnavailable
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrUnavailable
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrUnavailable
	}
	return fields, nil
}

func decodeManagedKey(body []byte, creation bool) (ManagedKey, error) {
	fields, err := managedKeyFields(body)
	if err != nil {
		return ManagedKey{}, err
	}
	var k ManagedKey
	required := map[string]any{"name": &k.Name, "type": &k.Type, "expires": &k.ExpiresAt, "auto_groups": &k.Groups, "usage_limit": &k.UsageLimit, "used_times": &k.UsedTimes, "allow_extra_dns_labels": &k.ExtraDNS, "ephemeral": &k.Ephemeral, "valid": &k.Valid, "revoked": &k.Revoked}
	if creation {
		required["key"] = &k.Secret
	}
	for name, out := range required {
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, out) != nil {
			return ManagedKey{}, ErrUnavailable
		}
		for key := range fields {
			if key != name && strings.EqualFold(key, name) {
				return ManagedKey{}, ErrUnavailable
			}
		}
	}
	raw, ok := fields["id"]
	if !ok {
		return ManagedKey{}, ErrUnavailable
	}
	if json.Unmarshal(raw, &k.ID) != nil {
		n, e := strconv.ParseUint(string(raw), 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != string(raw) {
			return ManagedKey{}, ErrUnavailable
		}
		k.ID = string(raw)
	}
	for name := range fields {
		if name != "id" && strings.EqualFold(name, "id") {
			return ManagedKey{}, ErrUnavailable
		}
	}
	if !identifier(k.ID) || len(k.Name) > 1024 || !utf8.ValidString(k.Name) || strings.ContainsAny(k.Name, "\x00\r\n") || k.ExpiresAt.IsZero() || k.ExpiresAt.Year() < 1970 || k.ExpiresAt.Year() > 9999 || k.Type != "one-off" || k.UsageLimit != 1 || k.UsedTimes < 0 || k.UsedTimes > 1 || k.Ephemeral || len(k.Groups) > MaxManagedGroups {
		return ManagedKey{}, ErrUnavailable
	}
	groups := append([]string{}, k.Groups...)
	slices.Sort(groups)
	for i, id := range groups {
		if !identifier(id) || i > 0 && groups[i-1] == id {
			return ManagedKey{}, ErrUnavailable
		}
	}
	if creation {
		if k.Secret == "" || len(k.Secret) > 512 {
			return ManagedKey{}, ErrUnavailable
		}
		for _, r := range k.Secret {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return ManagedKey{}, ErrUnavailable
			}
		}
	}
	k.ExpiresAt = k.ExpiresAt.UTC()
	k.Groups = groups
	return k, nil
}

// CreateManagedKey sends once. The caller must durably record its exact body
// digest before entry and persist the result before delivering the secret.
func CreateManagedKey(ctx context.Context, transport http.RoundTripper, base, token string, r ManagedKeyRequest) (*ManagedKey, error) {
	payload, err := r.payload()
	if err != nil {
		return nil, err
	}
	started := time.Now()
	body, err := request(ctx, transport, base, token, http.MethodPost, "setup-keys", nil, payload)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	k, err := decodeManagedKey(body, true)
	if err != nil || !k.Valid || k.Revoked || k.UsedTimes != 0 || k.Name != payload.Name || k.ExtraDNS != payload.ExtraDNS || !slices.Equal(k.Groups, payload.Groups) || !k.ExpiresAt.After(time.Now().Add(2*time.Minute)) || k.ExpiresAt.After(started.Add(ManagedKeyLifetime+5*time.Minute)) {
		return nil, ErrUnavailable
	}
	return &k, nil
}

// ObserveManagedKey reads only the exact provider ID retained from creation.
// A successful 404 observation reports absence; other failures remain unknown.
// Returned metadata deliberately excludes the provider's key/masked key field.
func ObserveManagedKey(ctx context.Context, transport http.RoundTripper, base, token, id string) (*ManagedKeyMetadata, bool, error) {
	if !identifier(id) {
		return nil, false, ErrUnavailable
	}
	body, missing, err := requestObserved(ctx, transport, base, token, http.MethodGet, "setup-keys/"+id, nil, nil, true)
	if err != nil {
		return nil, false, err
	}
	defer clear(body)
	if missing {
		return nil, true, nil
	}
	k, err := decodeManagedKey(body, false)
	if err != nil || k.ID != id {
		return nil, false, ErrUnavailable
	}
	return &k.ManagedKeyMetadata, false, nil
}
