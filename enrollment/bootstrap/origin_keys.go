package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const MaxOriginKeysSize = enrollment.MaxBootstrapKeysSize

type originKeys struct {
	Schema int         `json:"schema"`
	Origin string      `json:"origin"`
	Keys   []originKey `json:"keys"`
}

type originKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// MarshalOriginKeys publishes configuration public keys for an explicitly
// configured origin. The HTTPS service authenticates this document; it contains
// no signature and cannot independently establish trust in an origin or key.
func MarshalOriginKeys(origin string, keys []ed25519.PublicKey) ([]byte, error) {
	if !enrollment.ValidOrigin(origin) || len(keys) == 0 || len(keys) > 8 {
		return nil, ErrInvalid
	}
	document := originKeys{Schema: Schema, Origin: origin}
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		document.Keys = append(document.Keys, originKey{KeyID: artifacts.KeyID(key), PublicKey: base64.RawStdEncoding.EncodeToString(key)})
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := ParseOriginKeys(data, origin); err != nil {
		return nil, err
	}
	return data, nil
}

// ParseOriginKeys validates a bounded key document obtained through verified
// HTTPS at the independently authorized expectedOrigin (or an equally trusted
// provisioning channel). Parsing alone does not authenticate downloaded keys.
// Returned keys are independent caller-owned buffers, for configuration trust
// only. Release verification must use its separately provisioned key ring.
func ParseOriginKeys(data []byte, expectedOrigin string) ([]ed25519.PublicKey, error) {
	if !enrollment.ValidOrigin(expectedOrigin) || len(data) == 0 || len(data) > MaxOriginKeysSize {
		return nil, ErrInvalid
	}
	var document originKeys
	if err := strictjson.Unmarshal(data, &document); err != nil || document.Schema != Schema || document.Origin != expectedOrigin || len(document.Keys) == 0 || len(document.Keys) > 8 {
		return nil, ErrInvalid
	}
	keys := make([]ed25519.PublicKey, 0, len(document.Keys))
	seen := make(map[string]bool)
	for _, entry := range document.Keys {
		key, err := base64.RawStdEncoding.Strict().DecodeString(entry.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize || base64.RawStdEncoding.EncodeToString(key) != entry.PublicKey || artifacts.KeyID(key) != entry.KeyID || seen[entry.KeyID] {
			return nil, ErrInvalid
		}
		seen[entry.KeyID] = true
		keys = append(keys, ed25519.PublicKey(key))
	}
	return keys, nil
}
