package netbirdapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrPeerEvidenceConflict = errors.New("NetBird peer evidence is ambiguous")

// ManagedPeerEvent is provider evidence that a peer registered using an exact
// setup-key ID. Names, IP addresses, free-form metadata and user PII are omitted.
// It does not prove the current local WireGuard identity or command completion.
type ManagedPeerEvent struct {
	ID, KeyID, PeerID string
	Timestamp         time.Time
}

// ManagedPeerMetadata identifies one provider object, with a display name that
// is never used as ownership evidence. CreatedAt detects replacement objects.
type ManagedPeerMetadata struct {
	ID, Name, UserID string
	CreatedAt        time.Time
	Ephemeral        bool
}

func peerEvidenceTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 }

func peerEvidenceFields(body []byte) (map[string]json.RawMessage, error) {
	fields, err := managedKeyFields(body)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for key := range fields {
		name := strings.ToLower(key)
		if seen[name] {
			return nil, ErrUnavailable
		}
		seen[name] = true
	}
	return fields, nil
}

func peerEvidenceField(fields map[string]json.RawMessage, name string, out any) bool {
	raw, ok := fields[name]
	return ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, out) == nil
}

func peerEventID(raw json.RawMessage) (string, bool) {
	var id string
	if json.Unmarshal(raw, &id) != nil {
		n, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != string(raw) {
			return "", false
		}
		id = string(raw)
	}
	return id, identifier(id) && id != "0"
}

// ManagedKeyPeer reads the bounded account audit feed once. A nil event means
// no usable positive evidence was returned; it never proves no registration.
// Two matching events are ambiguous even if they name the same peer. The API
// can truncate its history, so callers must not infer completeness from this read.
func ManagedKeyPeer(ctx context.Context, transport http.RoundTripper, base, token, keyID string, notBefore, notAfter time.Time) (*ManagedPeerEvent, error) {
	if !identifier(keyID) || !peerEvidenceTime(notBefore) || !peerEvidenceTime(notAfter) || !notAfter.After(notBefore) || notAfter.Sub(notBefore) > ManagedKeyLifetime+10*time.Minute {
		return nil, ErrUnavailable
	}
	body, err := request(ctx, transport, base, token, http.MethodGet, "events/audit", nil, nil)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	body = bytes.TrimSpace(body)
	var rows []json.RawMessage
	if len(body) == 0 || body[0] != '[' || json.Unmarshal(body, &rows) != nil || len(rows) > 10000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	var matched *ManagedPeerEvent
	for _, row := range rows {
		fields, err := peerEvidenceFields(row)
		if err != nil {
			return nil, err
		}
		id, ok := peerEventID(fields["id"])
		if !ok || seen[id] {
			return nil, ErrPeerEvidenceConflict
		}
		seen[id] = true
		var activity, initiator string
		if !peerEvidenceField(fields, "activity_code", &activity) || !peerEvidenceField(fields, "initiator_id", &initiator) {
			return nil, ErrUnavailable
		}
		if activity != "peer.setupkey.add" || initiator != keyID {
			continue
		}
		event := &ManagedPeerEvent{ID: id, KeyID: keyID}
		if !peerEvidenceField(fields, "target_id", &event.PeerID) || !identifier(event.PeerID) || !peerEvidenceField(fields, "timestamp", &event.Timestamp) || !peerEvidenceTime(event.Timestamp) {
			return nil, ErrUnavailable
		}
		event.Timestamp = event.Timestamp.UTC()
		if event.Timestamp.Before(notBefore) || event.Timestamp.After(notAfter) {
			continue
		}
		if matched != nil {
			return nil, ErrPeerEvidenceConflict
		}
		matched = event
	}
	return matched, nil
}

// ObserveManagedPeer reads only the exact provider ID named in retained evidence.
// An exact-ID 404 is absence; redirects, errors and malformed responses are not.
func ObserveManagedPeer(ctx context.Context, transport http.RoundTripper, base, token, id string) (*ManagedPeerMetadata, bool, error) {
	if !identifier(id) {
		return nil, false, ErrUnavailable
	}
	body, absent, err := requestObserved(ctx, transport, base, token, http.MethodGet, "peers/"+id, nil, nil, true)
	if err != nil {
		return nil, false, err
	}
	defer clear(body)
	if absent {
		return nil, true, nil
	}
	fields, err := peerEvidenceFields(body)
	if err != nil {
		return nil, false, err
	}
	p := &ManagedPeerMetadata{}
	if !peerEvidenceField(fields, "id", &p.ID) || p.ID != id || !peerEvidenceField(fields, "name", &p.Name) || !peerEvidenceField(fields, "created_at", &p.CreatedAt) || !peerEvidenceTime(p.CreatedAt) || !peerEvidenceField(fields, "user_id", &p.UserID) || !peerEvidenceField(fields, "ephemeral", &p.Ephemeral) {
		return nil, false, ErrUnavailable
	}
	for _, text := range []string{p.Name, p.UserID} {
		if len(text) > 1024 || !utf8.ValidString(text) {
			return nil, false, ErrUnavailable
		}
		for _, r := range text {
			if unicode.IsControl(r) {
				return nil, false, ErrUnavailable
			}
		}
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, false, nil
}
