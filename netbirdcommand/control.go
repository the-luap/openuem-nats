package netbirdcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const ControlLifetime = 10 * time.Second
const MaxJournalAttempts = 4096

// State is a live journal summary, not a periodic inventory capability claim.
// Revision changes with the local identity, boot, attempts and resolution state.
type State struct {
	Status      string `json:"status"`
	Revision    string `json:"revision"`
	Remaining   int    `json:"remaining"`
	PendingID   string `json:"pending_id"`
	PendingHash string `json:"pending_hash"`
	CanRelease  bool   `json:"can_release"`
}

func (s State) Valid() bool {
	if s.Status == "unavailable" {
		return s == (State{Status: "unavailable"})
	}
	if !ValidDigest(s.Revision) || s.Remaining < 0 || s.Remaining > MaxJournalAttempts {
		return false
	}
	switch s.Status {
	case "ready":
		return s.Remaining > 0 && s.PendingID == "" && s.PendingHash == "" && !s.CanRelease
	case "full":
		return s.Remaining == 0 && s.PendingID == "" && s.PendingHash == "" && !s.CanRelease
	case "busy":
		return ValidRequestID(s.PendingID) && ValidDigest(s.PendingHash) && !s.CanRelease
	case "unconfirmed":
		return ValidRequestID(s.PendingID) && ValidDigest(s.PendingHash)
	default:
		return false
	}
}

// ControlRequest is an expiring state, receipt or explicit release request. For
// release, RequestID is also the permanent resolution ID. State is read-only.
type ControlRequest struct {
	Version int `json:"version"`
	Identity
	RequestID   string    `json:"request_id"`
	Kind        string    `json:"kind"`
	ReferenceID string    `json:"reference_id"`
	CommandHash string    `json:"command_hash"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (c ControlRequest) Valid() bool {
	if c.Version != Version || !c.Identity.Valid() || !ValidRequestID(c.RequestID) || c.IssuedAt.Year() < 1970 || c.IssuedAt.Year() > 9999 || c.ExpiresAt.Year() < 1970 || c.ExpiresAt.Year() > 9999 || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > ControlLifetime {
		return false
	}
	switch c.Kind {
	case "state", "registration-state":
		return c.ReferenceID == "" && c.CommandHash == ""
	case "receipt", "release":
		return ValidRequestID(c.ReferenceID) && ValidDigest(c.CommandHash)
	default:
		return false
	}
}

func (c ControlRequest) Executable(identity Identity, now time.Time) bool {
	return c.Valid() && identity.Valid() && c.Identity == identity && !now.IsZero() && !c.IssuedAt.After(now.Add(ClockAllowance)) && c.ExpiresAt.After(now)
}

func EncodeControl(c ControlRequest) ([]byte, error) {
	if !c.Valid() {
		return nil, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return json.Marshal(c)
}

func DecodeControl(data []byte) (ControlRequest, error) {
	var c ControlRequest
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "kind", "reference_id", "command_hash", "issued_at", "expires_at"}, &c) != nil || !c.Valid() {
		return ControlRequest{}, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

func (c ControlRequest) Digest() (string, error) {
	data, err := EncodeControl(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ControlSubject(device string) (string, error) {
	if !ValidDeviceID(device) {
		return "", ErrInvalid
	}
	return "agent.netbird.control." + device, nil
}

type ControlResponse struct {
	Version int `json:"version"`
	Identity
	RequestID   string  `json:"request_id"`
	RequestHash string  `json:"request_hash"`
	Kind        string  `json:"kind"`
	Outcome     string  `json:"outcome"`
	State       State   `json:"state"`
	Receipt     Receipt `json:"receipt"`
	ReleaseID   string  `json:"release_id"`
}

func ControlResponseFor(c ControlRequest, outcome string) (ControlResponse, error) {
	hash, err := c.Digest()
	if err != nil {
		return ControlResponse{}, err
	}
	return ControlResponse{Version: Version, Identity: c.Identity, RequestID: c.RequestID, RequestHash: hash, Kind: c.Kind, Outcome: outcome}, nil
}

func (r ControlResponse) Matches(c ControlRequest) bool {
	hash, err := c.Digest()
	if err != nil || r.Version != Version || r.Identity != c.Identity || r.RequestID != c.RequestID || r.RequestHash != hash || r.Kind != c.Kind {
		return false
	}
	if r.Outcome != "ok" {
		switch r.Outcome {
		case "missing", "blocked", "conflict", "unavailable":
			return r.State == (State{}) && r.Receipt == (Receipt{}) && r.ReleaseID == ""
		default:
			return false
		}
	}
	switch r.Kind {
	case "state", "registration-state":
		return r.State.Valid() && r.Receipt == (Receipt{}) && r.ReleaseID == ""
	case "receipt", "release":
		if r.State != (State{}) || !r.Receipt.Valid() || (r.Receipt.Status != "completed" && r.Receipt.Status != "unconfirmed") || r.Receipt.DeviceID != c.DeviceID || r.Receipt.RequestID != c.ReferenceID || r.Receipt.CommandHash != c.CommandHash {
			return false
		}
		if r.ReleaseID != "" && (!ValidRequestID(r.ReleaseID) || r.Receipt.Status != "unconfirmed") {
			return false
		}
		if r.Kind == "release" {
			return r.ReleaseID == c.RequestID && r.Receipt.Status == "unconfirmed"
		}
		return true
	default:
		return false
	}
}

func EncodeControlResponse(c ControlRequest, r ControlResponse) ([]byte, error) {
	if !r.Matches(c) {
		return nil, ErrInvalid
	}
	return json.Marshal(r)
}

func DecodeControlResponse(data []byte, c ControlRequest) (ControlResponse, error) {
	var r ControlResponse
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "receipt", "release_id"}, &r) != nil {
		return ControlResponse{}, ErrInvalid
	}
	// The nested payloads use the same exact-key/type rules as the envelope,
	// including their canonical empty forms when this response does not use them.
	var nested struct {
		State   json.RawMessage `json:"state"`
		Receipt json.RawMessage `json:"receipt"`
	}
	if json.Unmarshal(data, &nested) != nil || decode(nested.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil || decode(nested.Receipt, []string{"version", "request_id", "device_id", "revision", "command_hash", "operation", "status"}, &r.Receipt) != nil || !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}
