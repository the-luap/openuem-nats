package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const RemovalRecoveryInspectionVersion = 4
const RemovalRecoveryInspectionLifetime = 45 * time.Second

type removalRecoveryInspectionWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Kind      string          `json:"kind"`
	Original  json.RawMessage `json:"original"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemovalRecoveryInspection(c ControlRequest) ([]byte, error) {
	original, err := EncodeRemovalRecoveryReference(c.RemovalRecoveryOriginal)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalRecoveryInspectionWire{c.Version, c.Identity, c.RequestID, c.Kind, original, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalRecoveryInspection(data []byte) (ControlRequest, error) {
	var wire removalRecoveryInspectionWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "kind", "original", "issued_at", "expires_at"}, &wire) != nil {
		return ControlRequest{}, ErrInvalid
	}
	original, err := DecodeRemovalRecoveryReference(wire.Original)
	if err != nil {
		return ControlRequest{}, ErrInvalid
	}
	c := ControlRequest{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Kind: wire.Kind, RemovalRecoveryOriginal: original, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalRecoveryInspectionVersion || !c.Valid() {
		return ControlRequest{}, ErrInvalid
	}
	return c, nil
}

type removalRecoveryStateWire struct {
	Version int `json:"version"`
	Identity
	RequestID   string          `json:"request_id"`
	RequestHash string          `json:"request_hash"`
	Kind        string          `json:"kind"`
	Outcome     string          `json:"outcome"`
	State       json.RawMessage `json:"state"`
	Recovery    json.RawMessage `json:"recovery"`
}

func (r ControlResponse) removalRecoveryStateMatches(c ControlRequest) bool {
	if r.Receipt != (Receipt{}) || r.ReleaseID != "" || r.Removal != (packageapi.Removal{}) {
		return false
	}
	switch r.Outcome {
	case "ok":
		return r.State.Valid() && r.State.Status == "ready" && r.RemovalRecovery.Valid() && r.RemovalRecovery.Original == c.RemovalRecoveryOriginal && r.RemovalRecovery.JournalRevision == r.State.Revision
	case "missing", "unavailable", "blocked", "conflict":
		return r.State == (State{}) && r.RemovalRecovery == (RemovalRecovery{})
	default:
		return false
	}
}

func encodeRemovalRecoveryState(r ControlResponse) ([]byte, error) {
	state, err := json.Marshal(r.State)
	if err != nil {
		return nil, ErrInvalid
	}
	recovery := []byte("{}")
	if r.RemovalRecovery != (RemovalRecovery{}) {
		recovery, err = EncodeRemovalRecovery(r.RemovalRecovery)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	data, err := json.Marshal(removalRecoveryStateWire{r.Version, r.Identity, r.RequestID, r.RequestHash, r.Kind, r.Outcome, state, recovery})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalRecoveryState(data []byte, c ControlRequest) (ControlResponse, error) {
	var wire removalRecoveryStateWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "recovery"}, &wire) != nil {
		return ControlResponse{}, ErrInvalid
	}
	r := ControlResponse{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, RequestHash: wire.RequestHash, Kind: wire.Kind, Outcome: wire.Outcome}
	if decode(wire.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil {
		return ControlResponse{}, ErrInvalid
	}
	if decode(wire.Recovery, nil, &struct{}{}) != nil {
		var err error
		r.RemovalRecovery, err = DecodeRemovalRecovery(wire.Recovery)
		if err != nil {
			return ControlResponse{}, ErrInvalid
		}
	}
	if !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}
