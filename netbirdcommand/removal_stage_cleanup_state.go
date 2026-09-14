package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const RemovalStageCleanupInspectionVersion = 6
const RemovalStageCleanupInspectionLifetime = 45 * time.Second

type removalStageCleanupInspectionWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Kind      string          `json:"kind"`
	Original  json.RawMessage `json:"original"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemovalStageCleanupInspection(c ControlRequest) ([]byte, error) {
	original, err := EncodeRemovalStageCleanupReference(c.RemovalStageCleanupOriginal)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalStageCleanupInspectionWire{c.Version, c.Identity, c.RequestID, c.Kind, original, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalStageCleanupInspection(data []byte) (ControlRequest, error) {
	var wire removalStageCleanupInspectionWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "kind", "original", "issued_at", "expires_at"}, &wire) != nil {
		return ControlRequest{}, ErrInvalid
	}
	original, err := DecodeRemovalStageCleanupReference(wire.Original)
	if err != nil {
		return ControlRequest{}, ErrInvalid
	}
	c := ControlRequest{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Kind: wire.Kind, RemovalStageCleanupOriginal: original, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalStageCleanupInspectionVersion || !c.Valid() {
		return ControlRequest{}, ErrInvalid
	}
	return c, nil
}

type removalStageCleanupStateWire struct {
	Version int `json:"version"`
	Identity
	RequestID    string          `json:"request_id"`
	RequestHash  string          `json:"request_hash"`
	Kind         string          `json:"kind"`
	Outcome      string          `json:"outcome"`
	State        json.RawMessage `json:"state"`
	StageCleanup json.RawMessage `json:"stage_cleanup"`
}

func (r ControlResponse) removalStageCleanupStateMatches(c ControlRequest) bool {
	if r.Receipt != (Receipt{}) || r.ReleaseID != "" || r.Removal != (packageapi.Removal{}) || r.RemovalRecovery != (RemovalRecovery{}) || r.RemovalAbsence != (RemovalAbsence{}) {
		return false
	}
	switch r.Outcome {
	case "ok":
		return r.State.Valid() && r.State.Status == "ready" && r.RemovalStageCleanup.Valid() && r.RemovalStageCleanup.Original == c.RemovalStageCleanupOriginal && r.RemovalStageCleanup.JournalRevision == r.State.Revision
	case "missing", "unavailable", "blocked", "conflict":
		return r.State == (State{}) && r.RemovalStageCleanup == (RemovalStageCleanup{})
	default:
		return false
	}
}

func encodeRemovalStageCleanupState(r ControlResponse) ([]byte, error) {
	state, err := json.Marshal(r.State)
	if err != nil {
		return nil, ErrInvalid
	}
	cleanup := []byte("{}")
	if r.RemovalStageCleanup != (RemovalStageCleanup{}) {
		cleanup, err = EncodeRemovalStageCleanup(r.RemovalStageCleanup)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	data, err := json.Marshal(removalStageCleanupStateWire{r.Version, r.Identity, r.RequestID, r.RequestHash, r.Kind, r.Outcome, state, cleanup})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalStageCleanupState(data []byte, c ControlRequest) (ControlResponse, error) {
	var wire removalStageCleanupStateWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "stage_cleanup"}, &wire) != nil {
		return ControlResponse{}, ErrInvalid
	}
	r := ControlResponse{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, RequestHash: wire.RequestHash, Kind: wire.Kind, Outcome: wire.Outcome}
	if decode(wire.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil {
		return ControlResponse{}, ErrInvalid
	}
	if decode(wire.StageCleanup, nil, &struct{}{}) != nil {
		var err error
		r.RemovalStageCleanup, err = DecodeRemovalStageCleanup(wire.StageCleanup)
		if err != nil {
			return ControlResponse{}, ErrInvalid
		}
	}
	if !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}
