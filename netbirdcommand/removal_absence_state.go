package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const RemovalAbsenceInspectionVersion = 5
const RemovalAbsenceInspectionLifetime = 45 * time.Second

type removalAbsenceInspectionWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Kind      string          `json:"kind"`
	Original  json.RawMessage `json:"original"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemovalAbsenceInspection(c ControlRequest) ([]byte, error) {
	original, err := EncodeRemovalAbsenceReference(c.RemovalAbsenceOriginal)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalAbsenceInspectionWire{c.Version, c.Identity, c.RequestID, c.Kind, original, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalAbsenceInspection(data []byte) (ControlRequest, error) {
	var wire removalAbsenceInspectionWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "kind", "original", "issued_at", "expires_at"}, &wire) != nil {
		return ControlRequest{}, ErrInvalid
	}
	original, err := DecodeRemovalAbsenceReference(wire.Original)
	if err != nil {
		return ControlRequest{}, ErrInvalid
	}
	c := ControlRequest{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Kind: wire.Kind, RemovalAbsenceOriginal: original, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalAbsenceInspectionVersion || !c.Valid() {
		return ControlRequest{}, ErrInvalid
	}
	return c, nil
}

type removalAbsenceStateWire struct {
	Version int `json:"version"`
	Identity
	RequestID   string          `json:"request_id"`
	RequestHash string          `json:"request_hash"`
	Kind        string          `json:"kind"`
	Outcome     string          `json:"outcome"`
	State       json.RawMessage `json:"state"`
	Absence     json.RawMessage `json:"absence"`
}

func (r ControlResponse) removalAbsenceStateMatches(c ControlRequest) bool {
	if r.Receipt != (Receipt{}) || r.ReleaseID != "" || r.Removal != (packageapi.Removal{}) || r.RemovalRecovery != (RemovalRecovery{}) {
		return false
	}
	switch r.Outcome {
	case "ok":
		return r.State.Valid() && r.State.Status == "ready" && r.RemovalAbsence.Valid() && r.RemovalAbsence.Original == c.RemovalAbsenceOriginal && r.RemovalAbsence.JournalRevision == r.State.Revision
	case "missing", "unavailable", "blocked", "conflict":
		return r.State == (State{}) && r.RemovalAbsence == (RemovalAbsence{})
	default:
		return false
	}
}

func encodeRemovalAbsenceState(r ControlResponse) ([]byte, error) {
	state, err := json.Marshal(r.State)
	if err != nil {
		return nil, ErrInvalid
	}
	absence := []byte("{}")
	if r.RemovalAbsence != (RemovalAbsence{}) {
		absence, err = EncodeRemovalAbsence(r.RemovalAbsence)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	data, err := json.Marshal(removalAbsenceStateWire{r.Version, r.Identity, r.RequestID, r.RequestHash, r.Kind, r.Outcome, state, absence})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalAbsenceState(data []byte, c ControlRequest) (ControlResponse, error) {
	var wire removalAbsenceStateWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "absence"}, &wire) != nil {
		return ControlResponse{}, ErrInvalid
	}
	r := ControlResponse{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, RequestHash: wire.RequestHash, Kind: wire.Kind, Outcome: wire.Outcome}
	if decode(wire.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil {
		return ControlResponse{}, ErrInvalid
	}
	if decode(wire.Absence, nil, &struct{}{}) != nil {
		var err error
		r.RemovalAbsence, err = DecodeRemovalAbsence(wire.Absence)
		if err != nil {
			return ControlResponse{}, ErrInvalid
		}
	}
	if !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}
