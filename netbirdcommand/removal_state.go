package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// RemovalInspectionVersion is a read-only native package inspection. Older
// journal state controls cannot advertise package ownership or removal support.
const RemovalInspectionVersion = 3
const RemovalInspectionLifetime = 30 * time.Second

type removalStateWire struct {
	Version int `json:"version"`
	Identity
	RequestID   string          `json:"request_id"`
	RequestHash string          `json:"request_hash"`
	Kind        string          `json:"kind"`
	Outcome     string          `json:"outcome"`
	State       json.RawMessage `json:"state"`
	Removal     json.RawMessage `json:"removal"`
}

func (r ControlResponse) removalStateMatches() bool {
	if r.Receipt != (Receipt{}) || r.ReleaseID != "" {
		return false
	}
	switch r.Outcome {
	case "ok":
		return r.State.Valid() && r.State.Status != "unavailable" && r.Removal.Valid()
	case "absent":
		return r.State.Valid() && r.State.Status != "unavailable" && r.Removal == (packageapi.Removal{})
	case "unavailable", "blocked", "conflict":
		return r.State == (State{}) && r.Removal == (packageapi.Removal{})
	default:
		return false
	}
}

func encodeRemovalState(r ControlResponse) ([]byte, error) {
	state, err := json.Marshal(r.State)
	if err != nil {
		return nil, ErrInvalid
	}
	removal := []byte("{}")
	if r.Removal != (packageapi.Removal{}) {
		removal, err = packageapi.EncodeRemoval(r.Removal)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	data, err := json.Marshal(removalStateWire{r.Version, r.Identity, r.RequestID, r.RequestHash, r.Kind, r.Outcome, state, removal})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalState(data []byte, c ControlRequest) (ControlResponse, error) {
	var wire removalStateWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "removal"}, &wire) != nil {
		return ControlResponse{}, ErrInvalid
	}
	r := ControlResponse{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, RequestHash: wire.RequestHash, Kind: wire.Kind, Outcome: wire.Outcome}
	if decode(wire.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil {
		return ControlResponse{}, ErrInvalid
	}
	if decode(wire.Removal, nil, &struct{}{}) != nil {
		var err error
		r.Removal, err = packageapi.DecodeRemoval(wire.Removal)
		if err != nil {
			return ControlResponse{}, ErrInvalid
		}
	}
	if !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}
