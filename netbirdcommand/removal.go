package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const RemovalVersion = 4
const RemovalLifetime = 10 * time.Minute

// Removal is a separate command grammar: an approval or installation descriptor
// cannot stand in for the exact current installed state reviewed for removal.
type removalWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Revision  string          `json:"revision"`
	Operation string          `json:"operation"`
	Removal   json.RawMessage `json:"removal"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemoval(c Command) ([]byte, error) {
	data, err := packageapi.EncodeRemoval(c.Removal)
	if err != nil {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(removalWire{c.Version, c.Identity, c.RequestID, c.Revision, c.Operation, data, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(encoded) > MaxMessage {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func decodeRemoval(data []byte) (Command, error) {
	var wire removalWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "removal", "issued_at", "expires_at"}, &wire) != nil {
		return Command{}, ErrInvalid
	}
	r, err := packageapi.DecodeRemoval(wire.Removal)
	if err != nil {
		return Command{}, ErrInvalid
	}
	c := Command{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Revision: wire.Revision, Operation: wire.Operation, Removal: r, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalVersion || !c.Valid() {
		return Command{}, ErrInvalid
	}
	return c, nil
}

// RequiresIndividualIdentity applies to both execution and retained recovery
// evidence. A legacy journal or receipt must never acquire native package rights.
func RequiresIndividualIdentity(operation string) bool {
	return operation == "install" || operation == "uninstall"
}
