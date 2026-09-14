package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// Installation shares the ordinary command subject, UUID namespace, receipt and
// recovery barrier. It contains no connection settings or provider credential.
// A package must be prepared separately before fresh durable installation
// admission; the longer deadline bounds native execution, not package download.
type installationWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Revision  string          `json:"revision"`
	Operation string          `json:"operation"`
	Package   json.RawMessage `json:"package"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeInstallation(c Command) ([]byte, error) {
	data, err := packageapi.Encode(c.Package)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(data)
	encoded, err := json.Marshal(installationWire{c.Version, c.Identity, c.RequestID, c.Revision, c.Operation, data, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(encoded) > MaxMessage {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func decodeInstallation(data []byte) (Command, error) {
	var wire installationWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "package", "issued_at", "expires_at"}, &wire) != nil {
		return Command{}, ErrInvalid
	}
	defer clear(wire.Package)
	p, err := packageapi.Decode(wire.Package)
	if err != nil {
		return Command{}, ErrInvalid
	}
	c := Command{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Revision: wire.Revision, Operation: wire.Operation, Package: p, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != InstallationVersion || !c.Valid() {
		return Command{}, ErrInvalid
	}
	return c, nil
}
