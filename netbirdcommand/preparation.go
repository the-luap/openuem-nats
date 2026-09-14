package netbirdcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const PreparationVersion = 1
const PreparationLifetime = 10 * time.Minute

// PreparationRequest authorizes private download and inspection only. Revision
// identifies the reviewed installation intent; JournalRevision binds the live
// exclusion state. Installation requires a separate, fresh durable command.
type PreparationRequest struct {
	Version int
	Identity
	RequestID, Revision, JournalRevision string
	Package                              packageapi.Package
	IssuedAt, ExpiresAt                  time.Time
}

func (PreparationRequest) String() string               { return "NetBird preparation (source redacted)" }
func (p PreparationRequest) GoString() string           { return p.String() }
func (PreparationRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type preparationWire struct {
	Version int `json:"version"`
	Identity
	RequestID       string          `json:"request_id"`
	Revision        string          `json:"revision"`
	JournalRevision string          `json:"journal_revision"`
	Package         json.RawMessage `json:"package"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

func (p PreparationRequest) Valid() bool {
	return p.Version == PreparationVersion && p.Identity.Valid() && p.Individual && ValidRequestID(p.DeviceID) && ValidRequestID(p.RequestID) && ValidDigest(p.Revision) && ValidDigest(p.JournalRevision) && p.Package.Valid() && p.Package.TenantID == p.TenantID && p.IssuedAt.Year() >= 1970 && p.IssuedAt.Year() <= 9999 && p.ExpiresAt.Year() >= 1970 && p.ExpiresAt.Year() <= 9999 && p.ExpiresAt.After(p.IssuedAt) && p.ExpiresAt.Sub(p.IssuedAt) <= PreparationLifetime
}

func (p PreparationRequest) Executable(identity Identity, now time.Time) bool {
	return p.Valid() && identity == p.Identity && !now.IsZero() && !p.IssuedAt.After(now.Add(ClockAllowance)) && p.ExpiresAt.After(now)
}

func EncodePreparation(p PreparationRequest) ([]byte, error) {
	if !p.Valid() {
		return nil, ErrInvalid
	}
	data, err := packageapi.Encode(p.Package)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(data)
	encoded, err := json.Marshal(preparationWire{p.Version, p.Identity, p.RequestID, p.Revision, p.JournalRevision, data, p.IssuedAt.UTC(), p.ExpiresAt.UTC()})
	if err != nil || len(encoded) > MaxMessage {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func DecodePreparation(data []byte) (PreparationRequest, error) {
	var w preparationWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "journal_revision", "package", "issued_at", "expires_at"}, &w) != nil {
		return PreparationRequest{}, ErrInvalid
	}
	defer clear(w.Package)
	pkg, err := packageapi.Decode(w.Package)
	if err != nil {
		return PreparationRequest{}, ErrInvalid
	}
	p := PreparationRequest{w.Version, w.Identity, w.RequestID, w.Revision, w.JournalRevision, pkg, w.IssuedAt.UTC(), w.ExpiresAt.UTC()}
	if !p.Valid() {
		return PreparationRequest{}, ErrInvalid
	}
	return p, nil
}

func (p PreparationRequest) Digest() (string, error) {
	data, err := EncodePreparation(p)
	if err != nil {
		return "", err
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func PreparationSubject(device string) (string, error) {
	if !ValidRequestID(device) {
		return "", ErrInvalid
	}
	return "agent.netbird.prepare." + device, nil
}

// PreparationResponse exposes no source or local path. A prepared response is
// ephemeral evidence of inspection, never an installation receipt or authority.
type PreparationResponse struct {
	Version int `json:"version"`
	Identity
	RequestID   string `json:"request_id"`
	RequestHash string `json:"request_hash"`
	Outcome     string `json:"outcome"`
}

func PreparationResponseFor(p PreparationRequest, outcome string) (PreparationResponse, error) {
	hash, err := p.Digest()
	if err != nil {
		return PreparationResponse{}, err
	}
	r := PreparationResponse{PreparationVersion, p.Identity, p.RequestID, hash, outcome}
	if !r.Matches(p) {
		return PreparationResponse{}, ErrInvalid
	}
	return r, nil
}

func (r PreparationResponse) Matches(p PreparationRequest) bool {
	hash, err := p.Digest()
	if err != nil || r.Version != PreparationVersion || r.Identity != p.Identity || r.RequestID != p.RequestID || r.RequestHash != hash {
		return false
	}
	return r.Outcome == "prepared" || r.Outcome == "blocked" || r.Outcome == "conflict" || r.Outcome == "unavailable"
}

func EncodePreparationResponse(p PreparationRequest, r PreparationResponse) ([]byte, error) {
	if !r.Matches(p) {
		return nil, ErrInvalid
	}
	return json.Marshal(r)
}

func DecodePreparationResponse(data []byte, p PreparationRequest) (PreparationResponse, error) {
	var r PreparationResponse
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "outcome"}, &r) != nil || !r.Matches(p) {
		return PreparationResponse{}, ErrInvalid
	}
	return r, nil
}
