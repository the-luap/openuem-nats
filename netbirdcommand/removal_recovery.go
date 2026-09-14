package netbirdcommand

import (
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const RemovalRecoveryVersion = 5
const RemovalRecoveryLifetime = 10 * time.Minute

// RemovalRecoveryReference names immutable original removal evidence and its
// separate reviewed release. Syntax does not prove that the journal owns it.
type RemovalRecoveryReference struct {
	RequestID, CommandHash, Revision, ReleaseID string
	Removal                                     packageapi.Removal
}

func (r RemovalRecoveryReference) Valid() bool {
	return ValidRequestID(r.RequestID) && ValidDigest(r.CommandHash) && ValidDigest(r.Revision) && ValidRequestID(r.ReleaseID) && r.Removal.Valid() && r.Removal.Platform == "macos"
}

func (RemovalRecoveryReference) String() string               { return "[NetBird removal recovery reference]" }
func (r RemovalRecoveryReference) GoString() string           { return r.String() }
func (RemovalRecoveryReference) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// JournalRevision is the live ready-journal revision from native inspection.
// It is distinct from Command.Revision, which binds the console's current review.
// Mode is explicit so a manifest-backed continuation cannot silently become
// cleanup of an absent manifest or a fresh removal of a replacement package.
type RemovalRecovery struct {
	Original                           RemovalRecoveryReference
	Mode, JournalRevision, StateDigest string
}

func (r RemovalRecovery) Valid() bool {
	return r.Original.Valid() && r.Mode == "manifest" && ValidDigest(r.JournalRevision) && ValidDigest(r.StateDigest)
}

func (RemovalRecovery) String() string               { return "[NetBird removal recovery descriptor]" }
func (r RemovalRecovery) GoString() string           { return r.String() }
func (RemovalRecovery) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type removalRecoveryReferenceWire struct {
	RequestID   string          `json:"request_id"`
	CommandHash string          `json:"command_hash"`
	Revision    string          `json:"revision"`
	ReleaseID   string          `json:"release_id"`
	Removal     json.RawMessage `json:"removal"`
}

func EncodeRemovalRecoveryReference(r RemovalRecoveryReference) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	removal, err := packageapi.EncodeRemoval(r.Removal)
	if err != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(removalRecoveryReferenceWire{r.RequestID, r.CommandHash, r.Revision, r.ReleaseID, removal})
}

func DecodeRemovalRecoveryReference(data []byte) (RemovalRecoveryReference, error) {
	var wire removalRecoveryReferenceWire
	if decode(data, []string{"request_id", "command_hash", "revision", "release_id", "removal"}, &wire) != nil {
		return RemovalRecoveryReference{}, ErrInvalid
	}
	removal, err := packageapi.DecodeRemoval(wire.Removal)
	if err != nil {
		return RemovalRecoveryReference{}, ErrInvalid
	}
	r := RemovalRecoveryReference{wire.RequestID, wire.CommandHash, wire.Revision, wire.ReleaseID, removal}
	if !r.Valid() {
		return RemovalRecoveryReference{}, ErrInvalid
	}
	return r, nil
}

type removalRecoveryDescriptorWire struct {
	Original        json.RawMessage `json:"original"`
	Mode            string          `json:"mode"`
	JournalRevision string          `json:"journal_revision"`
	StateDigest     string          `json:"state_digest"`
}

func EncodeRemovalRecovery(r RemovalRecovery) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	original, err := EncodeRemovalRecoveryReference(r.Original)
	if err != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(removalRecoveryDescriptorWire{original, r.Mode, r.JournalRevision, r.StateDigest})
}

func DecodeRemovalRecovery(data []byte) (RemovalRecovery, error) {
	var wire removalRecoveryDescriptorWire
	if decode(data, []string{"original", "mode", "journal_revision", "state_digest"}, &wire) != nil {
		return RemovalRecovery{}, ErrInvalid
	}
	original, err := DecodeRemovalRecoveryReference(wire.Original)
	if err != nil {
		return RemovalRecovery{}, ErrInvalid
	}
	r := RemovalRecovery{original, wire.Mode, wire.JournalRevision, wire.StateDigest}
	if !r.Valid() {
		return RemovalRecovery{}, ErrInvalid
	}
	return r, nil
}

type removalRecoveryWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Revision  string          `json:"revision"`
	Operation string          `json:"operation"`
	Recovery  json.RawMessage `json:"recovery"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemovalRecoveryCommand(c Command) ([]byte, error) {
	recovery, err := EncodeRemovalRecovery(c.RemovalRecovery)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalRecoveryWire{c.Version, c.Identity, c.RequestID, c.Revision, c.Operation, recovery, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalRecoveryCommand(data []byte) (Command, error) {
	var wire removalRecoveryWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "recovery", "issued_at", "expires_at"}, &wire) != nil {
		return Command{}, ErrInvalid
	}
	recovery, err := DecodeRemovalRecovery(wire.Recovery)
	if err != nil {
		return Command{}, ErrInvalid
	}
	c := Command{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Revision: wire.Revision, Operation: wire.Operation, RemovalRecovery: recovery, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalRecoveryVersion || !c.Valid() {
		return Command{}, ErrInvalid
	}
	return c, nil
}
