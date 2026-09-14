package netbirdcommand

import (
	"encoding/json"
	"time"
)

const RemovalAbsenceVersion = 6
const RemovalAbsenceProfile = "macos-official-pkg-v1"
const RemovalAbsenceLifetime = 2 * time.Minute

// RemovalAbsenceReference names immutable original removal evidence and its
// separate reviewed release. Syntax does not prove that the journal owns it.
type RemovalAbsenceReference struct {
	RequestID, CommandHash, Revision, ReleaseID string
}

func (r RemovalAbsenceReference) Valid() bool {
	return ValidRequestID(r.RequestID) && ValidDigest(r.CommandHash) && ValidDigest(r.Revision) && ValidRequestID(r.ReleaseID) && r.RequestID != r.ReleaseID
}

func (RemovalAbsenceReference) String() string               { return "[NetBird removal absence reference]" }
func (r RemovalAbsenceReference) GoString() string           { return r.String() }
func (RemovalAbsenceReference) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// JournalRevision is the live ready-journal revision from native inspection.
// It is distinct from Command.Revision, which binds the console's current review.
// The fixed profile describes current absence of the supported package layout.
// It never claims original success or authorizes native filesystem mutation.
type RemovalAbsence struct {
	Original                              RemovalAbsenceReference
	Profile, JournalRevision, StateDigest string
}

func (r RemovalAbsence) Valid() bool {
	return r.Original.Valid() && r.Profile == RemovalAbsenceProfile && ValidDigest(r.JournalRevision) && ValidDigest(r.StateDigest)
}

func (RemovalAbsence) String() string               { return "[NetBird removal absence descriptor]" }
func (r RemovalAbsence) GoString() string           { return r.String() }
func (RemovalAbsence) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type removalAbsenceReferenceWire struct {
	RequestID   string `json:"request_id"`
	CommandHash string `json:"command_hash"`
	Revision    string `json:"revision"`
	ReleaseID   string `json:"release_id"`
}

func EncodeRemovalAbsenceReference(r RemovalAbsenceReference) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(removalAbsenceReferenceWire{r.RequestID, r.CommandHash, r.Revision, r.ReleaseID})
}

func DecodeRemovalAbsenceReference(data []byte) (RemovalAbsenceReference, error) {
	var wire removalAbsenceReferenceWire
	if decode(data, []string{"request_id", "command_hash", "revision", "release_id"}, &wire) != nil {
		return RemovalAbsenceReference{}, ErrInvalid
	}
	r := RemovalAbsenceReference{wire.RequestID, wire.CommandHash, wire.Revision, wire.ReleaseID}
	if !r.Valid() {
		return RemovalAbsenceReference{}, ErrInvalid
	}
	return r, nil
}

type removalAbsenceDescriptorWire struct {
	Original        json.RawMessage `json:"original"`
	Profile         string          `json:"profile"`
	JournalRevision string          `json:"journal_revision"`
	StateDigest     string          `json:"state_digest"`
}

func EncodeRemovalAbsence(r RemovalAbsence) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	original, err := EncodeRemovalAbsenceReference(r.Original)
	if err != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(removalAbsenceDescriptorWire{original, r.Profile, r.JournalRevision, r.StateDigest})
}

func DecodeRemovalAbsence(data []byte) (RemovalAbsence, error) {
	var wire removalAbsenceDescriptorWire
	if decode(data, []string{"original", "profile", "journal_revision", "state_digest"}, &wire) != nil {
		return RemovalAbsence{}, ErrInvalid
	}
	original, err := DecodeRemovalAbsenceReference(wire.Original)
	if err != nil {
		return RemovalAbsence{}, ErrInvalid
	}
	r := RemovalAbsence{original, wire.Profile, wire.JournalRevision, wire.StateDigest}
	if !r.Valid() {
		return RemovalAbsence{}, ErrInvalid
	}
	return r, nil
}

type removalAbsenceWire struct {
	Version int `json:"version"`
	Identity
	RequestID string          `json:"request_id"`
	Revision  string          `json:"revision"`
	Operation string          `json:"operation"`
	Absence   json.RawMessage `json:"absence"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func encodeRemovalAbsenceCommand(c Command) ([]byte, error) {
	absence, err := EncodeRemovalAbsence(c.RemovalAbsence)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalAbsenceWire{c.Version, c.Identity, c.RequestID, c.Revision, c.Operation, absence, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalAbsenceCommand(data []byte) (Command, error) {
	var wire removalAbsenceWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "absence", "issued_at", "expires_at"}, &wire) != nil {
		return Command{}, ErrInvalid
	}
	absence, err := DecodeRemovalAbsence(wire.Absence)
	if err != nil {
		return Command{}, ErrInvalid
	}
	c := Command{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Revision: wire.Revision, Operation: wire.Operation, RemovalAbsence: absence, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalAbsenceVersion || !c.Valid() {
		return Command{}, ErrInvalid
	}
	return c, nil
}
