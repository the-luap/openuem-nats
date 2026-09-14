package netbirdcommand

import (
	"encoding/json"
	"time"
)

const RemovalStageCleanupVersion = 7
const RemovalStageCleanupProfile = "macos-official-pkg-stage-v1"
const RemovalStageCleanupLifetime = 5 * time.Minute

// RemovalStageCleanupReference names immutable original removal evidence and its
// separate reviewed release. Syntax does not prove that the journal owns it.
type RemovalStageCleanupReference struct {
	RequestID, CommandHash, Revision, ReleaseID string
}

func (r RemovalStageCleanupReference) Valid() bool {
	return ValidRequestID(r.RequestID) && ValidDigest(r.CommandHash) && ValidDigest(r.Revision) && ValidRequestID(r.ReleaseID) && r.RequestID != r.ReleaseID
}

func (RemovalStageCleanupReference) String() string {
	return "[NetBird removal stage cleanup reference]"
}
func (r RemovalStageCleanupReference) GoString() string           { return r.String() }
func (RemovalStageCleanupReference) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// JournalRevision is the live ready-journal revision from native inspection.
// It is distinct from Command.Revision, which binds the console's current review.
// The fixed profile authorizes only the explicitly reviewed current scaffold
// and incomplete metadata. It never claims original uninstall success.
type RemovalStageCleanup struct {
	Original                              RemovalStageCleanupReference
	Profile, JournalRevision, StateDigest string
	DirectoryCount                        int
	ManifestPresent                       bool
	ManifestBytes                         int64
}

func (r RemovalStageCleanup) Valid() bool {
	return r.Original.Valid() && r.Profile == RemovalStageCleanupProfile && ValidDigest(r.JournalRevision) && ValidDigest(r.StateDigest) && r.DirectoryCount >= 1 && r.DirectoryCount <= 7 && r.ManifestBytes >= 0 && r.ManifestBytes <= 2<<20 && (r.ManifestPresent || r.ManifestBytes == 0)
}

func (RemovalStageCleanup) String() string               { return "[NetBird removal stage cleanup descriptor]" }
func (r RemovalStageCleanup) GoString() string           { return r.String() }
func (RemovalStageCleanup) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type removalStageCleanupReferenceWire struct {
	RequestID   string `json:"request_id"`
	CommandHash string `json:"command_hash"`
	Revision    string `json:"revision"`
	ReleaseID   string `json:"release_id"`
}

func EncodeRemovalStageCleanupReference(r RemovalStageCleanupReference) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(removalStageCleanupReferenceWire{r.RequestID, r.CommandHash, r.Revision, r.ReleaseID})
}

func DecodeRemovalStageCleanupReference(data []byte) (RemovalStageCleanupReference, error) {
	var wire removalStageCleanupReferenceWire
	if decode(data, []string{"request_id", "command_hash", "revision", "release_id"}, &wire) != nil {
		return RemovalStageCleanupReference{}, ErrInvalid
	}
	r := RemovalStageCleanupReference{wire.RequestID, wire.CommandHash, wire.Revision, wire.ReleaseID}
	if !r.Valid() {
		return RemovalStageCleanupReference{}, ErrInvalid
	}
	return r, nil
}

type removalStageCleanupDescriptorWire struct {
	Original        json.RawMessage `json:"original"`
	Profile         string          `json:"profile"`
	JournalRevision string          `json:"journal_revision"`
	StateDigest     string          `json:"state_digest"`
	DirectoryCount  int             `json:"directory_count"`
	ManifestPresent bool            `json:"manifest_present"`
	ManifestBytes   int64           `json:"manifest_bytes"`
}

func EncodeRemovalStageCleanup(r RemovalStageCleanup) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	original, err := EncodeRemovalStageCleanupReference(r.Original)
	if err != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(removalStageCleanupDescriptorWire{original, r.Profile, r.JournalRevision, r.StateDigest, r.DirectoryCount, r.ManifestPresent, r.ManifestBytes})
}

func DecodeRemovalStageCleanup(data []byte) (RemovalStageCleanup, error) {
	var wire removalStageCleanupDescriptorWire
	if decode(data, []string{"original", "profile", "journal_revision", "state_digest", "directory_count", "manifest_present", "manifest_bytes"}, &wire) != nil {
		return RemovalStageCleanup{}, ErrInvalid
	}
	original, err := DecodeRemovalStageCleanupReference(wire.Original)
	if err != nil {
		return RemovalStageCleanup{}, ErrInvalid
	}
	r := RemovalStageCleanup{original, wire.Profile, wire.JournalRevision, wire.StateDigest, wire.DirectoryCount, wire.ManifestPresent, wire.ManifestBytes}
	if !r.Valid() {
		return RemovalStageCleanup{}, ErrInvalid
	}
	return r, nil
}

type removalStageCleanupWire struct {
	Version int `json:"version"`
	Identity
	RequestID    string          `json:"request_id"`
	Revision     string          `json:"revision"`
	Operation    string          `json:"operation"`
	StageCleanup json.RawMessage `json:"stage_cleanup"`
	IssuedAt     time.Time       `json:"issued_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

func encodeRemovalStageCleanupCommand(c Command) ([]byte, error) {
	cleanup, err := EncodeRemovalStageCleanup(c.RemovalStageCleanup)
	if err != nil {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(removalStageCleanupWire{c.Version, c.Identity, c.RequestID, c.Revision, c.Operation, cleanup, c.IssuedAt, c.ExpiresAt})
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeRemovalStageCleanupCommand(data []byte) (Command, error) {
	var wire removalStageCleanupWire
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "revision", "operation", "stage_cleanup", "issued_at", "expires_at"}, &wire) != nil {
		return Command{}, ErrInvalid
	}
	cleanup, err := DecodeRemovalStageCleanup(wire.StageCleanup)
	if err != nil {
		return Command{}, ErrInvalid
	}
	c := Command{Version: wire.Version, Identity: wire.Identity, RequestID: wire.RequestID, Revision: wire.Revision, Operation: wire.Operation, RemovalStageCleanup: cleanup, IssuedAt: wire.IssuedAt.UTC(), ExpiresAt: wire.ExpiresAt.UTC()}
	if c.Version != RemovalStageCleanupVersion || !c.Valid() {
		return Command{}, ErrInvalid
	}
	return c, nil
}
