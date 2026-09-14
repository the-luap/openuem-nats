package netbirdcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// RecoveryVersion adds explicit withdrawal of an unattempted command. Version
// one encoding and digests remain unchanged; old agents cannot confirm support.
const RecoveryVersion = 2
const ControlLifetime = 10 * time.Second
const MaxJournalAttempts = 4096

// State is a live journal summary, not a periodic inventory capability claim.
// Revision changes with the local identity, boot, attempts and resolution state.
type State struct {
	Status      string `json:"status"`
	Revision    string `json:"revision"`
	Remaining   int    `json:"remaining"`
	PendingID   string `json:"pending_id"`
	PendingHash string `json:"pending_hash"`
	CanRelease  bool   `json:"can_release"`
}

func (s State) Valid() bool {
	if s.Status == "unavailable" {
		return s == (State{Status: "unavailable"})
	}
	if !ValidDigest(s.Revision) || s.Remaining < 0 || s.Remaining > MaxJournalAttempts {
		return false
	}
	switch s.Status {
	case "ready":
		return s.Remaining > 0 && s.PendingID == "" && s.PendingHash == "" && !s.CanRelease
	case "full":
		return s.Remaining == 0 && s.PendingID == "" && s.PendingHash == "" && !s.CanRelease
	case "busy":
		return ValidRequestID(s.PendingID) && ValidDigest(s.PendingHash) && !s.CanRelease
	case "unconfirmed":
		return ValidRequestID(s.PendingID) && ValidDigest(s.PendingHash)
	default:
		return false
	}
}

// ControlRequest is an expiring state, receipt or explicit release request. For
// release/withdraw, RequestID is also the permanent resolution ID. State is read-only.
type ControlRequest struct {
	Version int `json:"version"`
	Identity
	RequestID   string    `json:"request_id"`
	Kind        string    `json:"kind"`
	ReferenceID string    `json:"reference_id"`
	CommandHash string    `json:"command_hash"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revision    string    `json:"revision,omitempty"`
	Operation   string    `json:"operation,omitempty"`
	// Only version-four native recovery inspection carries this reference.
	RemovalRecoveryOriginal RemovalRecoveryReference `json:"-"`
	// Only version-five inspection carries a descriptor-free original reference.
	RemovalAbsenceOriginal RemovalAbsenceReference `json:"-"`
	// Only version-six inspection carries the original scaffold reference.
	RemovalStageCleanupOriginal RemovalStageCleanupReference `json:"-"`
}

func (c ControlRequest) Valid() bool {
	lifetime := ControlLifetime
	if c.Version == RemovalStageCleanupInspectionVersion {
		lifetime = RemovalStageCleanupInspectionLifetime
	}
	if c.Version == RemovalInspectionVersion {
		lifetime = RemovalInspectionLifetime
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		lifetime = RemovalRecoveryInspectionLifetime
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		lifetime = RemovalAbsenceInspectionLifetime
	}
	if (c.Version != Version && c.Version != RecoveryVersion && c.Version != RemovalInspectionVersion && c.Version != RemovalRecoveryInspectionVersion && c.Version != RemovalAbsenceInspectionVersion && c.Version != RemovalStageCleanupInspectionVersion) || !c.Identity.Valid() || !ValidRequestID(c.RequestID) || c.IssuedAt.Year() < 1970 || c.IssuedAt.Year() > 9999 || c.ExpiresAt.Year() < 1970 || c.ExpiresAt.Year() > 9999 || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > lifetime {
		return false
	}
	if c.Version == RemovalStageCleanupInspectionVersion {
		return c.Kind == "removal-stage-cleanup-state" && c.Individual && c.ReferenceID == "" && c.CommandHash == "" && c.Revision == "" && c.Operation == "" && c.RemovalRecoveryOriginal == (RemovalRecoveryReference{}) && c.RemovalAbsenceOriginal == (RemovalAbsenceReference{}) && c.RemovalStageCleanupOriginal.Valid()
	}
	if c.RemovalStageCleanupOriginal != (RemovalStageCleanupReference{}) {
		return false
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		return c.Kind == "removal-absence-state" && c.Individual && c.ReferenceID == "" && c.CommandHash == "" && c.Revision == "" && c.Operation == "" && c.RemovalRecoveryOriginal == (RemovalRecoveryReference{}) && c.RemovalAbsenceOriginal.Valid()
	}
	if c.RemovalAbsenceOriginal != (RemovalAbsenceReference{}) {
		return false
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		return c.Kind == "removal-recovery-state" && c.Individual && c.ReferenceID == "" && c.CommandHash == "" && c.Revision == "" && c.Operation == "" && c.RemovalRecoveryOriginal.Valid()
	}
	if c.RemovalRecoveryOriginal != (RemovalRecoveryReference{}) {
		return false
	}
	if c.Version == RemovalInspectionVersion {
		return c.Kind == "removal-state" && c.Individual && c.ReferenceID == "" && c.CommandHash == "" && c.Revision == "" && c.Operation == ""
	}
	if c.Version == RecoveryVersion {
		return (c.Kind == "receipt" || c.Kind == "withdraw") && ValidRequestID(c.ReferenceID) && ValidDigest(c.CommandHash) && ValidDigest(c.Revision) && receiptOperationValid(c.Operation) && (!RequiresIndividualIdentity(c.Operation) || c.Individual)
	}
	if c.Revision != "" || c.Operation != "" {
		return false
	}
	switch c.Kind {
	case "preparation-state", "installation-state":
		return c.Individual && c.ReferenceID == "" && c.CommandHash == ""
	case "state", "registration-state":
		return c.ReferenceID == "" && c.CommandHash == ""
	case "receipt", "release":
		return ValidRequestID(c.ReferenceID) && ValidDigest(c.CommandHash)
	default:
		return false
	}
}

func (c ControlRequest) Executable(identity Identity, now time.Time) bool {
	return c.Valid() && identity.Valid() && c.Identity == identity && !now.IsZero() && !c.IssuedAt.After(now.Add(ClockAllowance)) && c.ExpiresAt.After(now)
}

func EncodeControl(c ControlRequest) ([]byte, error) {
	if !c.Valid() {
		return nil, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	if c.Version == RemovalStageCleanupInspectionVersion {
		return encodeRemovalStageCleanupInspection(c)
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		return encodeRemovalAbsenceInspection(c)
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		return encodeRemovalRecoveryInspection(c)
	}
	return json.Marshal(c)
}

func DecodeControl(data []byte) (ControlRequest, error) {
	var c ControlRequest
	var header struct {
		Version int `json:"version"`
	}
	if len(data) > MaxMessage || json.Unmarshal(data, &header) != nil {
		return ControlRequest{}, ErrInvalid
	}
	if header.Version == RemovalStageCleanupInspectionVersion {
		return decodeRemovalStageCleanupInspection(data)
	}
	if header.Version == RemovalAbsenceInspectionVersion {
		return decodeRemovalAbsenceInspection(data)
	}
	if header.Version == RemovalRecoveryInspectionVersion {
		return decodeRemovalRecoveryInspection(data)
	}
	fields := []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "kind", "reference_id", "command_hash", "issued_at", "expires_at"}
	if header.Version == RecoveryVersion {
		fields = append(fields, "revision", "operation")
	}
	if decode(data, fields, &c) != nil || !c.Valid() {
		return ControlRequest{}, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, nil
}

func (c ControlRequest) Digest() (string, error) {
	data, err := EncodeControl(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ControlSubject(device string) (string, error) {
	if !ValidDeviceID(device) {
		return "", ErrInvalid
	}
	return "agent.netbird.control." + device, nil
}

type ControlResponse struct {
	Version int `json:"version"`
	Identity
	RequestID   string  `json:"request_id"`
	RequestHash string  `json:"request_hash"`
	Kind        string  `json:"kind"`
	Outcome     string  `json:"outcome"`
	State       State   `json:"state"`
	Receipt     Receipt `json:"receipt"`
	ReleaseID   string  `json:"release_id"`
	// Only version-three inspection responses include native removal evidence.
	Removal             packageapi.Removal  `json:"-"`
	RemovalRecovery     RemovalRecovery     `json:"-"`
	RemovalAbsence      RemovalAbsence      `json:"-"`
	RemovalStageCleanup RemovalStageCleanup `json:"-"`
}

func ControlResponseFor(c ControlRequest, outcome string) (ControlResponse, error) {
	hash, err := c.Digest()
	if err != nil {
		return ControlResponse{}, err
	}
	return ControlResponse{Version: c.Version, Identity: c.Identity, RequestID: c.RequestID, RequestHash: hash, Kind: c.Kind, Outcome: outcome}, nil
}

func (r ControlResponse) Matches(c ControlRequest) bool {
	hash, err := c.Digest()
	if err != nil || r.Version != c.Version || r.Identity != c.Identity || r.RequestID != c.RequestID || r.RequestHash != hash || r.Kind != c.Kind {
		return false
	}
	if c.Version == RemovalStageCleanupInspectionVersion {
		return r.removalStageCleanupStateMatches(c)
	}
	if r.RemovalStageCleanup != (RemovalStageCleanup{}) {
		return false
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		return r.removalAbsenceStateMatches(c)
	}
	if r.RemovalAbsence != (RemovalAbsence{}) {
		return false
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		return r.removalRecoveryStateMatches(c)
	}
	if r.RemovalRecovery != (RemovalRecovery{}) {
		return false
	}
	if c.Version == RemovalInspectionVersion {
		return r.removalStateMatches()
	}
	if r.Removal != (packageapi.Removal{}) {
		return false
	}
	if r.Outcome != "ok" {
		switch r.Outcome {
		case "missing", "blocked", "conflict", "unavailable":
			return r.State == (State{}) && r.Receipt == (Receipt{}) && r.ReleaseID == ""
		default:
			return false
		}
	}
	switch r.Kind {
	case "state", "registration-state", "preparation-state", "installation-state":
		return r.State.Valid() && r.Receipt == (Receipt{}) && r.ReleaseID == ""
	case "receipt", "release", "withdraw":
		if r.State != (State{}) || !r.Receipt.Valid() || r.Receipt.DeviceID != c.DeviceID || r.Receipt.RequestID != c.ReferenceID || r.Receipt.CommandHash != c.CommandHash || RequiresIndividualIdentity(r.Receipt.Operation) && !c.Individual {
			return false
		}
		if c.Version == RecoveryVersion && (r.Receipt.Revision != c.Revision || r.Receipt.Operation != c.Operation) {
			return false
		}
		switch r.Receipt.Status {
		case "withdrawn":
			return c.Version == RecoveryVersion && ValidRequestID(r.ReleaseID) && (r.Kind == "receipt" || r.Kind == "withdraw" && r.ReleaseID == c.RequestID)
		case "completed", "unconfirmed":
			if r.Kind == "withdraw" {
				return false
			}
		default:
			return false
		}
		if r.ReleaseID != "" && (!ValidRequestID(r.ReleaseID) || r.Receipt.Status != "unconfirmed") {
			return false
		}
		if r.Kind == "release" {
			return r.ReleaseID == c.RequestID && r.Receipt.Status == "unconfirmed"
		}
		return true
	default:
		return false
	}
}

func EncodeControlResponse(c ControlRequest, r ControlResponse) ([]byte, error) {
	if !r.Matches(c) {
		return nil, ErrInvalid
	}
	if c.Version == RemovalStageCleanupInspectionVersion {
		return encodeRemovalStageCleanupState(r)
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		return encodeRemovalAbsenceState(r)
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		return encodeRemovalRecoveryState(r)
	}
	if c.Version == RemovalInspectionVersion {
		return encodeRemovalState(r)
	}
	return json.Marshal(r)
}

func DecodeControlResponse(data []byte, c ControlRequest) (ControlResponse, error) {
	if c.Version == RemovalStageCleanupInspectionVersion {
		return decodeRemovalStageCleanupState(data, c)
	}
	if c.Version == RemovalAbsenceInspectionVersion {
		return decodeRemovalAbsenceState(data, c)
	}
	if c.Version == RemovalRecoveryInspectionVersion {
		return decodeRemovalRecoveryState(data, c)
	}
	if c.Version == RemovalInspectionVersion {
		return decodeRemovalState(data, c)
	}
	var r ControlResponse
	if decode(data, []string{"version", "device_id", "tenant_id", "site_id", "individual", "certificate_hash", "request_id", "request_hash", "kind", "outcome", "state", "receipt", "release_id"}, &r) != nil {
		return ControlResponse{}, ErrInvalid
	}
	// The nested payloads use the same exact-key/type rules as the envelope,
	// including their canonical empty forms when this response does not use them.
	var nested struct {
		State   json.RawMessage `json:"state"`
		Receipt json.RawMessage `json:"receipt"`
	}
	if json.Unmarshal(data, &nested) != nil || decode(nested.State, []string{"status", "revision", "remaining", "pending_id", "pending_hash", "can_release"}, &r.State) != nil || decode(nested.Receipt, []string{"version", "request_id", "device_id", "revision", "command_hash", "operation", "status"}, &r.Receipt) != nil || !r.Matches(c) {
		return ControlResponse{}, ErrInvalid
	}
	return r, nil
}

// Incidental serialization must not silently omit inspection evidence. Existing
// control grammars retain their prior wire shape; use EncodeControlResponse.
type wireControlResponse ControlResponse

func (r ControlResponse) MarshalJSON() ([]byte, error) {
	if r.Version == RemovalStageCleanupInspectionVersion || r.RemovalStageCleanup != (RemovalStageCleanup{}) || r.Version == RemovalAbsenceInspectionVersion || r.RemovalAbsence != (RemovalAbsence{}) || r.Version == RemovalInspectionVersion || r.Version == RemovalRecoveryInspectionVersion || r.Removal != (packageapi.Removal{}) || r.RemovalRecovery != (RemovalRecovery{}) {
		return nil, ErrInvalid
	}
	return json.Marshal(wireControlResponse(r))
}

type wireControlRequest ControlRequest

// Native recovery references require the explicit version-four wire codec.
// Existing control bytes and their incidental serialization stay unchanged.
func (c ControlRequest) MarshalJSON() ([]byte, error) {
	if c.Version == RemovalStageCleanupInspectionVersion || c.RemovalStageCleanupOriginal != (RemovalStageCleanupReference{}) || c.Version == RemovalAbsenceInspectionVersion || c.RemovalAbsenceOriginal != (RemovalAbsenceReference{}) || c.Version == RemovalRecoveryInspectionVersion || c.RemovalRecoveryOriginal != (RemovalRecoveryReference{}) {
		return nil, ErrInvalid
	}
	return json.Marshal(wireControlRequest(c))
}
