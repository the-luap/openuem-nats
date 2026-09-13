// Package netbirdcommand defines expiring, correlated NetBird device commands.
// The protocol is separate from legacy NetBird subjects and their empty replies.
package netbirdcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdapi"
)

const (
	Version             = 1
	RegistrationVersion = 2
	MaxMessage          = 16 << 10
	Lifetime            = 2 * time.Minute
	ClockAllowance      = 5 * time.Second
)

var ErrInvalid = errors.New("invalid NetBird command or receipt")

// Identity binds a command to the configured endpoint and organization. A
// certificate hash is mandatory for individual identities and absent in legacy
// mode. Legacy mode retains the limitations of its shared broker credentials.
type Identity struct {
	DeviceID        string `json:"device_id"`
	TenantID        int64  `json:"tenant_id"`
	SiteID          int64  `json:"site_id"`
	Individual      bool   `json:"individual"`
	CertificateHash string `json:"certificate_hash"`
}

type Command struct {
	Version int `json:"version"`
	Identity
	RequestID     string    `json:"request_id"`
	Revision      string    `json:"revision"`
	Operation     string    `json:"operation"`
	ManagementURL string    `json:"management_url"`
	Profile       string    `json:"profile"`
	SetupKey      string    `json:"setup_key,omitempty"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type Receipt struct {
	Version     int    `json:"version"`
	RequestID   string `json:"request_id"`
	DeviceID    string `json:"device_id"`
	Revision    string `json:"revision"`
	CommandHash string `json:"command_hash"`
	Operation   string `json:"operation"`
	Status      string `json:"status"`
}

// Diagnostic formatting never includes the one-off registration credential.
// Encode is the explicit wire serialization API and does include that field.
func (c Command) String() string   { return "NetBird command (credential redacted)" }
func (c Command) GoString() string { return c.String() }

func ValidRequestID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func ValidDeviceID(id string) bool {
	if len(id) == 0 || len(id) > 255 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func ValidDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == sha256.Size && hex.EncodeToString(data) == value
}

func (i Identity) Valid() bool {
	return ValidDeviceID(i.DeviceID) && i.TenantID > 0 && i.SiteID > 0 &&
		(i.Individual && ValidRequestID(i.DeviceID) && ValidDigest(i.CertificateHash) || !i.Individual && i.CertificateHash == "")
}

func profileValue(value string) bool {
	return len(value) > 0 && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func operationValid(operation, profile string) bool {
	switch operation {
	case "up", "down":
		return profile == ""
	case "switchprofile":
		return profileValue(profile)
	default:
		return false
	}
}

// Valid checks immutable syntax independently of the clock, so retained records
// can still be inspected after expiry. It never authorizes execution by itself.
func (c Command) Valid() bool {
	operation := c.Version == Version && operationValid(c.Operation, c.Profile) && c.SetupKey == "" || c.Version == RegistrationVersion && c.Operation == "register" && c.Profile == "" && validSetupKey(c.SetupKey)
	return operation && c.Identity.Valid() && ValidRequestID(c.RequestID) && ValidDigest(c.Revision) &&
		len(c.ManagementURL) <= 2048 && netbirdapi.ValidBase(c.ManagementURL) &&
		c.IssuedAt.Year() >= 1970 && c.IssuedAt.Year() <= 9999 && c.ExpiresAt.Year() >= 1970 && c.ExpiresAt.Year() <= 9999 &&
		c.ExpiresAt.After(c.IssuedAt) && c.ExpiresAt.Sub(c.IssuedAt) <= Lifetime
}

func validSetupKey(key string) bool {
	if len(key) == 0 || len(key) > 512 {
		return false
	}
	for _, r := range key {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Executable requires the current trusted local identity and an unexpired
// command. Every queued callback must recheck it immediately before admission.
func (c Command) Executable(identity Identity, now time.Time) bool {
	return c.Valid() && identity.Valid() && c.Identity == identity && !now.IsZero() &&
		!c.IssuedAt.After(now.Add(ClockAllowance)) && c.ExpiresAt.After(now)
}

func Encode(c Command) ([]byte, error) {
	if !c.Valid() {
		return nil, ErrInvalid
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	data, err := json.Marshal(c)
	if err != nil || len(data) > MaxMessage {
		return nil, ErrInvalid
	}
	return data, nil
}

func (c Command) Digest() (string, error) {
	data, err := Encode(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Subject is outside AGENTS_STREAM's retrying command filters. Old subscribers
// cannot consume these versioned envelopes as legacy NetBird settings.
func Subject(device string) (string, error) {
	if !ValidDeviceID(device) {
		return "", ErrInvalid
	}
	return "agent.netbird.command." + device, nil
}

func ReceiptFor(c Command, status string) (Receipt, error) {
	digest, err := c.Digest()
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{Version: Version, RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, CommandHash: digest, Operation: c.Operation, Status: status}
	if !r.Valid() {
		return Receipt{}, ErrInvalid
	}
	return r, nil
}

func (r Receipt) Valid() bool {
	if r.Version != Version || !ValidRequestID(r.RequestID) || !ValidDeviceID(r.DeviceID) || !ValidDigest(r.Revision) || !ValidDigest(r.CommandHash) {
		return false
	}
	if r.Operation != "up" && r.Operation != "down" && r.Operation != "switchprofile" && r.Operation != "register" {
		return false
	}
	switch r.Status {
	case "completed", "unconfirmed", "rejected", "busy":
		return true
	default:
		return false
	}
}

func (r Receipt) Matches(c Command) bool {
	digest, err := c.Digest()
	return err == nil && r.Valid() && r.RequestID == c.RequestID && r.DeviceID == c.DeviceID && r.Revision == c.Revision && r.Operation == c.Operation && r.CommandHash == digest
}

func EncodeReceipt(r Receipt) ([]byte, error) {
	if !r.Valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(r)
}
