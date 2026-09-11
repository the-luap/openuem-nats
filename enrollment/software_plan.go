package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const SoftwareVersion = 1

// SoftwareBurnVersion requires explicit recipient registration. Existing MSI/EXE
// plans retain their canonical encoding and execution rules.
const SoftwareBurnVersion = 1
const SoftwareProtocol = "openuem/windows-software/v1"
const MaxSoftwarePlan = 32 << 10
const MaxSoftwareMessage = 64 << 10

var ErrSoftware = errors.New("the approved Windows software operation is unavailable")

// SoftwarePlan is private execution data, not a catalog or log model. Only the
// explicit canonical codec may serialize it at the encryption/storage boundary.
// The first delivery adapters are immutable custom MSI/EXE artifacts. A WinGet
// coordinate alone never qualifies as an executable plan.
type SoftwarePlan struct {
	Kind          string            `json:"kind"`
	Operation     string            `json:"operation"`
	Identifier    string            `json:"identifier"`
	Version       string            `json:"version"`
	Architecture  string            `json:"architecture"`
	MinimumOS     string            `json:"minimum_os"`
	Artifact      SoftwareArtifact  `json:"artifact"`
	Arguments     []string          `json:"arguments"`
	MSIProperties map[string]string `json:"msi_properties"`
	Detection     SoftwareDetection `json:"detection"`
	SuccessCodes  []uint32          `json:"success_codes"`
	RebootCodes   []uint32          `json:"reboot_codes"`
}
type softwarePlanWire SoftwarePlan

func (SoftwarePlan) String() string               { return "[protected Windows software plan]" }
func (p SoftwarePlan) GoString() string           { return p.String() }
func (SoftwarePlan) MarshalJSON() ([]byte, error) { return nil, ErrSoftware }

type SoftwareArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
}

func (SoftwareArtifact) String() string     { return "[protected Windows software artifact]" }
func (a SoftwareArtifact) GoString() string { return a.String() }

type SoftwareDetection struct {
	Kind         string `json:"kind"`
	ProductCode  string `json:"product_code,omitempty"`
	UninstallKey string `json:"uninstall_key,omitempty"`
	RegistryView string `json:"registry_view,omitempty"`
	Version      string `json:"version"`
}

// SoftwareExpectation is the safe, signed part needed to validate a receipt
// without exposing artifact URLs, installer arguments or property values.
type SoftwareExpectation struct {
	Operation    string            `json:"operation"`
	Detection    SoftwareDetection `json:"detection"`
	SuccessCodes []uint32          `json:"success_codes"`
	RebootCodes  []uint32          `json:"reboot_codes"`
}

func (e SoftwareExpectation) Valid() bool {
	if (e.Operation != "install" && e.Operation != "remove") || !e.Detection.Valid() || len(e.SuccessCodes) == 0 || len(e.SuccessCodes) > 16 || len(e.RebootCodes) > 16 || !slices.Contains(e.SuccessCodes, uint32(0)) {
		return false
	}
	seen := map[uint32]bool{}
	for _, codes := range [][]uint32{e.SuccessCodes, e.RebootCodes} {
		for _, code := range codes {
			if seen[code] {
				return false
			}
			seen[code] = true
		}
	}
	return true
}
func (p SoftwarePlan) Expectation() SoftwareExpectation {
	return SoftwareExpectation{Operation: p.Operation, Detection: p.Detection, SuccessCodes: slices.Clone(p.SuccessCodes), RebootCodes: slices.Clone(p.RebootCodes)}
}
func (e SoftwareExpectation) Equal(other SoftwareExpectation) bool {
	return e.Operation == other.Operation && e.Detection == other.Detection && slices.Equal(e.SuccessCodes, other.SuccessCodes) && slices.Equal(e.RebootCodes, other.RebootCodes)
}

func softwareText(s string, n int) bool {
	return s != "" && len(s) <= n && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func softwareArgument(s string) bool {
	return len(s) <= 2048 && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func softwareDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func (d SoftwareDetection) Valid() bool {
	if !softwareText(d.Version, 128) || strings.TrimSpace(d.Version) != d.Version {
		return false
	}
	switch d.Kind {
	case "msi-product":
		if len(d.ProductCode) != 38 || d.ProductCode[0] != '{' || d.ProductCode[37] != '}' || !ValidDeviceID(strings.ToLower(d.ProductCode[1:37])) || d.ProductCode != strings.ToUpper(d.ProductCode) || d.UninstallKey != "" || d.RegistryView != "" {
			return false
		}
	case "uninstall-key":
		if !softwareText(d.UninstallKey, 255) || strings.TrimSpace(d.UninstallKey) != d.UninstallKey || strings.ContainsAny(d.UninstallKey, `\/`) || d.ProductCode != "" || (d.RegistryView != "32" && d.RegistryView != "64") {
			return false
		}
	default:
		return false
	}
	return true
}

var softwareIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
var softwareMinimumOS = regexp.MustCompile(`^10\.0\.[1-9][0-9]{3,4}(\.(0|[1-9][0-9]{0,5}))?$`)
var softwareProperty = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func (a SoftwareArtifact) Valid() bool {
	if (a.Format != "msi" && a.Format != "exe") || !softwareDigest(a.SHA256) || !softwareText(a.URL, 8192) {
		return false
	}
	for _, c := range a.URL {
		if c <= 32 || c > 126 {
			return false
		}
	}
	u, err := url.ParseRequestURI(a.URL)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") || strings.Contains(a.URL, "#") || !strings.HasSuffix(strings.ToLower(u.Path), "."+a.Format) {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func (p SoftwarePlan) Valid() bool {
	if (p.Kind != "windows-msi" && p.Kind != "windows-exe" && p.Kind != "windows-burn") || (p.Operation != "install" && p.Operation != "remove") || !softwareIdentifier.MatchString(p.Identifier) || !softwareText(p.Version, 128) || !softwareMinimumOS.MatchString(p.MinimumOS) || (p.Architecture != "amd64" && p.Architecture != "arm64") || !p.Detection.Valid() {
		return false
	}
	if len(p.Arguments) > 32 || len(p.MSIProperties) > 32 || len(p.SuccessCodes) == 0 || len(p.SuccessCodes) > 16 || len(p.RebootCodes) > 16 || !slices.Contains(p.SuccessCodes, uint32(0)) {
		return false
	}
	seen := map[uint32]bool{}
	for _, codes := range [][]uint32{p.SuccessCodes, p.RebootCodes} {
		for _, code := range codes {
			if seen[code] {
				return false
			}
			seen[code] = true
		}
	}
	for _, arg := range p.Arguments {
		if !softwareArgument(arg) {
			return false
		}
	}
	for key, value := range p.MSIProperties {
		// MSI's property parser has its own quoting rules. Do not transform an
		// approved value into another command or silently reinterpret quotes.
		if !softwareProperty.MatchString(key) || !softwareArgument(value) || strings.Contains(value, `"`) || slices.Contains([]string{"REBOOT", "REBOOTPROMPT", "ALLUSERS", "MSIINSTALLPERUSER", "TRANSFORMS", "PATCH", "ADDLOCAL", "REMOVE", "ACTION", "INSTALL", "UNINSTALL", "TARGETDIR"}, key) {
			return false
		}
	}
	if p.Kind == "windows-exe" || p.Kind == "windows-burn" {
		if p.Artifact.Format != "exe" || !p.Artifact.Valid() || len(p.Arguments) == 0 || len(p.MSIProperties) != 0 {
			return false
		}
		if p.Kind == "windows-burn" {
			// Only native 64-bit machine bundles with one exact ARP identity are
			// eligible. The helper separately proves this identity in the binary.
			code := p.Detection.UninstallKey
			if p.Detection.Kind != "uninstall-key" || p.Detection.RegistryView != "64" || len(code) != 38 || code[0] != '{' || code[37] != '}' || code != strings.ToUpper(code) || !ValidDeviceID(strings.ToLower(code[1:37])) || !slices.Equal(p.SuccessCodes, []uint32{0}) || !slices.Equal(p.RebootCodes, []uint32{3010}) {
				return false
			}
			args := []string{"/quiet", "/norestart"}
			if p.Operation == "remove" {
				args = append([]string{"/uninstall"}, args...)
			}
			if !slices.Equal(p.Arguments, args) {
				return false
			}
		}
	} else {
		if p.Detection.Kind != "msi-product" || len(p.Arguments) != 0 || !slices.Equal(p.SuccessCodes, []uint32{0}) || !slices.Equal(p.RebootCodes, []uint32{3010}) {
			return false
		}
		if p.Operation == "install" {
			if p.Artifact.Format != "msi" || !p.Artifact.Valid() {
				return false
			}
		} else if p.Artifact != (SoftwareArtifact{}) || len(p.MSIProperties) != 0 {
			return false
		}
	}
	data, err := json.Marshal(softwarePlanWire(p))
	defer clear(data)
	return err == nil && len(data) <= MaxSoftwarePlan
}

func (p SoftwarePlan) Canonical() ([]byte, error) {
	if !p.Valid() {
		return nil, ErrSoftware
	}
	return json.Marshal(softwarePlanWire(p))
}
func (p SoftwarePlan) Digest() (string, error) {
	data, err := p.Canonical()
	if err != nil {
		return "", err
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
func DecodeSoftwarePlan(data []byte) (*SoftwarePlan, error) {
	var wire softwarePlanWire
	if len(data) == 0 || len(data) > MaxSoftwarePlan || json.Unmarshal(data, &wire) != nil {
		return nil, ErrSoftware
	}
	p := SoftwarePlan(wire)
	canonical, err := p.Canonical()
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrSoftware
	}
	return &p, nil
}

type SoftwareObservation struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
}

func (o SoftwareObservation) Valid() bool {
	return ((o.State == "absent" || o.State == "unknown") && o.Version == "") || (o.State == "present" && softwareText(o.Version, 128))
}
func (o SoftwareObservation) Matches(d SoftwareDetection) bool {
	return d.Valid() && o.Valid() && o.State == "present" && o.Version == d.Version
}

// SoftwareOutcome reports process facts separately from exact native evidence.
// It does not treat a successful exit, interruption, or restart request as proof
// that the required installation/removal completed.
type SoftwareOutcome struct {
	State     string              `json:"state"`
	Execution string              `json:"execution"`
	ExitCode  *uint32             `json:"exit_code,omitempty"`
	Before    SoftwareObservation `json:"before"`
	After     SoftwareObservation `json:"after"`
	Error     string              `json:"error,omitempty"`
}

func (o SoftwareOutcome) Valid() bool {
	if !slices.Contains([]string{"not_started", "started", "unknown"}, o.Execution) || !o.Before.Valid() || !o.After.Valid() || (o.Execution != "started" && o.ExitCode != nil) {
		return false
	}
	if !slices.Contains([]string{"", "incompatible", "version_conflict", "preflight", "download", "signature", "changed_file", "execution", "detection", "interrupted", "journal", "unavailable"}, o.Error) {
		return false
	}
	switch o.State {
	case "observed":
		return o.Error == "" && ((o.Execution == "not_started" && o.ExitCode == nil) || (o.Execution == "started" && o.ExitCode != nil))
	case "not_started":
		return o.Execution == "not_started" && o.ExitCode == nil && o.Error != ""
	case "restart_required":
		return o.Execution == "started" && o.ExitCode != nil && o.Error == ""
	case "failed":
		return o.Execution == "started" && o.ExitCode != nil && o.Error != ""
	case "uncertain":
		return o.Error != ""
	default:
		return false
	}
}
func (o SoftwareOutcome) ValidFor(p SoftwarePlan) bool {
	if !p.Valid() || !o.Valid() {
		return false
	}
	return o.ValidForExpectation(p.Expectation())
}
func (o SoftwareOutcome) ValidForExpectation(expected SoftwareExpectation) bool {
	if !expected.Valid() || !o.Valid() {
		return false
	}
	reached := o.After.Matches(expected.Detection)
	if expected.Operation == "remove" {
		reached = o.After.State == "absent"
	}
	switch o.State {
	case "observed":
		if !reached {
			return false
		}
		if o.Execution == "started" {
			return slices.Contains(expected.SuccessCodes, *o.ExitCode)
		}
		return o.Before == o.After
	case "restart_required":
		return slices.Contains(expected.RebootCodes, *o.ExitCode)
	case "failed":
		return !slices.Contains(expected.SuccessCodes, *o.ExitCode) && !slices.Contains(expected.RebootCodes, *o.ExitCode)
	default:
		return true
	}
}
