package enrollment

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

const HardwareInventoryVersion = 1
const MacBindingDomain = "eu.openuem.device-binding"

var ErrHardwareInventory = errors.New("invalid Mac hardware inventory")

// HardwareInventory is sent only through an individually authorized subject.
// IDs are hardware observations, not a substitute for either channel's key proof.
type HardwareInventory struct {
	Version          int              `json:"version"`
	AgentID          string           `json:"agent_id"`
	Model            string           `json:"model"`
	Serial           string           `json:"serial"`
	PlatformUUID     string           `json:"platform_uuid"`
	ProvisioningUDID string           `json:"provisioning_udid,omitempty"`
	Binding          *MacBindingProof `json:"binding,omitempty"`
}

// MacBindingProof is provisioned over MDM and returned over the agent's channel.
// Never print it or include it in the ordinary desktop inventory JSON.
type MacBindingProof struct {
	ChallengeID string `json:"challenge_id" plist:"ChallengeID"`
	DeviceID    string `json:"device_id" plist:"DeviceID"`
	Token       string `json:"token" plist:"Token"`
}

type HardwareReceipt struct {
	Version int  `json:"version"`
	OK      bool `json:"ok"`
}

var macHardwareModel = regexp.MustCompile(`^(Mac|MacBookPro|MacBookAir|MacBook|Macmini|MacPro|MacStudio|iMac|iMacPro|Xserve)[0-9]+,[0-9]+$`)
var macHardwareSerial = regexp.MustCompile(`^[A-Z0-9]{8,32}$`)
var provisioningID = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{16}$`)

func (p MacBindingProof) Valid() bool {
	data, err := base64.RawURLEncoding.DecodeString(p.Token)
	return ValidDeviceID(p.ChallengeID) && ValidDeviceID(p.DeviceID) && err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == p.Token
}

func NormalizeHardware(h HardwareInventory) (HardwareInventory, error) {
	if h.Version != HardwareInventoryVersion || !ValidDeviceID(h.AgentID) || !macHardwareModel.MatchString(h.Model) {
		return HardwareInventory{}, ErrHardwareInventory
	}
	h.Serial = strings.ToUpper(strings.TrimSpace(h.Serial))
	h.PlatformUUID = strings.ToUpper(strings.TrimSpace(h.PlatformUUID))
	h.ProvisioningUDID = strings.ToUpper(strings.TrimSpace(h.ProvisioningUDID))
	if !macHardwareSerial.MatchString(h.Serial) || strings.Trim(h.Serial, "0") == "" || !ValidDeviceID(strings.ToLower(h.PlatformUUID)) {
		return HardwareInventory{}, ErrHardwareInventory
	}
	if h.ProvisioningUDID != "" && !ValidDeviceID(strings.ToLower(h.ProvisioningUDID)) && (!provisioningID.MatchString(h.ProvisioningUDID) || strings.Trim(h.ProvisioningUDID, "0-") == "") {
		return HardwareInventory{}, ErrHardwareInventory
	}
	if h.Binding != nil {
		if !h.Binding.Valid() {
			return HardwareInventory{}, ErrHardwareInventory
		}
		copy := *h.Binding
		h.Binding = &copy
	}
	return h, nil
}
