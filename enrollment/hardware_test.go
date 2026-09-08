package enrollment

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHardwareInventoryRejectsAmbiguousIDsAndKeepsProofSeparate(t *testing.T) {
	good := HardwareInventory{Version: 1, AgentID: "11111111-2222-3333-4444-555555555555", Model: "Mac16,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ProvisioningUDID: "00006001-001234567890ABCD"}
	normalized, err := NormalizeHardware(good)
	if err != nil || normalized.PlatformUUID != good.PlatformUUID {
		t.Fatal(err)
	}
	for _, change := range []func(*HardwareInventory){
		func(h *HardwareInventory) { h.Version = 2 }, func(h *HardwareInventory) { h.AgentID = strings.ToUpper(h.PlatformUUID) },
		func(h *HardwareInventory) { h.Model = "MacAttack" }, func(h *HardwareInventory) { h.Model = "iPhone16,1" },
		func(h *HardwareInventory) { h.Serial = "System Serial Number" }, func(h *HardwareInventory) { h.PlatformUUID = "00000000-0000-0000-0000-000000000000" },
		func(h *HardwareInventory) { h.ProvisioningUDID = "00000000-0000000000000000" }, func(h *HardwareInventory) { h.ProvisioningUDID = "bad\nidentifier" },
		func(h *HardwareInventory) {
			h.Binding = &MacBindingProof{ChallengeID: h.AgentID, DeviceID: h.AgentID, Token: "wrong"}
		},
	} {
		h := good
		change(&h)
		if _, err := NormalizeHardware(h); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	good.Binding = &MacBindingProof{ChallengeID: good.AgentID, DeviceID: good.AgentID, Token: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("t", 32)))}
	normalized, err = NormalizeHardware(good)
	if err != nil {
		t.Fatal(err)
	}
	normalized.Binding.Token = "modified"
	if normalized.Binding.Token == good.Binding.Token {
		t.Fatal("normalization retained mutable proof pointer")
	}
}
