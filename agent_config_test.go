package nats

import (
	"encoding/json"
	"testing"
)

func TestAgentConfigBurnHintPreservesLegacyWire(t *testing.T) {
	legacy := `{"software_task_version":1,"ok":true}`
	var config Config
	if err := json.Unmarshal([]byte(legacy), &config); err != nil || config.SoftwareBurnVersion != 0 {
		t.Fatal("legacy configuration acquired Burn support", err)
	}
	wire, err := json.Marshal(config)
	if err != nil || string(wire) != legacy {
		t.Fatal("legacy configuration wire changed", err)
	}
	config.SoftwareBurnVersion = 1
	wire, err = json.Marshal(config)
	var decoded Config
	if err != nil || json.Unmarshal(wire, &decoded) != nil || decoded.SoftwareBurnVersion != 1 || decoded.SoftwareTaskVersion != 1 {
		t.Fatal("explicit Burn profile hint did not survive transport", err)
	}
}
