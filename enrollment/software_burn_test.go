package enrollment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testBurnPlan() SoftwarePlan {
	p := testSoftwarePlan()
	p.Kind = "windows-burn"
	p.Artifact.Format = "exe"
	p.Artifact.URL = "https://packages.example.test/owned.exe?token=private-burn"
	p.Arguments, p.MSIProperties = []string{"/quiet", "/norestart"}, nil
	p.Detection = SoftwareDetection{Kind: "uninstall-key", UninstallKey: p.Detection.ProductCode, RegistryView: "64", Version: "1.2.3.4"}
	return p
}

func TestSoftwareBurnPlanHasAnExplicitStrictContract(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, operation := range []string{"install", "remove"} {
			p := testBurnPlan()
			p.Architecture, p.Operation = arch, operation
			if operation == "remove" {
				p.Arguments = []string{"/uninstall", "/quiet", "/norestart"}
			}
			wire, err := p.Canonical()
			if err != nil {
				t.Fatal("canonical Burn plan", err)
			}
			if got, err := DecodeSoftwarePlan(wire); err != nil || got.Kind != "windows-burn" || got.Detection != p.Detection || got.Operation != operation {
				t.Fatal("Burn identity lost in canonical plan", err)
			}
			burnHash, _ := p.Digest()
			p.Kind = "windows-exe"
			genericHash, err := p.Digest()
			if err != nil || burnHash == genericHash {
				t.Fatal("Burn proof requirement did not change signed intent")
			}
		}
	}
	for _, change := range []func(*SoftwarePlan){
		func(p *SoftwarePlan) { p.Detection.UninstallKey = "Owned.GenericEXE" },
		func(p *SoftwarePlan) { p.Detection.UninstallKey = strings.ToLower(p.Detection.UninstallKey) },
		func(p *SoftwarePlan) { p.Detection.UninstallKey = "{00000000-0000-0000-0000-000000000000}" },
		func(p *SoftwarePlan) { p.Detection.RegistryView = "32" },
		func(p *SoftwarePlan) { p.Detection = testSoftwarePlan().Detection },
		func(p *SoftwarePlan) { p.Architecture = "386" },
		func(p *SoftwarePlan) { p.Artifact = SoftwareArtifact{} },
		func(p *SoftwarePlan) { p.Arguments = []string{"/quiet", "/forcerestart"} },
		func(p *SoftwarePlan) { p.Arguments = []string{"/quiet", "/norestart", "Private=argument"} },
		func(p *SoftwarePlan) { p.Operation = "remove" },
		func(p *SoftwarePlan) { p.MSIProperties = map[string]string{"OWNED": "value"} },
		func(p *SoftwarePlan) { p.SuccessCodes = []uint32{0, 123} },
		func(p *SoftwarePlan) { p.RebootCodes = nil },
	} {
		p := testBurnPlan()
		change(&p)
		if p.Valid() {
			t.Fatal("unsupported Burn behavior admitted")
		}
	}
}

func TestSoftwareBurnCapabilityBindsSignaturesAndEncryptedDelivery(t *testing.T) {
	f := testSoftwareFixture(t)
	r := SoftwareRegistration{Version: SoftwareVersion, Protocol: SoftwareProtocol, Identity: f.identity, ID: f.recipientInfo.ID, PublicKey: f.recipient.PublicKey(), Nonce: bytes.Repeat([]byte{8}, 32), ExpiresAt: f.now.Add(5 * time.Minute).Unix()}
	for _, version := range []int{0, SoftwareBurnVersion} {
		r.BurnVersion = version
		signature, err := SignSoftwareRegistration(r, f.certificate, f.signer, f.now)
		if err != nil || VerifySoftwareRegistration(r, signature, f.certificate, f.now) != nil {
			t.Fatal("signed capability denied", err)
		}
		r.BurnVersion = 1 - version
		if VerifySoftwareRegistration(r, signature, f.certificate, f.now) == nil {
			t.Fatal("capability added or removed without a new device signature")
		}
	}
	p := testBurnPlan()
	f.context.PlanHash, _ = p.Digest()
	f.context.Expectation = p.Expectation()
	if _, err := SealSoftwareTask(f.recipientInfo, f.context, p, bytes.Repeat([]byte{7}, 32), f.authority, f.issuer, f.now); err == nil {
		t.Fatal("legacy recipient received Burn execution intent")
	}
	f.recipientInfo.BurnVersion = SoftwareBurnVersion
	task, err := SealSoftwareTask(f.recipientInfo, f.context, p, bytes.Repeat([]byte{7}, 32), f.authority, f.issuer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := f.recipient.Open(*task, f.authority, f.identity, f.recipientInfo.ID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	if secret.Plan.Kind != "windows-burn" || secret.Plan.Detection != p.Detection {
		t.Fatal("encrypted task lost the required Burn proof")
	}
	for _, version := range []int{-1, 2, 999} {
		r.BurnVersion = version
		f.recipientInfo.BurnVersion = version
		if r.Valid(f.now) || f.recipientInfo.Valid() {
			t.Fatal("unknown capability admitted")
		}
	}
}

func TestSoftwareBurnWirePreservesLegacyOmissionAndActionBounds(t *testing.T) {
	f := testSoftwareFixture(t)
	request := SoftwareRequest{Version: SoftwareVersion, Protocol: SoftwareProtocol, AgentID: f.identity.AgentID, Action: "challenge", PublicKey: f.recipient.PublicKey()}
	legacy, _ := json.Marshal(request)
	if bytes.Contains(legacy, []byte("burn_version")) {
		t.Fatal("legacy challenge changed")
	}
	if _, err := DecodeSoftwareRequest(legacy, f.now); err != nil {
		t.Fatal("legacy challenge rejected", err)
	}
	for _, version := range []int{1, -1, 2} {
		request.BurnVersion = version
		wire, _ := json.Marshal(request)
		_, err := DecodeSoftwareRequest(wire, f.now)
		if (err == nil) != (version == 1) {
			t.Fatal("capability negotiation grammar", version, err)
		}
	}
	request = SoftwareRequest{Version: SoftwareVersion, Protocol: SoftwareProtocol, AgentID: f.identity.AgentID, Action: "poll", RecipientID: f.recipientInfo.ID, BurnVersion: 1}
	wire, _ := json.Marshal(request)
	if _, err := DecodeSoftwareRequest(wire, f.now); err == nil {
		t.Fatal("poll substituted an unsigned capability update")
	}
	for _, value := range []any{f.recipientInfo, SoftwareRegistration{Version: 1}} {
		wire, _ := json.Marshal(value)
		if bytes.Contains(wire, []byte("burn_version")) {
			t.Fatal("legacy registration or recipient encoding changed")
		}
	}
}
