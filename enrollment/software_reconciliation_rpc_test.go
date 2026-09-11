package enrollment

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSoftwareReconciliationRPCSeparatesExecutableAndReadOnlyActions(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	hash, _ := task.Digest()
	result, err := SignSoftwareReconciliationResult(task.Context, hash, bytes.Repeat([]byte{7}, 32), testSoftwareReconciliationOutcome(), f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignSoftwareReconciliationSubmission(*result, f.identity, f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []SoftwareReconciliationRequest{
		{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, AgentID: f.identity.AgentID, Action: "poll"},
		{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, AgentID: f.identity.AgentID, Action: "result", Result: result, Submission: proof},
	} {
		data, _ := json.Marshal(request)
		if _, err := DecodeSoftwareReconciliationRequest(data, f.now); err != nil {
			t.Fatal("canonical request rejected", err)
		}
		if _, err := DecodeSoftwareRequest(data, f.now); err == nil {
			t.Fatal("reconciliation entered executable RPC grammar")
		}
		for _, malformed := range [][]byte{nil, append(bytes.Clone(data), '\n'), append([]byte(`{"unknown":1,`), data[1:]...), append([]byte(`{"action":"poll",`), data[1:]...), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1.0`), 1), bytes.Repeat([]byte("x"), MaxSoftwareMessage+1)} {
			if _, err := DecodeSoftwareReconciliationRequest(malformed, f.now); err == nil {
				t.Fatal("noncanonical request accepted")
			}
		}
		for _, action := range []string{"challenge", "register", "cancel", "install", ""} {
			wrong := request
			wrong.Action = action
			data, _ := json.Marshal(wrong)
			if _, err := DecodeSoftwareReconciliationRequest(data, f.now); err == nil {
				t.Fatal("unrecognized read-only action accepted")
			}
		}
		wrong := request
		if wrong.Action == "poll" {
			wrong.Result, wrong.Submission = result, proof
		} else {
			wrong.Submission = nil
		}
		data, _ = json.Marshal(wrong)
		if _, err := DecodeSoftwareReconciliationRequest(data, f.now); err == nil {
			t.Fatal("mixed or incomplete action accepted")
		}
	}
	receipt, _ := SoftwareReconciliationReceipt(*result, f.now)
	for _, reply := range []SoftwareReconciliationReply{
		{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, OK: true},
		{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, OK: true, Task: task},
		{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, OK: true, Receipt: receipt},
	} {
		data, _ := json.Marshal(reply)
		if _, err := DecodeSoftwareReconciliationReply(data, f.now); err != nil {
			t.Fatal("canonical reply rejected", err)
		}
		if _, err := DecodeSoftwareReply(data, f.now); err == nil {
			t.Fatal("read-only reply entered executable grammar")
		}
		wrong := reply
		wrong.Task, wrong.Receipt = task, receipt
		data, _ = json.Marshal(wrong)
		if _, err := DecodeSoftwareReconciliationReply(data, f.now); err == nil {
			t.Fatal("ambiguous reply accepted")
		}
	}
	executable, _ := json.Marshal(SoftwareRequest{Version: SoftwareVersion, Protocol: SoftwareProtocol, AgentID: f.identity.AgentID, Action: "poll", RecipientID: f.context.RecipientID})
	if _, err := DecodeSoftwareReconciliationRequest(executable, f.now); err == nil {
		t.Fatal("executable poll entered reconciliation grammar")
	}
}
