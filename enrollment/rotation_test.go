package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testRotationKeys(t testing.TB, i RecoveryIdentity) (RotationContext, *RecoveryRecipientKey, *RecoveryRecipientKey) {
	t.Helper()
	agent, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	console, err := NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.Close)
	t.Cleanup(console.Close)
	c := RotationContext{Binding: testRecoveryContext(i), Ordinal: 1, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(console.PublicKey())}
	return c, agent, console
}

func rotationNonceHash(nonce []byte) string {
	hash := sha256.Sum256(nonce)
	return hex.EncodeToString(hash[:])
}

func TestRotationRoundTripKeepsBothKeysPrivateAndSurvivesDelayedReceipt(t *testing.T) {
	i, cert, signer := testRecoveryIdentity(t)
	c, agent, console := testRotationKeys(t, i)
	oldKey, newKey := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), []byte("1111-2222-3333-4444-5555-6666")
	nonce := bytes.Repeat([]byte{7}, 32)
	recipient := RecoveryRecipient{ID: c.Binding.RecipientID, Identity: i, PublicKey: agent.PublicKey()}
	task, err := EncryptRotationTask(recipient, c, oldKey, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := agent.OpenRotationTask(*task, i, recipient.ID, time.Now())
	if err != nil || !bytes.Equal(secret.Key(), oldKey) || !bytes.Equal(secret.Nonce(), nonce) || cap(secret.Key()) != 29 {
		t.Fatal("incorrect rotation request decryption", err)
	}
	if _, err = json.Marshal(secret); err == nil || strings.Contains(fmt.Sprintf("%v %#v", secret, secret), string(oldKey)) {
		t.Fatal("rotation material has a public representation")
	}
	borrowedKey, borrowedNonce := secret.Key(), secret.Nonce()
	secret.Close()
	if !bytes.Equal(borrowedKey, make([]byte, 29)) || !bytes.Equal(borrowedNonce, make([]byte, 32)) || secret.Key() != nil {
		t.Fatal("rotation plaintext was not cleared")
	}
	// The endpoint may persist its outcome after the mutation deadline, and
	// deliver it later. That deadline must still prevent a fresh execution.
	later := time.Unix(c.Binding.ExpiresAt+60, 0)
	if _, err = agent.OpenRotationTask(*task, i, recipient.ID, later); err == nil {
		t.Fatal("expired rotation can still be admitted")
	}
	for _, outcome := range []string{"rotated", "unverified", "uncertain", "invalid", "unavailable", "unsupported"} {
		var outputKey []byte
		if outcome == "rotated" || outcome == "unverified" {
			outputKey = newKey
		}
		r, err := NewRotationResult(c, outcome, nonce, outputKey, cert, signer, later)
		if err != nil || VerifyRotationResult(*r, cert, later) != nil {
			t.Fatal("valid late result rejected", outcome, err)
		}
		wire, _ := json.Marshal(RotationRequest{Version: RotationVersion, Protocol: RotationProtocol, AgentID: i.AgentID, Action: "result", Result: r})
		if _, err = DecodeRotationRequest(wire); err != nil || bytes.Contains(wire, oldKey) || bytes.Contains(wire, newKey) {
			t.Fatal("invalid or exposed rotation result", err)
		}
		if outputKey == nil {
			if r.NewKey != nil {
				t.Fatal("key returned for an outcome without key material")
			}
			continue
		}
		returned, err := console.OpenRotationResult(*r, c, rotationNonceHash(nonce), cert, later)
		if err != nil || !bytes.Equal(returned.Key(), newKey) || !bytes.Equal(returned.Nonce(), nonce) {
			t.Fatal("new key did not reach its independent console recipient", err)
		}
		returned.Close()
		if _, err = agent.OpenRotationResult(*r, c, rotationNonceHash(nonce), cert, later); err == nil {
			t.Fatal("agent recipient opened the console's return envelope")
		}
		if _, err = console.OpenRotationResult(*r, c, strings.Repeat("0", 64), cert, later); err == nil {
			t.Fatal("returned key accepted with a different expected nonce")
		}
		if VerifyRotationResult(*r, cert, cert.NotAfter) == nil {
			t.Fatal("expired signing certificate accepted")
		}
	}
}

func TestRotationBindsContextCiphertextAndPurpose(t *testing.T) {
	i, cert, signer := testRecoveryIdentity(t)
	c, agent, console := testRotationKeys(t, i)
	key, nonce := []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), bytes.Repeat([]byte{9}, 32)
	recipient := RecoveryRecipient{ID: c.Binding.RecipientID, Identity: i, PublicKey: agent.PublicKey()}
	task, err := EncryptRotationTask(recipient, c, key, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RotationTask){
		"task":            func(t *RotationTask) { t.Context.Binding.TaskID = uuid.NewString() },
		"native":          func(t *RotationTask) { t.Context.Binding.NativeID = uuid.NewString() },
		"key":             func(t *RotationTask) { t.Context.Binding.KeyID = uuid.NewString() },
		"scope":           func(t *RotationTask) { t.Context.Binding.Identity.SiteID++ },
		"agent":           func(t *RotationTask) { t.Context.Binding.Identity.AgentID = uuid.NewString() },
		"certificate":     func(t *RotationTask) { t.Context.Binding.Identity.CertificateHash = strings.Repeat("e", 64) },
		"recipient":       func(t *RotationTask) { t.Context.Binding.RecipientID = uuid.NewString() },
		"deadline":        func(t *RotationTask) { t.Context.Binding.ExpiresAt++ },
		"ordinal":         func(t *RotationTask) { t.Context.Ordinal++ },
		"escrow":          func(t *RotationTask) { t.Context.EscrowID = uuid.NewString() },
		"reply recipient": func(t *RotationTask) { t.Context.ReplyKey = hex.EncodeToString(agent.PublicKey()) },
		"ciphertext": func(t *RotationTask) {
			t.Envelope.Ciphertext = bytes.Clone(t.Envelope.Ciphertext)
			t.Envelope.Ciphertext[0] ^= 1
		},
		"encapsulation": func(t *RotationTask) {
			t.Envelope.Encapsulation = bytes.Clone(t.Envelope.Encapsulation)
			t.Envelope.Encapsulation[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *task
			mutate(&changed)
			if _, err := agent.OpenRotationTask(changed, i, recipient.ID, time.Now()); err == nil {
				t.Fatal("modified rotation admitted")
			}
		})
	}
	validation, err := EncryptRecoveryTask(recipient, c.Binding, key, nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	transplant := *task
	transplant.Envelope = RotationEnvelope{Encapsulation: validation.Encapsulation, Ciphertext: validation.Ciphertext}
	if _, err = agent.OpenRotationTask(transplant, i, recipient.ID, time.Now()); err == nil {
		t.Fatal("validation ciphertext authorized a mutation")
	}
	validation.Encapsulation, validation.Ciphertext = task.Envelope.Encapsulation, task.Envelope.Ciphertext
	if _, err = agent.Open(*validation, i, recipient.ID, time.Now()); err == nil {
		t.Fatal("rotation ciphertext accepted by the validation protocol")
	}
	r, err := NewRotationResult(c, "rotated", nonce, []byte("1111-2222-3333-4444-5555-6666"), cert, signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"outcome", "nonce", "key", "context"} {
		changed := *r
		switch field {
		case "outcome":
			changed.Outcome = "unverified"
		case "nonce":
			changed.Nonce = bytes.Repeat([]byte{3}, 32)
		case "context":
			changed.Context.Ordinal++
		case "key":
			changed.NewKey = &RotationEnvelope{Encapsulation: bytes.Clone(r.NewKey.Encapsulation), Ciphertext: bytes.Clone(r.NewKey.Ciphertext)}
			changed.NewKey.Ciphertext[0] ^= 1
		}
		if VerifyRotationResult(changed, cert, time.Now()) == nil {
			t.Fatal("worker could change rotation result", field)
		}
	}
	// Even an authentic signature cannot make an unrelated inner nonce match
	// the independent console expectation.
	wrong, err := sealRotation(c, rotationKeyDomain, console.PublicKey(), key, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r.NewKey, r.Signature = wrong, nil
	unsigned, _ := json.Marshal(r)
	r.Signature, err = signRecovery(i, rotationResultDomain, unsigned, cert, signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = console.OpenRotationResult(*r, c, rotationNonceHash(nonce), cert, time.Now()); err == nil {
		t.Fatal("mismatched encrypted return nonce accepted")
	}
}

func TestRotationWireRejectsAmbiguityAndInvalidBounds(t *testing.T) {
	i, cert, signer := testRecoveryIdentity(t)
	c, agent, _ := testRotationKeys(t, i)
	for _, ordinal := range []int{-1, 0, MaxRotationAttempts + 1} {
		changed := c
		changed.Ordinal = ordinal
		if changed.Valid(time.Now()) || changed.ValidReceipt() {
			t.Fatal("unbounded journal ordinal")
		}
	}
	changed := c
	changed.Binding.ExpiresAt = time.Now().Add(RotationTaskLifetime + time.Minute).Unix()
	if changed.Valid(time.Now()) {
		t.Fatal("excessive execution lifetime")
	}
	changed = c
	changed.ReplyKey = strings.ToUpper(c.ReplyKey)
	if changed.ValidReceipt() {
		t.Fatal("noncanonical reply recipient")
	}
	changed.ReplyKey = strings.Repeat("0", 64)
	if changed.ValidReceipt() {
		t.Fatal("low-order reply recipient")
	}
	changed = c
	changed.ReplyKey = hex.EncodeToString(agent.PublicKey())
	if _, err := EncryptRotationTask(RecoveryRecipient{ID: c.Binding.RecipientID, Identity: i, PublicKey: agent.PublicKey()}, changed, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), make([]byte, 32), time.Now()); err == nil {
		t.Fatal("shared request and reply recipient")
	}
	request := RotationRequest{Version: RotationVersion, Protocol: RotationProtocol, AgentID: i.AgentID, Action: "poll", RecipientID: c.Binding.RecipientID}
	encoded, _ := json.Marshal(request)
	if _, err := DecodeRotationRequest(encoded); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(encoded, '\n'), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"unexpected":true,"version":1`), 1), bytes.Repeat([]byte("a"), MaxRecoveryMessage+1)} {
		if _, err := DecodeRotationRequest(bad); err == nil {
			t.Fatal("ambiguous rotation request")
		}
	}
	if _, err := DecodeRecoveryRequest(encoded, time.Now()); err == nil {
		t.Fatal("rotation poll accepted by validation protocol")
	}
	for _, reply := range [][]byte{[]byte(`{"version":1,"ok":true}`), []byte(`{"version":1,"protocol":"validation","ok":true}`)} {
		if _, err := DecodeRotationReply(reply, time.Now()); err == nil {
			t.Fatal("foreign protocol acknowledgement accepted")
		}
	}
	for _, outcome := range []string{"valid", "rotated", "unverified", "uncertain"} {
		key := []byte(nil)
		if outcome == "uncertain" {
			key = []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
		}
		if _, err := NewRotationResult(c, outcome, make([]byte, 32), key, cert, signer, time.Now()); err == nil {
			t.Fatal("invalid outcome/key combination")
		}
	}
}

func FuzzRotationWire(f *testing.F) {
	f.Add([]byte(`{"version":1,"protocol":"filevault-rotation","agent_id":"00000000-0000-4000-8000-000000000001","action":"poll","recipient_id":"00000000-0000-4000-8000-000000000002"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if r, err := DecodeRotationRequest(data); err == nil {
			encoded, err := json.Marshal(r)
			if err != nil || !bytes.Equal(data, encoded) {
				t.Fatal("noncanonical request accepted")
			}
		}
		if r, err := DecodeRotationReply(data, time.Now()); err == nil {
			encoded, err := json.Marshal(r)
			if err != nil || !bytes.Equal(data, encoded) {
				t.Fatal("noncanonical reply accepted")
			}
		}
	})
}

func TestRotationReplySeparatesLiveTasksFromLateReceiptRequests(t *testing.T) {
	i, _, _ := testRecoveryIdentity(t)
	c, agent, _ := testRotationKeys(t, i)
	task, err := EncryptRotationTask(RecoveryRecipient{ID: c.Binding.RecipientID, Identity: i, PublicKey: agent.PublicKey()}, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), make([]byte, 32), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ack := RotationReply{Version: RotationVersion, Protocol: RotationProtocol, OK: true}
	for _, payload := range []string{"ack", "task", "receipt"} {
		r := ack
		if payload == "task" {
			r.Task = task
		}
		if payload == "receipt" {
			r.Receipt = &c
		}
		wire, _ := json.Marshal(r)
		if _, err = DecodeRotationReply(wire, time.Now()); err != nil {
			t.Fatal("valid rotation reply rejected", payload, err)
		}
		_, err = DecodeRotationReply(wire, time.Unix(c.Binding.ExpiresAt+60, 0))
		if (err != nil) != (payload == "task") {
			t.Fatal("wrong expiry rule for rotation reply", payload, err)
		}
		for _, bad := range [][]byte{append(bytes.Clone(wire), '\n'), bytes.Replace(wire, []byte(`"ok":true`), []byte(`"ok":true,"ok":true`), 1), bytes.Replace(wire, []byte(`"ok":true`), []byte(`"ok":true,"unexpected":true`), 1)} {
			if _, err = DecodeRotationReply(bad, time.Now()); err == nil {
				t.Fatal("ambiguous rotation reply accepted", payload)
			}
		}
	}
	for _, change := range []func(*RotationReply){
		func(r *RotationReply) { r.OK = false },
		func(r *RotationReply) { r.Version++ },
		func(r *RotationReply) { r.Task, r.Receipt = task, &c },
		func(r *RotationReply) { r.Receipt = new(RotationContext) },
	} {
		r := ack
		change(&r)
		wire, _ := json.Marshal(r)
		if _, err = DecodeRotationReply(wire, time.Now()); err == nil {
			t.Fatal("invalid rotation reply accepted")
		}
	}
}
