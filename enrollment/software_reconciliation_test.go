package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testSoftwareReconciliation(t testing.TB, f *softwareFixture) *SoftwareReconciliationTask {
	t.Helper()
	hash, err := f.task.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c := SoftwareReconciliationContext{Version: SoftwareReconciliationVersion, Protocol: SoftwareReconciliationProtocol, Identity: f.identity, ID: uuid.NewString(), Original: f.context, OriginalTaskHash: hash, CreatedAt: f.now.Unix(), ExpiresAt: f.now.Add(20 * time.Minute).Unix()}
	task, err := SignSoftwareReconciliationTask(c, f.authority, f.issuer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func testSoftwareReconciliationOutcome() SoftwareReconciliationOutcome {
	return SoftwareReconciliationOutcome{State: "observed", Admission: SoftwareBootSession{Sequence: 14, SystemProcessCreated: 133000000000000000}, Current: SoftwareBootSession{Sequence: 15, SystemProcessCreated: 133000100000000000}, Observation: SoftwareObservation{State: "present", Version: "1.2.3"}}
}

func TestSoftwareReconciliationTaskBindsOriginalAndCurrentAuthority(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	if err := VerifySoftwareReconciliationTask(*task, f.authority, f.identity, f.now); err != nil {
		t.Fatal(err)
	}
	if err := VerifySoftwareReconciliationTask(*task, f.authority, f.identity, f.now.Add(time.Hour)); err == nil {
		t.Fatal("expired reconciliation authorized an observation")
	}
	if err := VerifySoftwareReconciliationTaskHistory(*task, f.authority); err != nil {
		t.Fatal("historical verification failed", err)
	}
	other := testSoftwareFixture(t)
	if VerifySoftwareReconciliationTask(*task, other.authority, f.identity, f.now) == nil {
		t.Fatal("foreign authority accepted")
	}
	identity := f.identity
	identity.CertificateHash = strings.Repeat("b", 64)
	if VerifySoftwareReconciliationTask(*task, f.authority, identity, f.now) == nil {
		t.Fatal("old reconciliation rebound to renewed identity")
	}
	mutations := map[string]func(*SoftwareReconciliationTask){
		"reconciliation id": func(v *SoftwareReconciliationTask) { v.Context.ID = uuid.NewString() },
		"original task":     func(v *SoftwareReconciliationTask) { v.Context.Original.TaskID = uuid.NewString() },
		"original hash":     func(v *SoftwareReconciliationTask) { v.Context.OriginalTaskHash = strings.Repeat("b", 64) },
		"original generation": func(v *SoftwareReconciliationTask) {
			v.Context.Original.Identity.CertificateHash = strings.Repeat("b", 64)
		},
		"plan":                   func(v *SoftwareReconciliationTask) { v.Context.Original.PlanHash = strings.Repeat("b", 64) },
		"expected version":       func(v *SoftwareReconciliationTask) { v.Context.Original.Expectation.Detection.Version = "9.0.0" },
		"operation":              func(v *SoftwareReconciliationTask) { v.Context.Original.Expectation.Operation = "remove" },
		"deadline":               func(v *SoftwareReconciliationTask) { v.Context.ExpiresAt++ },
		"signature":              func(v *SoftwareReconciliationTask) { v.Signature = bytes.Repeat([]byte{1}, 64) },
		"executable certificate": func(v *SoftwareReconciliationTask) { v.SigningCertificate = f.task.SigningCertificate },
		"executable signature":   func(v *SoftwareReconciliationTask) { v.Signature = f.task.Signature },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := *task
			mutate(&v)
			if VerifySoftwareReconciliationTask(v, f.authority, f.identity, f.now) == nil {
				t.Fatal("modified command accepted")
			}
		})
	}
	encoded, _ := json.Marshal(task)
	for _, private := range []string{"private-download", "private-license", "packages.example.test", "msi_properties", "arguments", "ciphertext"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("read-only task contains execution material")
		}
	}
	if _, err := DecodeSoftwareTask(encoded); err == nil {
		t.Fatal("reconciliation decoded as executable task")
	}
	executable := *f.task
	executable.SigningCertificate, executable.Signature = task.SigningCertificate, task.Signature
	if VerifySoftwareTask(executable, f.authority, f.identity, f.context.RecipientID, f.now) == nil {
		t.Fatal("read-only command signature authorized an installer")
	}
}

func TestSoftwareReconciliationContextRejectsScopeAndLifetimeDrift(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	for name, mutate := range map[string]func(*SoftwareReconciliationContext){
		"old protocol":         func(c *SoftwareReconciliationContext) { c.Protocol = SoftwareProtocol },
		"future version":       func(c *SoftwareReconciliationContext) { c.Version++ },
		"same id":              func(c *SoftwareReconciliationContext) { c.ID = c.Original.TaskID },
		"foreign device":       func(c *SoftwareReconciliationContext) { c.Identity.AgentID = uuid.NewString() },
		"foreign site":         func(c *SoftwareReconciliationContext) { c.Identity.SiteID++ },
		"foreign organization": func(c *SoftwareReconciliationContext) { c.Identity.TenantID++ },
		"before original":      func(c *SoftwareReconciliationContext) { c.CreatedAt = c.Original.CreatedAt - 1 },
		"excessive lifetime":   func(c *SoftwareReconciliationContext) { c.ExpiresAt = c.CreatedAt + 3601 },
		"expired":              func(c *SoftwareReconciliationContext) { c.ExpiresAt = c.CreatedAt },
		"uppercase hash":       func(c *SoftwareReconciliationContext) { c.OriginalTaskHash = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			c := task.Context
			mutate(&c)
			if c.ValidShape() {
				t.Fatal("invalid context accepted")
			}
			if _, err := SignSoftwareReconciliationTask(c, f.authority, f.issuer, f.now); err == nil {
				t.Fatal("invalid context signed")
			}
		})
	}
}

func TestSoftwareReconciliationRequiresLaterKernelAndDefiniteObservation(t *testing.T) {
	expected := testSoftwarePlan().Expectation()
	base := testSoftwareReconciliationOutcome()
	for name, current := range map[string]SoftwareBootSession{
		"service restart":        base.Admission,
		"hibernate resume":       {Sequence: base.Admission.Sequence + 1, SystemProcessCreated: base.Admission.SystemProcessCreated},
		"creation changed alone": {Sequence: base.Admission.Sequence, SystemProcessCreated: base.Current.SystemProcessCreated},
		"loader rollback":        {Sequence: base.Admission.Sequence - 1, SystemProcessCreated: base.Current.SystemProcessCreated},
		"missing":                {},
		"negative timestamp":     {Sequence: 15, SystemProcessCreated: 1 << 63},
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			v.Current = current
			if v.ValidFor(expected) || v.AllowsRelease(expected) {
				t.Fatal("unproven boot released reservation")
			}
			v.State, v.Observation = "waiting_for_boot", SoftwareObservation{State: "unknown"}
			if v.ValidFor(expected) != current.Valid() || v.AllowsRelease(expected) {
				t.Fatal("waiting state has incorrect semantics")
			}
		})
	}
	for name, mutate := range map[string]func(*SoftwareReconciliationOutcome){
		"exact install": func(v *SoftwareReconciliationOutcome) {},
		"clock moved backward": func(v *SoftwareReconciliationOutcome) {
			v.Current.SystemProcessCreated = v.Admission.SystemProcessCreated - 100
		},
		"different version": func(v *SoftwareReconciliationOutcome) { v.State = "drifted"; v.Observation.Version = "9.8.7" },
		"missing install": func(v *SoftwareReconciliationOutcome) {
			v.State = "drifted"
			v.Observation = SoftwareObservation{State: "absent"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			mutate(&v)
			if !v.ValidFor(expected) || !v.AllowsRelease(expected) {
				t.Fatal("definite later-boot observation rejected")
			}
		})
	}
	unknown := base
	unknown.State, unknown.Observation = "unknown", SoftwareObservation{State: "unknown"}
	if !unknown.ValidFor(expected) || unknown.AllowsRelease(expected) {
		t.Fatal("unknown observation released reservation")
	}
	unavailable := SoftwareReconciliationOutcome{State: "unavailable", Observation: SoftwareObservation{State: "unknown"}}
	if !unavailable.ValidFor(expected) || unavailable.AllowsRelease(expected) {
		t.Fatal("missing evidence released reservation")
	}
	for _, v := range []SoftwareReconciliationOutcome{
		{State: "observed", Observation: base.Observation},
		{State: "unavailable", Admission: base.Admission, Current: base.Current, Observation: base.Observation},
		{State: "observed", Admission: base.Admission, Current: base.Current, Observation: SoftwareObservation{State: "unknown"}},
		{State: "observed", Admission: base.Admission, Current: base.Current, Observation: SoftwareObservation{State: "absent"}},
		{State: "drifted", Admission: base.Admission, Current: base.Current, Observation: base.Observation},
	} {
		if v.ValidFor(expected) || v.AllowsRelease(expected) {
			t.Fatal("contradictory outcome accepted")
		}
	}
	expected.Operation = "remove"
	base.Observation = SoftwareObservation{State: "absent"}
	if !base.ValidFor(expected) || !base.AllowsRelease(expected) {
		t.Fatal("exact removal rejected")
	}
	base.Observation = SoftwareObservation{State: "present", Version: "1.2.3"}
	if base.ValidFor(expected) {
		t.Fatal("present package reported removed")
	}
	base.State = "drifted"
	if !base.ValidFor(expected) || !base.AllowsRelease(expected) {
		t.Fatal("definite removal drift rejected")
	}
}

func TestSoftwareReconciliationSignedResultsAndFreshSubmissions(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	hash, _ := task.Digest()
	nonce := bytes.Repeat([]byte{7}, 32)
	result, err := SignSoftwareReconciliationResult(task.Context, hash, nonce, testSoftwareReconciliationOutcome(), f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySoftwareReconciliationResult(*result, f.certificate, f.now.Add(2*time.Hour)); err != nil {
		t.Fatal("durable result failed historical verification", err)
	}
	proof, err := SignSoftwareReconciliationSubmission(*result, f.identity, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareReconciliationSubmission(*proof, *result, f.identity, f.certificate, f.now) != nil {
		t.Fatal("current proof failed", err)
	}
	if VerifySoftwareReconciliationSubmission(*proof, *result, f.identity, f.certificate, f.now.Add(6*time.Minute)) == nil {
		t.Fatal("expired submission accepted")
	}
	for name, mutate := range map[string]func(*SoftwareReconciliationResult){
		"nonce":             func(r *SoftwareReconciliationResult) { r.OriginalNonce = bytes.Repeat([]byte{8}, 32) },
		"task hash":         func(r *SoftwareReconciliationResult) { r.TaskHash = strings.Repeat("c", 64) },
		"reconciliation id": func(r *SoftwareReconciliationResult) { r.Context.ID = uuid.NewString() },
		"original task":     func(r *SoftwareReconciliationResult) { r.Context.Original.TaskID = uuid.NewString() },
		"admission boot":    func(r *SoftwareReconciliationResult) { r.Outcome.Admission.Sequence-- },
		"observed boot":     func(r *SoftwareReconciliationResult) { r.Outcome.Current.Sequence++ },
		"observation": func(r *SoftwareReconciliationResult) {
			r.Outcome.State = "drifted"
			r.Outcome.Observation.Version = "8.0"
		},
		"timestamp": func(r *SoftwareReconciliationResult) { r.SignedAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			v := *result
			mutate(&v)
			if VerifySoftwareReconciliationResult(v, f.certificate, f.now) == nil || proof.Matches(v, f.now) {
				t.Fatal("modified result accepted or matched original proof")
			}
		})
	}
	// A valid signature under the executable-result domain must not validate in
	// the reconciliation domain, even over the same canonical result bytes.
	forged := *result
	forged.Signature = nil
	data, _ := json.Marshal(forged)
	forged.Signature, err = signRecovery(f.identity, "openuem/windows-software/result/v1\x00", data, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareReconciliationResult(forged, f.certificate, f.now) == nil {
		t.Fatal("executable result domain accepted")
	}
	forgedProof := *proof
	forgedProof.Signature = nil
	data, _ = json.Marshal(forgedProof)
	forgedProof.Signature, err = signRecovery(f.identity, "openuem/windows-software/submission/v1\x00", data, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareReconciliationSubmission(forgedProof, *result, f.identity, f.certificate, f.now) == nil {
		t.Fatal("executable submission domain accepted")
	}
	// Renew the certificate while preserving the original receipt, then require
	// the new generation's proof to submit that receipt.
	later := f.now.Add(2 * time.Hour)
	leaf := *f.certificate
	leaf.Raw, leaf.SerialNumber, leaf.SignatureAlgorithm = nil, big.NewInt(3), x509.UnknownSignatureAlgorithm
	leaf.NotBefore, leaf.NotAfter = later.Add(-time.Minute), later.Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &leaf, f.authority, &f.signer.PublicKey, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	identity := f.identity
	fingerprint := sha256.Sum256(der)
	identity.CertificateHash = hex.EncodeToString(fingerprint[:])
	renewed, err := SignSoftwareReconciliationSubmission(*result, identity, certificate, f.signer, later)
	if err != nil || VerifySoftwareReconciliationSubmission(*renewed, *result, identity, certificate, later) != nil {
		t.Fatal("renewed submission failed", err)
	}
	if VerifySoftwareReconciliationSubmission(*proof, *result, identity, certificate, later) == nil {
		t.Fatal("old generation proof accepted after renewal")
	}
	if _, err := SignSoftwareReconciliationResult(task.Context, hash, nonce, result.Outcome, certificate, f.signer, later); err == nil {
		t.Fatal("expired reconciliation created a new observation")
	}
	unavailable := SoftwareReconciliationOutcome{State: "unavailable", Observation: SoftwareObservation{State: "unknown"}}
	failure, err := SignSoftwareReconciliationResult(task.Context, hash, nil, unavailable, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareReconciliationResult(*failure, f.certificate, f.now) != nil || failure.Outcome.AllowsRelease(f.context.Expectation) {
		t.Fatal("missing journal result mishandled", err)
	}
	if _, err := SignSoftwareReconciliationResult(task.Context, hash, nil, result.Outcome, f.certificate, f.signer, f.now); err == nil {
		t.Fatal("successful recovery signed without original nonce")
	}
}

func TestSoftwareReconciliationCodecsAreCanonicalAndBounded(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	hash, _ := task.Digest()
	result, err := SignSoftwareReconciliationResult(task.Context, hash, bytes.Repeat([]byte{7}, 32), testSoftwareReconciliationOutcome(), f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"task": task, "result": result} {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(value)
			decode := func(data []byte) error {
				if name == "task" {
					_, err := DecodeSoftwareReconciliationTask(data)
					return err
				}
				_, err := DecodeSoftwareReconciliationResult(data, f.now)
				return err
			}
			if err := decode(encoded); err != nil {
				t.Fatal("canonical message rejected", err)
			}
			for _, changed := range [][]byte{nil, append(bytes.Clone(encoded), '\n'), append([]byte(`{"unknown":1,`), encoded[1:]...), append([]byte(`{"context":null,`), encoded[1:]...), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1.0`), 1), bytes.Repeat([]byte("x"), MaxSoftwareMessage+1)} {
				if decode(changed) == nil {
					t.Fatal("noncanonical or excessive message accepted")
				}
			}
		})
	}
	// Detached untrusted result signatures cannot be substituted by a generated
	// Ed25519 command key; endpoint receipt identities require the device key.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(key)
	copy := *result
	copy.Signature = ed25519.Sign(key, []byte("synthetic result"))
	if copy.Valid(f.now) || VerifySoftwareReconciliationResult(copy, f.certificate, f.now) == nil {
		t.Fatal("command key accepted as device receipt key")
	}
}

func TestSoftwareReconciliationEvidenceRequiresTheCompleteRetainedTranscript(t *testing.T) {
	f := testSoftwareFixture(t)
	task := testSoftwareReconciliation(t, f)
	hash, _ := task.Digest()
	nonce := bytes.Repeat([]byte{7}, 32)
	nonceDigest := sha256.Sum256(nonce)
	nonceHash := hex.EncodeToString(nonceDigest[:])
	result, err := SignSoftwareReconciliationResult(task.Context, hash, nonce, testSoftwareReconciliationOutcome(), f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySoftwareReconciliationEvidence(*task, *f.task, *result, f.authority, nonceHash, f.now.Add(3*time.Hour)); err != nil {
		t.Fatal("retained transcript rejected", err)
	}
	for _, wrong := range []string{"", strings.Repeat("a", 64)} {
		if VerifySoftwareReconciliationEvidence(*task, *f.task, *result, f.authority, wrong, f.now) == nil {
			t.Fatal("unbound original nonce accepted")
		}
	}
	other := testSoftwareReconciliation(t, f)
	if VerifySoftwareReconciliationEvidence(*other, *f.task, *result, f.authority, nonceHash, f.now) == nil {
		t.Fatal("receipt from another reconciliation accepted")
	}
	// Even a correctly signed reconciliation is not proof that its copied
	// original context/hash corresponds to the retained executable envelope.
	for _, change := range []string{"original hash", "original context", "result task hash", "original nonce"} {
		t.Run(change, func(t *testing.T) {
			c := task.Context
			if change == "original hash" {
				c.OriginalTaskHash = strings.Repeat("e", 64)
			}
			if change == "original context" {
				c.Original.TaskID = uuid.NewString()
			}
			changed, err := SignSoftwareReconciliationTask(c, f.authority, f.issuer, f.now)
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := changed.Digest()
			if change == "result task hash" {
				hash = strings.Repeat("e", 64)
			}
			proofNonce := nonce
			if change == "original nonce" {
				proofNonce = bytes.Repeat([]byte{8}, 32)
			}
			proof, err := SignSoftwareReconciliationResult(c, hash, proofNonce, result.Outcome, f.certificate, f.signer, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if VerifySoftwareReconciliationEvidence(*changed, *f.task, *proof, f.authority, nonceHash, f.now) == nil {
				t.Fatal("individually signed but mismatched transcript accepted")
			}
		})
	}
	unavailable, err := SignSoftwareReconciliationResult(task.Context, hash, nil, SoftwareReconciliationOutcome{State: "unavailable", Observation: SoftwareObservation{State: "unknown"}}, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareReconciliationEvidence(*task, *f.task, *unavailable, f.authority, nonceHash, f.now) != nil || unavailable.Outcome.AllowsRelease(f.context.Expectation) {
		t.Fatal("unavailable evidence was treated as release proof", err)
	}
}

func FuzzSoftwareReconciliationCodecs(f *testing.F) {
	fixture := testSoftwareFixture(f)
	task := testSoftwareReconciliation(f, fixture)
	encoded, _ := json.Marshal(task)
	f.Add(encoded)
	hash, _ := task.Digest()
	result, err := SignSoftwareReconciliationResult(task.Context, hash, bytes.Repeat([]byte{7}, 32), testSoftwareReconciliationOutcome(), fixture.certificate, fixture.signer, fixture.now)
	if err != nil {
		f.Fatal(err)
	}
	encoded, _ = json.Marshal(result)
	f.Add(encoded)
	f.Add([]byte(`{"context":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxSoftwareMessage+1 {
			return
		}
		if task, err := DecodeSoftwareReconciliationTask(data); err == nil {
			canonical, _ := json.Marshal(task)
			if !bytes.Equal(data, canonical) || !task.ValidShape() {
				t.Fatal("noncanonical task accepted")
			}
		}
		if result, err := DecodeSoftwareReconciliationResult(data, fixture.now); err == nil {
			canonical, _ := json.Marshal(result)
			if !bytes.Equal(data, canonical) || !result.Valid(fixture.now) {
				t.Fatal("noncanonical result accepted")
			}
			if result.Outcome.AllowsRelease(result.Context.Original.Expectation) && (len(result.OriginalNonce) != 32 || !result.Outcome.Current.After(result.Outcome.Admission)) {
				t.Fatal("release without original evidence and later boot")
			}
		}
	})
}
