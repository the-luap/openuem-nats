package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testSoftwarePlan() SoftwarePlan {
	return SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.Product", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.26100", Artifact: SoftwareArtifact{URL: "https://packages.example.test/owned.msi?token=private-download", SHA256: strings.Repeat("a", 64), Format: "msi"}, MSIProperties: map[string]string{"LICENSEKEY": "private-license"}, Detection: SoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
}

type softwareFixture struct {
	identity               SoftwareIdentity
	certificate, authority *x509.Certificate
	signer                 *rsa.PrivateKey
	issuer                 ed25519.PrivateKey
	recipient              *SoftwareRecipientKey
	recipientInfo          SoftwareRecipient
	context                SoftwareContext
	task                   *SoftwareTask
	now                    time.Time
}

func testSoftwareFixture(t testing.TB) *softwareFixture {
	t.Helper()
	f := &softwareFixture{now: time.Now().Truncate(time.Second)}
	var err error
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer = private
	t.Cleanup(func() { clear(private) })
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned software task CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	f.authority, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, f.certificate, f.signer = testRecoveryIdentity(t)
	leaf := *f.certificate
	leaf.Raw = nil
	leaf.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	leaf.BasicConstraintsValid = true
	leaf.NotBefore = f.now.Add(-time.Hour)
	leaf.NotAfter = f.now.Add(time.Hour)
	der, err = x509.CreateCertificate(rand.Reader, &leaf, f.authority, &f.signer.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	f.certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	f.identity.CertificateHash = hex.EncodeToString(digest[:])
	f.recipient, err = NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.recipient.Close)
	plan := testSoftwarePlan()
	hash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.context = SoftwareContext{Version: SoftwareVersion, Protocol: SoftwareProtocol, Identity: f.identity, TaskID: uuid.NewString(), PreparationID: uuid.NewString(), RevisionID: uuid.NewString(), RecipientID: uuid.NewString(), PlanHash: hash, CreatedAt: f.now.Unix(), ExpiresAt: f.now.Add(10 * time.Minute).Unix()}
	f.recipientInfo = SoftwareRecipient{ID: f.context.RecipientID, Identity: f.identity, PublicKey: f.recipient.PublicKey()}
	f.context.Expectation = plan.Expectation()
	f.task, err = SealSoftwareTask(f.recipientInfo, f.context, plan, bytes.Repeat([]byte{7}, 32), f.authority, f.issuer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSoftwarePlanPreservesPrivateIntentAndRejectsUnsupportedAdapters(t *testing.T) {
	p := testSoftwarePlan()
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeSoftwarePlan(data)
	if err != nil || parsed.Artifact.URL != p.Artifact.URL || parsed.MSIProperties["LICENSEKEY"] != p.MSIProperties["LICENSEKEY"] {
		t.Fatal("lost exact private intent", err)
	}
	if _, err = json.Marshal(p); err == nil {
		t.Fatal("private plan serialized outside explicit codec")
	}
	if strings.Contains(fmt.Sprintf("%v %#v %v", p, p, p.Artifact), "private-") {
		t.Fatal("private plan leaked to formatting")
	}
	for _, change := range []func(*SoftwarePlan){
		func(p *SoftwarePlan) { p.Kind = "windows-winget" }, func(p *SoftwarePlan) { p.Operation = "execute" },
		func(p *SoftwarePlan) { p.Architecture = "386" }, func(p *SoftwarePlan) { p.Detection.ProductCode = strings.ToLower(p.Detection.ProductCode) },
		func(p *SoftwarePlan) { p.Artifact.URL = "https://user:private@packages.example.test/a.msi" },
		func(p *SoftwarePlan) { p.Artifact.URL = "http://packages.example.test/a.msi" },
		func(p *SoftwarePlan) { p.Artifact.SHA256 = strings.Repeat("A", 64) },
		func(p *SoftwarePlan) { p.MSIProperties = map[string]string{"TRANSFORMS": "external.mst"} },
		func(p *SoftwarePlan) { p.MSIProperties = map[string]string{"LICENSEKEY": `quote" /x`} },
		func(p *SoftwarePlan) { p.Arguments = []string{"/quiet"} },
		func(p *SoftwarePlan) { p.SuccessCodes = []uint32{0, 3010} },
	} {
		p := testSoftwarePlan()
		change(&p)
		if p.Valid() {
			t.Fatal("invalid executable intent accepted")
		}
	}
	for _, wire := range [][]byte{append([]byte(" "), data...), bytes.Replace(data, []byte(`"operation":"install"`), []byte(`"operation":"remove","operation":"install"`), 1), bytes.Replace(data, []byte(`"operation"`), []byte(`"Operation"`), 1)} {
		if _, err := DecodeSoftwarePlan(wire); err == nil {
			t.Fatal("ambiguous plan accepted")
		}
	}
	p = testSoftwarePlan()
	p.Operation = "remove"
	p.Artifact = SoftwareArtifact{}
	p.MSIProperties = nil
	if !p.Valid() {
		t.Fatal("exact MSI product removal rejected")
	}
	p = testSoftwarePlan()
	p.Kind = "windows-exe"
	p.Artifact.Format = "exe"
	p.Artifact.URL = "https://packages.example.test/owned.exe"
	p.MSIProperties = nil
	p.Arguments = []string{"/quiet", "literal spaces ; &"}
	p.Detection = SoftwareDetection{Kind: "uninstall-key", UninstallKey: "Owned application", RegistryView: "64", Version: "1.2.3"}
	if !p.Valid() {
		t.Fatal("literal EXE plan rejected")
	}
	p.Detection.UninstallKey = `Owned\Nested`
	if p.Valid() {
		t.Fatal("arbitrary registry path accepted")
	}
}

func TestSoftwareTaskRequiresPinnedAuthorityAndExactRecipientContext(t *testing.T) {
	f := testSoftwareFixture(t)
	secret, err := f.recipient.Open(*f.task, f.authority, f.identity, f.context.RecipientID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	if secret.Plan.Artifact.URL != testSoftwarePlan().Artifact.URL || !bytes.Equal(secret.Nonce(), bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("decrypted intent changed")
	}
	raw, err := json.Marshal(f.task)
	if err != nil || bytes.Contains(raw, []byte("private-")) {
		t.Fatal("task exposed execution parameters", err)
	}
	if _, err = json.Marshal(secret); err == nil {
		t.Fatal("secret serialized")
	}
	if _, err = json.Marshal(f.recipient); err == nil {
		t.Fatal("private recipient serialized")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", secret, secret), "private-") {
		t.Fatal("task leaked to formatting")
	}
	clone := func() SoftwareTask {
		var task SoftwareTask
		if json.Unmarshal(raw, &task) != nil {
			t.Fatal("fixture clone")
		}
		return task
	}
	for _, change := range []func(*SoftwareTask){
		func(t *SoftwareTask) { t.Context.Identity.SiteID++ }, func(t *SoftwareTask) { t.Context.Identity.TenantID++ },
		func(t *SoftwareTask) { t.Context.Identity.AgentID = uuid.NewString() }, func(t *SoftwareTask) { t.Context.Identity.CertificateHash = strings.Repeat("b", 64) },
		func(t *SoftwareTask) { t.Context.TaskID = uuid.NewString() }, func(t *SoftwareTask) { t.Context.PreparationID = uuid.NewString() }, func(t *SoftwareTask) { t.Context.RevisionID = uuid.NewString() },
		func(t *SoftwareTask) { t.Context.RecipientID = uuid.NewString() }, func(t *SoftwareTask) { t.Context.PlanHash = strings.Repeat("c", 64) },
		func(t *SoftwareTask) { t.Context.ExpiresAt++ }, func(t *SoftwareTask) { t.Context.CreatedAt++ },
		func(t *SoftwareTask) { t.Encapsulation[0] ^= 1 }, func(t *SoftwareTask) { t.Ciphertext[0] ^= 1 }, func(t *SoftwareTask) { t.Signature[0] ^= 1 },
		func(t *SoftwareTask) { t.SigningCertificate = bytes.Clone(f.certificate.Raw) },
	} {
		task := clone()
		change(&task)
		if VerifySoftwareTask(task, f.authority, f.identity, f.context.RecipientID, f.now) == nil {
			t.Fatal("tampered command signature accepted")
		}
		if _, err = f.recipient.Open(task, f.authority, task.Context.Identity, task.Context.RecipientID, f.now); err == nil {
			t.Fatal("modified context decrypted")
		}
	}
	if VerifySoftwareTask(*f.task, f.certificate, f.identity, f.context.RecipientID, f.now) == nil {
		t.Fatal("device leaf became command CA")
	}
	wrong, err := NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err = wrong.Open(*f.task, f.authority, f.identity, f.context.RecipientID, f.now); err == nil {
		t.Fatal("another private recipient decrypted")
	}
	if VerifySoftwareTask(*f.task, f.authority, f.identity, f.context.RecipientID, time.Unix(f.context.ExpiresAt, 0)) == nil {
		t.Fatal("expired command executable")
	}
	other := f.identity
	other.CertificateHash = strings.Repeat("d", 64)
	if VerifySoftwareTask(*f.task, f.authority, other, f.context.RecipientID, f.now) == nil {
		t.Fatal("old command rebound after identity renewal")
	}
	rawKey, err := f.recipient.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rawKey)
	restored, err := ParseSoftwareRecipientKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if opened, err := restored.Open(*f.task, f.authority, f.identity, f.context.RecipientID, f.now); err != nil {
		t.Fatal("durable key could not recover task", err)
	} else {
		opened.Close()
	}
}

func TestSoftwareRegistrationAndDurableResultsHaveSeparateSignatureDomains(t *testing.T) {
	f := testSoftwareFixture(t)
	registration := SoftwareRegistration{Version: SoftwareVersion, Protocol: SoftwareProtocol, Identity: f.identity, ID: f.context.RecipientID, PublicKey: f.recipient.PublicKey(), Nonce: bytes.Repeat([]byte{5}, 32), ExpiresAt: f.now.Add(5 * time.Minute).Unix()}
	signature, err := SignSoftwareRegistration(registration, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareRegistration(registration, signature, f.certificate, f.now) != nil {
		t.Fatal("registration failed", err)
	}
	legacy := RecoveryRegistration{Version: RecoveryVersion, Identity: registration.Identity, ID: registration.ID, PublicKey: registration.PublicKey, Nonce: registration.Nonce, ExpiresAt: registration.ExpiresAt}
	legacySignature, err := SignRecoveryRegistration(legacy, f.certificate, f.signer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySoftwareRegistration(registration, legacySignature, f.certificate, f.now) == nil {
		t.Fatal("FileVault proof authorized software")
	}
	secret, err := f.recipient.Open(*f.task, f.authority, f.identity, f.context.RecipientID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	zero := uint32(0)
	outcome := SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: SoftwareObservation{State: "absent"}, After: SoftwareObservation{State: "present", Version: "1.2.3"}}
	if !outcome.ValidFor(secret.Plan) {
		t.Fatal("valid native outcome rejected")
	}
	result, err := SignSoftwareResult(secret.Context, f.identity, secret.TaskHash(), secret.Nonce(), outcome, f.certificate, f.signer, f.now)
	if err != nil || VerifySoftwareResult(*result, f.certificate, f.now.Add(48*time.Hour)) != nil {
		t.Fatal("durable receipt expired with delivery", err)
	}
	receipt, err := SoftwareResultReceipt(*result, f.now)
	if err != nil || !receipt.Valid() {
		t.Fatal("exact acknowledgement missing", err)
	}
	result.Outcome.After.Version = "2.0"
	if VerifySoftwareResult(*result, f.certificate, f.now) == nil || result.Outcome.ValidFor(secret.Plan) {
		t.Fatal("outcome changed after signing")
	}
	uncertain := SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: SoftwareObservation{State: "unknown"}, After: SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	late := f.now.Add(15 * time.Minute)
	result, err = SignSoftwareResult(secret.Context, f.identity, secret.TaskHash(), secret.Nonce(), uncertain, f.certificate, f.signer, late)
	if err != nil || VerifySoftwareResult(*result, f.certificate, late) != nil {
		t.Fatal("uncertain interrupted receipt unavailable", err)
	}
	if VerifySoftwareTask(*f.task, f.authority, f.identity, f.context.RecipientID, late) == nil {
		t.Fatal("late receipt reopened execution")
	}
	reboot := uint32(3010)
	outcome.ExitCode = &reboot
	if outcome.ValidFor(secret.Plan) {
		t.Fatal("restart was reported as observed completion")
	}
	outcome.State = "restart_required"
	if !outcome.ValidFor(secret.Plan) {
		t.Fatal("restart requirement lost")
	}
}

func TestSoftwareRPCIsCanonicalBoundedAndActionSpecific(t *testing.T) {
	f := testSoftwareFixture(t)
	request := SoftwareRequest{Version: SoftwareVersion, Protocol: SoftwareProtocol, AgentID: f.identity.AgentID, Action: "poll", RecipientID: f.context.RecipientID}
	data, _ := json.Marshal(request)
	if _, err := DecodeSoftwareRequest(data, f.now); err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{append(data, ' '), bytes.Replace(data, []byte(`"action":"poll"`), []byte(`"action":"result","action":"poll"`), 1), bytes.Replace(data, []byte(`"agent_id"`), []byte(`"Agent_ID"`), 1), append(data[:len(data)-1], []byte(`,"unknown":true}`)...), bytes.Repeat([]byte(" "), MaxSoftwareMessage+1)} {
		if _, err := DecodeSoftwareRequest(wire, f.now); err == nil {
			t.Fatal("ambiguous RPC accepted")
		}
	}
	request.PublicKey = f.recipient.PublicKey()
	data, _ = json.Marshal(request)
	if _, err := DecodeSoftwareRequest(data, f.now); err == nil {
		t.Fatal("mixed request actions accepted")
	}
	reply := SoftwareReply{Version: SoftwareVersion, Protocol: SoftwareProtocol, OK: true, Task: f.task}
	data, _ = json.Marshal(reply)
	if _, err := DecodeSoftwareReply(data, f.now.Add(24*time.Hour)); err != nil {
		t.Fatal("historical task cannot recover receipt", err)
	}
	reply.Recipient = &f.recipientInfo
	data, _ = json.Marshal(reply)
	if _, err := DecodeSoftwareReply(data, f.now); err == nil {
		t.Fatal("mixed reply accepted")
	}
}

func FuzzSoftwareWire(f *testing.F) {
	now := time.Unix(1789128000, 0)
	data, _ := json.Marshal(SoftwareRequest{Version: SoftwareVersion, Protocol: SoftwareProtocol, AgentID: "00000000-0000-4000-8000-000000000001", Action: "poll", RecipientID: "00000000-0000-4000-8000-000000000002"})
	f.Add(data)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxSoftwareMessage+1 {
			return
		}
		if request, err := DecodeSoftwareRequest(data, now); err == nil {
			encoded, err := json.Marshal(request)
			if err != nil || !bytes.Equal(data, encoded) {
				t.Fatal("noncanonical request accepted")
			}
		}
		if reply, err := DecodeSoftwareReply(data, now); err == nil {
			encoded, err := json.Marshal(reply)
			if err != nil || !bytes.Equal(data, encoded) {
				t.Fatal("noncanonical reply accepted")
			}
		}
		if plan, err := DecodeSoftwarePlan(data); err == nil {
			encoded, err := plan.Canonical()
			if err != nil || !bytes.Equal(data, encoded) {
				t.Fatal("noncanonical plan accepted")
			}
		}
	})
}
