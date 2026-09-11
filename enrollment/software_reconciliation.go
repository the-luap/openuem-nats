package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strconv"
	"time"
)

const SoftwareReconciliationVersion = 1
const SoftwareReconciliationProtocol = "openuem/windows-software/reconciliation/v1"

// SoftwareBootSession contains only the loader sequence and original System
// process creation value. Both must change as specified to distinguish a later
// kernel session from service restart, counter rollback and resumed hibernation.
// This is signed endpoint evidence, not hardware attestation.
type SoftwareBootSession struct {
	Sequence             uint32 `json:"sequence"`
	SystemProcessCreated uint64 `json:"system_process_created"`
}

func (b SoftwareBootSession) Valid() bool {
	return b.SystemProcessCreated > 0 && b.SystemProcessCreated < 1<<63
}

func (b SoftwareBootSession) After(original SoftwareBootSession) bool {
	return b.Valid() && original.Valid() && b.Sequence > original.Sequence && b.SystemProcessCreated != original.SystemProcessCreated
}

// A reconciliation authorizes one read-only observation of an earlier intent.
// It carries no artifact, installer arguments, executable plan or encryption key.
// The original envelope and any execution receipt remain separate and immutable.
type SoftwareReconciliationContext struct {
	Version          int              `json:"version"`
	Protocol         string           `json:"protocol"`
	Identity         SoftwareIdentity `json:"identity"`
	ID               string           `json:"id"`
	Original         SoftwareContext  `json:"original"`
	OriginalTaskHash string           `json:"original_task_hash"`
	CreatedAt        int64            `json:"created_at"`
	ExpiresAt        int64            `json:"expires_at"`
}

func (c SoftwareReconciliationContext) ValidShape() bool {
	return c.Version == SoftwareReconciliationVersion && c.Protocol == SoftwareReconciliationProtocol &&
		c.Identity.Valid() && c.Original.ValidShape() && ValidDeviceID(c.ID) && c.ID != c.Original.TaskID &&
		c.Identity.AgentID == c.Original.Identity.AgentID && c.Identity.TenantID == c.Original.Identity.TenantID && c.Identity.SiteID == c.Original.Identity.SiteID &&
		softwareDigest(c.OriginalTaskHash) && c.CreatedAt >= c.Original.CreatedAt && c.ExpiresAt > c.CreatedAt && c.ExpiresAt-c.CreatedAt <= 3600
}

func (c SoftwareReconciliationContext) Valid(now time.Time) bool {
	return c.ValidShape() && c.CreatedAt <= now.Add(time.Minute).Unix() && c.ExpiresAt > now.Unix()
}

func (c SoftwareReconciliationContext) Equal(other SoftwareReconciliationContext) bool {
	a, err := json.Marshal(c)
	if err != nil {
		return false
	}
	b, err := json.Marshal(other)
	return err == nil && bytes.Equal(a, b)
}

type SoftwareReconciliationTask struct {
	Context            SoftwareReconciliationContext `json:"context"`
	SigningCertificate []byte                        `json:"signing_certificate"`
	Signature          []byte                        `json:"signature"`
}

func (t SoftwareReconciliationTask) ValidShape() bool {
	return t.Context.ValidShape() && len(t.SigningCertificate) > 0 && len(t.SigningCertificate) <= 8192 && len(t.Signature) == ed25519.SignatureSize
}

func (t SoftwareReconciliationTask) Digest() (string, error) {
	if !t.ValidShape() {
		return "", ErrSoftware
	}
	data, err := json.Marshal(t)
	if err != nil {
		return "", ErrSoftware
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func DecodeSoftwareReconciliationTask(data []byte) (*SoftwareReconciliationTask, error) {
	var task SoftwareReconciliationTask
	if decodeSoftwareJSON(data, &task) != nil || !task.ValidShape() {
		return nil, ErrSoftware
	}
	return &task, nil
}

func softwareReconciliationURI(c SoftwareReconciliationContext) string {
	return "urn:openuem:windows-software-reconciliation:" + strconv.Itoa(c.Identity.TenantID) + ":" + c.ID
}

func softwareReconciliationTaskBytes(t SoftwareReconciliationTask) ([]byte, error) {
	t.Signature = nil
	data, err := json.Marshal(t)
	if err != nil {
		return nil, ErrSoftware
	}
	return append([]byte("openuem/windows-software/reconciliation/task-signature/v1\x00"), data...), nil
}

// SignSoftwareReconciliationTask is a trusted console operation, after current
// explicit authorization and verification of the exact retained original task.
func SignSoftwareReconciliationTask(c SoftwareReconciliationContext, authority *x509.Certificate, issuer crypto.Signer, now time.Time) (*SoftwareReconciliationTask, error) {
	if !c.Valid(now) || authority == nil || issuer == nil || !authority.IsCA || authority.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(authority.NotBefore) || authority.NotAfter.Unix() < c.ExpiresAt {
		return nil, ErrSoftware
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrSoftware
	}
	defer clear(key)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return nil, ErrSoftware
	}
	uri, err := url.Parse(softwareReconciliationURI(c))
	if err != nil {
		return nil, ErrSoftware
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM Windows software reconciliation"}, URIs: []*url.URL{uri}, NotBefore: time.Unix(c.CreatedAt, 0).Add(-time.Minute), NotAfter: time.Unix(c.ExpiresAt, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, public, issuer)
	if err != nil {
		return nil, ErrSoftware
	}
	task := &SoftwareReconciliationTask{Context: c, SigningCertificate: der}
	signed, err := softwareReconciliationTaskBytes(*task)
	if err != nil {
		return nil, ErrSoftware
	}
	task.Signature = ed25519.Sign(key, signed)
	if VerifySoftwareReconciliationTask(*task, authority, c.Identity, now) != nil {
		return nil, ErrSoftware
	}
	return task, nil
}

func VerifySoftwareReconciliationTask(t SoftwareReconciliationTask, authority *x509.Certificate, identity SoftwareIdentity, now time.Time) error {
	if !t.ValidShape() || !t.Context.Valid(now) || t.Context.Identity != identity || authority == nil || !authority.IsCA {
		return ErrSoftware
	}
	c := t.Context
	cert, err := x509.ParseCertificate(t.SigningCertificate)
	if err != nil || cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != softwareReconciliationURI(c) || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || cert.NotAfter.Unix() != c.ExpiresAt || cert.NotBefore.Unix() > c.CreatedAt || cert.NotBefore.Before(time.Unix(c.CreatedAt, 0).Add(-time.Minute)) {
		return ErrSoftware
	}
	public, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize || cert.CheckSignatureFrom(authority) != nil {
		return ErrSoftware
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return ErrSoftware
	}
	signed, err := softwareReconciliationTaskBytes(t)
	if err != nil || !ed25519.Verify(public, signed, t.Signature) {
		return ErrSoftware
	}
	return nil
}

// History verification cannot authorize a new observation after expiry or under
// another certificate generation. Consumers must use current verification first.
func VerifySoftwareReconciliationTaskHistory(t SoftwareReconciliationTask, authority *x509.Certificate) error {
	return VerifySoftwareReconciliationTask(t, authority, t.Context.Identity, time.Unix(t.Context.CreatedAt, 0))
}

type SoftwareReconciliationOutcome struct {
	State       string              `json:"state"`
	Admission   SoftwareBootSession `json:"admission"`
	Current     SoftwareBootSession `json:"current"`
	Observation SoftwareObservation `json:"observation"`
}

func (o SoftwareReconciliationOutcome) ValidFor(expected SoftwareExpectation) bool {
	if !expected.Valid() || !o.Observation.Valid() {
		return false
	}
	switch o.State {
	case "unavailable":
		return o.Admission == (SoftwareBootSession{}) && o.Current == (SoftwareBootSession{}) && o.Observation == (SoftwareObservation{State: "unknown"})
	case "waiting_for_boot":
		return o.Admission.Valid() && o.Current.Valid() && !o.Current.After(o.Admission) && o.Observation == (SoftwareObservation{State: "unknown"})
	case "unknown":
		return o.Current.After(o.Admission) && o.Observation == (SoftwareObservation{State: "unknown"})
	case "observed", "drifted":
		if !o.Current.After(o.Admission) || o.Observation.State == "unknown" {
			return false
		}
		matches := expected.Operation == "install" && o.Observation.Matches(expected.Detection) || expected.Operation == "remove" && o.Observation.State == "absent"
		return (o.State == "observed") == matches
	default:
		return false
	}
}

// AllowsRelease is only a shape check. Registry callers must first authenticate
// the task, result, original nonce and current certificate submission together.
func (o SoftwareReconciliationOutcome) AllowsRelease(expected SoftwareExpectation) bool {
	return o.ValidFor(expected) && (o.State == "observed" || o.State == "drifted")
}

type SoftwareReconciliationResult struct {
	Context       SoftwareReconciliationContext `json:"context"`
	Certificate   []byte                        `json:"certificate"`
	TaskHash      string                        `json:"task_hash"`
	OriginalNonce []byte                        `json:"original_nonce"`
	Outcome       SoftwareReconciliationOutcome `json:"outcome"`
	SignedAt      int64                         `json:"signed_at"`
	Signature     []byte                        `json:"signature"`
}

func (SoftwareReconciliationResult) String() string {
	return "[protected Windows software reconciliation result]"
}
func (r SoftwareReconciliationResult) GoString() string { return r.String() }

func (r SoftwareReconciliationResult) Valid(now time.Time) bool {
	nonce := len(r.OriginalNonce) == 32
	if r.Outcome.State == "unavailable" {
		nonce = len(r.OriginalNonce) == 0
	}
	return r.Context.ValidShape() && len(r.Certificate) > 0 && len(r.Certificate) <= 16384 && softwareDigest(r.TaskHash) && nonce && r.Outcome.ValidFor(r.Context.Original.Expectation) && r.SignedAt >= r.Context.CreatedAt && r.SignedAt < r.Context.ExpiresAt && r.SignedAt <= now.Add(time.Minute).Unix() && len(r.Signature) >= 384 && len(r.Signature) <= 512
}

func DecodeSoftwareReconciliationResult(data []byte, now time.Time) (*SoftwareReconciliationResult, error) {
	var result SoftwareReconciliationResult
	if decodeSoftwareJSON(data, &result) != nil || !result.Valid(now) {
		return nil, ErrSoftware
	}
	return &result, nil
}

func SignSoftwareReconciliationResult(c SoftwareReconciliationContext, taskHash string, originalNonce []byte, outcome SoftwareReconciliationOutcome, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) (*SoftwareReconciliationResult, error) {
	if cert == nil || !c.Valid(now) {
		return nil, ErrSoftware
	}
	r := &SoftwareReconciliationResult{Context: c, Certificate: bytes.Clone(cert.Raw), TaskHash: taskHash, OriginalNonce: bytes.Clone(originalNonce), Outcome: outcome, SignedAt: now.Unix(), Signature: make([]byte, 384)}
	if !r.Valid(now) {
		clear(r.OriginalNonce)
		return nil, ErrSoftware
	}
	r.Signature = nil
	data, _ := json.Marshal(r)
	defer clear(data)
	signature, err := signRecovery(c.Identity, "openuem/windows-software/reconciliation/result/v1\x00", data, cert, key, now)
	if err != nil {
		clear(r.OriginalNonce)
		return nil, ErrSoftware
	}
	r.Signature = signature
	return r, nil
}

func VerifySoftwareReconciliationResult(r SoftwareReconciliationResult, cert *x509.Certificate, now time.Time) error {
	if !r.Valid(now) || cert == nil || !bytes.Equal(r.Certificate, cert.Raw) {
		return ErrSoftware
	}
	signature := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	defer clear(data)
	if verifyRecovery(r.Context.Identity, "openuem/windows-software/reconciliation/result/v1\x00", data, signature, cert, time.Unix(r.SignedAt, 0)) != nil {
		return ErrSoftware
	}
	return nil
}

// VerifySoftwareReconciliationEvidence checks the complete historical transcript
// against the retained original nonce hash and pinned enrollment authority. The
// transaction boundary must additionally require a fresh current-certificate
// submission, current authorization and its original-scope reservation lock.
func VerifySoftwareReconciliationEvidence(task SoftwareReconciliationTask, original SoftwareTask, result SoftwareReconciliationResult, authority *x509.Certificate, originalNonceHash string, now time.Time) error {
	if !softwareDigest(originalNonceHash) || VerifySoftwareReconciliationTaskHistory(task, authority) != nil || VerifySoftwareTaskHistory(original, authority) != nil || !task.Context.Original.Equal(original.Context) || !result.Context.Equal(task.Context) {
		return ErrSoftware
	}
	originalHash, err := original.Digest()
	if err != nil || originalHash != task.Context.OriginalTaskHash {
		return ErrSoftware
	}
	taskHash, err := task.Digest()
	if err != nil || taskHash != result.TaskHash {
		return ErrSoftware
	}
	certificate, err := x509.ParseCertificate(result.Certificate)
	if err != nil || VerifySoftwareReconciliationResult(result, certificate, now) != nil || certificate.CheckSignatureFrom(authority) != nil {
		return ErrSoftware
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(result.SignedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrSoftware
	}
	if result.Outcome.State != "unavailable" {
		hash := sha256.Sum256(result.OriginalNonce)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(originalNonceHash)) != 1 {
			return ErrSoftware
		}
	}
	return nil
}

func SoftwareReconciliationReceipt(r SoftwareReconciliationResult, now time.Time) (*SoftwareReceipt, error) {
	if !r.Valid(now) {
		return nil, ErrSoftware
	}
	data, err := json.Marshal(r)
	defer clear(data)
	if err != nil {
		return nil, ErrSoftware
	}
	hash := sha256.Sum256(data)
	return &SoftwareReceipt{TaskID: r.Context.ID, ResultHash: hex.EncodeToString(hash[:])}, nil
}

// Submission uses a separate signature domain from executable-task receipts.
// A historical result still needs proof from the current certificate generation.
type SoftwareReconciliationSubmission SoftwareSubmission

func (s SoftwareReconciliationSubmission) Valid(now time.Time) bool {
	return SoftwareSubmission(s).Valid(now)
}
func (s SoftwareReconciliationSubmission) Matches(r SoftwareReconciliationResult, now time.Time) bool {
	receipt, err := SoftwareReconciliationReceipt(r, now)
	return err == nil && s.TaskID == receipt.TaskID && s.ResultHash == receipt.ResultHash && s.Identity.AgentID == r.Context.Identity.AgentID && s.Identity.TenantID == r.Context.Identity.TenantID && s.Identity.SiteID == r.Context.Identity.SiteID
}

func SignSoftwareReconciliationSubmission(result SoftwareReconciliationResult, identity SoftwareIdentity, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) (*SoftwareReconciliationSubmission, error) {
	receipt, err := SoftwareReconciliationReceipt(result, now)
	if err != nil || cert == nil {
		return nil, ErrSoftware
	}
	expires := now.Add(5 * time.Minute).Unix()
	if cert.NotAfter.Unix() < expires {
		expires = cert.NotAfter.Unix()
	}
	proof := &SoftwareReconciliationSubmission{Identity: identity, TaskID: receipt.TaskID, ResultHash: receipt.ResultHash, IssuedAt: now.Unix(), ExpiresAt: expires, Signature: make([]byte, 384)}
	if !proof.Valid(now) || !proof.Matches(result, now) {
		return nil, ErrSoftware
	}
	proof.Signature = nil
	data, _ := json.Marshal(proof)
	proof.Signature, err = signRecovery(identity, "openuem/windows-software/reconciliation/submission/v1\x00", data, cert, key, now)
	if err != nil {
		return nil, ErrSoftware
	}
	return proof, nil
}

func VerifySoftwareReconciliationSubmission(proof SoftwareReconciliationSubmission, result SoftwareReconciliationResult, current SoftwareIdentity, cert *x509.Certificate, now time.Time) error {
	if !proof.Valid(now) || proof.Identity != current || !proof.Matches(result, now) || cert == nil || proof.ExpiresAt > cert.NotAfter.Unix() {
		return ErrSoftware
	}
	signature := proof.Signature
	proof.Signature = nil
	data, _ := json.Marshal(proof)
	if verifyRecovery(current, "openuem/windows-software/reconciliation/submission/v1\x00", data, signature, cert, now) != nil {
		return ErrSoftware
	}
	return nil
}
