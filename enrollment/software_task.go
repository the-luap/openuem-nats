package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strconv"
	"time"
)

// SoftwareIdentity is the exact device certificate generation, plus permanent
// organization/site ownership. Signing, broker and encryption keys stay separate.
type SoftwareIdentity = RecoveryIdentity

type SoftwareRegistration struct {
	Version     int              `json:"version"`
	Protocol    string           `json:"protocol"`
	Identity    SoftwareIdentity `json:"identity"`
	ID          string           `json:"id"`
	PublicKey   []byte           `json:"public_key"`
	Nonce       []byte           `json:"nonce"`
	ExpiresAt   int64            `json:"expires_at"`
	BurnVersion int              `json:"burn_version,omitempty"`
}

func (r SoftwareRegistration) Valid(now time.Time) bool {
	return validSoftwareBurnVersion(r.BurnVersion) && r.Version == SoftwareVersion && r.Protocol == SoftwareProtocol && r.Identity.Valid() && ValidDeviceID(r.ID) && ValidRecoveryPublicKey(r.PublicKey) && len(r.Nonce) == 32 && r.ExpiresAt > now.Unix() && r.ExpiresAt <= now.Add(10*time.Minute).Unix()
}

type SoftwareRecipient struct {
	ID          string           `json:"id"`
	Identity    SoftwareIdentity `json:"identity"`
	PublicKey   []byte           `json:"public_key"`
	BurnVersion int              `json:"burn_version,omitempty"`
}

func (r SoftwareRecipient) Valid() bool {
	return validSoftwareBurnVersion(r.BurnVersion) && ValidDeviceID(r.ID) && r.Identity.Valid() && ValidRecoveryPublicKey(r.PublicKey)
}

func validSoftwareBurnVersion(version int) bool {
	return version == 0 || version == SoftwareBurnVersion
}

// Supports binds new execution kinds to the capability retained from the
// certificate-signed registration. It must be checked before sealing a task.
func (r SoftwareRecipient) Supports(plan SoftwarePlan) bool {
	return r.Valid() && plan.Valid() && (plan.Kind != "windows-burn" || r.BurnVersion == SoftwareBurnVersion)
}

type SoftwareContext struct {
	Version       int                 `json:"version"`
	Protocol      string              `json:"protocol"`
	Identity      SoftwareIdentity    `json:"identity"`
	TaskID        string              `json:"task_id"`
	PreparationID string              `json:"preparation_id"`
	RevisionID    string              `json:"revision_id"`
	RecipientID   string              `json:"recipient_id"`
	PlanHash      string              `json:"plan_hash"`
	Expectation   SoftwareExpectation `json:"expectation"`
	CreatedAt     int64               `json:"created_at"`
	ExpiresAt     int64               `json:"expires_at"`
}

func (c SoftwareContext) ValidShape() bool {
	return c.Version == SoftwareVersion && c.Protocol == SoftwareProtocol && c.Identity.Valid() && ValidDeviceID(c.TaskID) && ValidDeviceID(c.PreparationID) && ValidDeviceID(c.RevisionID) && ValidDeviceID(c.RecipientID) && softwareDigest(c.PlanHash) && c.Expectation.Valid() && c.CreatedAt > 0 && c.ExpiresAt > c.CreatedAt && c.ExpiresAt-c.CreatedAt <= 86400
}
func (c SoftwareContext) Valid(now time.Time) bool {
	return c.ValidShape() && c.CreatedAt <= now.Add(time.Minute).Unix() && c.ExpiresAt > now.Unix()
}
func (c SoftwareContext) Equal(other SoftwareContext) bool {
	a, err := json.Marshal(c)
	if err != nil {
		return false
	}
	b, err := json.Marshal(other)
	return err == nil && bytes.Equal(a, b)
}

type SoftwareTask struct {
	Context            SoftwareContext `json:"context"`
	Encapsulation      []byte          `json:"encapsulation"`
	Ciphertext         []byte          `json:"ciphertext"`
	SigningCertificate []byte          `json:"signing_certificate"`
	Signature          []byte          `json:"signature"`
}

func (t SoftwareTask) ValidShape() bool {
	return t.Context.ValidShape() && len(t.Encapsulation) == 32 && len(t.Ciphertext) > 64 && len(t.Ciphertext) <= MaxSoftwarePlan+256 && len(t.SigningCertificate) > 0 && len(t.SigningCertificate) <= 8192 && len(t.Signature) == ed25519.SignatureSize
}
func (t SoftwareTask) Digest() (string, error) {
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

func DecodeSoftwareTask(data []byte) (*SoftwareTask, error) {
	var task SoftwareTask
	if decodeSoftwareJSON(data, &task) != nil || !task.ValidShape() {
		return nil, ErrSoftware
	}
	return &task, nil
}

// Historical verification authenticates retained evidence only. It must never
// replace VerifySoftwareTask's current-time check before an execution attempt.
func VerifySoftwareTaskHistory(task SoftwareTask, authority *x509.Certificate) error {
	if !task.ValidShape() {
		return ErrSoftware
	}
	return VerifySoftwareTask(task, authority, task.Context.Identity, task.Context.RecipientID, time.Unix(task.Context.CreatedAt, 0))
}

func softwareSigningURI(c SoftwareContext) string {
	return "urn:openuem:windows-software:" + strconv.Itoa(c.Identity.TenantID) + ":" + c.TaskID
}
func softwareTaskBytes(t SoftwareTask) ([]byte, error) {
	t.Signature = nil
	data, err := json.Marshal(t)
	if err != nil {
		return nil, ErrSoftware
	}
	return append([]byte("openuem/windows-software/task-signature/v1\x00"), data...), nil
}

// SealSoftwareTask is a trusted console operation after transactional approval.
// An ephemeral Ed25519 command certificate is issued by the exact enrollment CA,
// constrained to this tenant/task and lifetime, then its private key is erased.
// HPKE alone hides a payload but does not establish its sender's authority.
func SealSoftwareTask(recipient SoftwareRecipient, c SoftwareContext, plan SoftwarePlan, nonce []byte, authority *x509.Certificate, issuer crypto.Signer, now time.Time) (*SoftwareTask, error) {
	if !recipient.Supports(plan) || !c.Valid(now) || recipient.Identity != c.Identity || recipient.ID != c.RecipientID || len(nonce) != 32 || authority == nil || issuer == nil || !authority.IsCA || authority.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(authority.NotBefore) || authority.NotAfter.Unix() < c.ExpiresAt {
		return nil, ErrSoftware
	}
	hash, err := plan.Digest()
	if err != nil || hash != c.PlanHash || !c.Expectation.Equal(plan.Expectation()) {
		return nil, ErrSoftware
	}
	payload, err := json.Marshal(struct {
		Plan  softwarePlanWire `json:"plan"`
		Nonce []byte           `json:"nonce"`
	}{softwarePlanWire(plan), nonce})
	if err != nil {
		return nil, ErrSoftware
	}
	defer clear(payload)
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(recipient.PublicKey)
	if err != nil {
		return nil, ErrSoftware
	}
	info, _ := json.Marshal(c)
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte("openuem/windows-software/task/v1\x00"), info...))
	if err != nil {
		return nil, ErrSoftware
	}
	sealed, err := sender.Seal(info, payload)
	if err != nil {
		return nil, ErrSoftware
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrSoftware
	}
	defer clear(key)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return nil, ErrSoftware
	}
	uri, err := url.Parse(softwareSigningURI(c))
	if err != nil {
		return nil, ErrSoftware
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM Windows software command"}, URIs: []*url.URL{uri}, NotBefore: time.Unix(c.CreatedAt, 0).Add(-time.Minute), NotAfter: time.Unix(c.ExpiresAt, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, pub, issuer)
	if err != nil {
		return nil, ErrSoftware
	}
	task := &SoftwareTask{Context: c, Encapsulation: enc, Ciphertext: sealed, SigningCertificate: der}
	signed, err := softwareTaskBytes(*task)
	if err != nil {
		return nil, ErrSoftware
	}
	task.Signature = ed25519.Sign(key, signed)
	if VerifySoftwareTask(*task, authority, c.Identity, c.RecipientID, now) != nil {
		return nil, ErrSoftware
	}
	return task, nil
}

// VerifySoftwareTask requires the independently pinned enrollment authority and
// exact current local identity. A task cannot introduce a CA or signing key as
// its own trust root. This check is for new work, so expiry is always enforced.
func VerifySoftwareTask(t SoftwareTask, authority *x509.Certificate, identity SoftwareIdentity, recipient string, now time.Time) error {
	if !t.ValidShape() || !t.Context.Valid(now) || t.Context.Identity != identity || t.Context.RecipientID != recipient || authority == nil || !authority.IsCA {
		return ErrSoftware
	}
	cert, err := x509.ParseCertificate(t.SigningCertificate)
	if err != nil || cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != softwareSigningURI(t.Context) || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || cert.NotAfter.Unix() != t.Context.ExpiresAt || cert.NotBefore.Unix() > t.Context.CreatedAt || cert.NotBefore.Before(time.Unix(t.Context.CreatedAt, 0).Add(-time.Minute)) {
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
	signed, err := softwareTaskBytes(t)
	if err != nil || !ed25519.Verify(public, signed, t.Signature) {
		return ErrSoftware
	}
	return nil
}

type SoftwareRecipientKey struct{ key *RecoveryRecipientKey }

func (*SoftwareRecipientKey) String() string               { return "[protected Windows software recipient key]" }
func (k *SoftwareRecipientKey) GoString() string           { return k.String() }
func (*SoftwareRecipientKey) MarshalJSON() ([]byte, error) { return nil, ErrSoftware }
func NewSoftwareRecipientKey() (*SoftwareRecipientKey, error) {
	key, err := NewRecoveryRecipientKey()
	if err != nil {
		return nil, ErrSoftware
	}
	return &SoftwareRecipientKey{key}, nil
}
func ParseSoftwareRecipientKey(data []byte) (*SoftwareRecipientKey, error) {
	key, err := ParseRecoveryRecipientKey(data)
	if err != nil {
		return nil, ErrSoftware
	}
	return &SoftwareRecipientKey{key}, nil
}
func (k *SoftwareRecipientKey) PublicKey() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return k.key.PublicKey()
}
func (k *SoftwareRecipientKey) Bytes() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, ErrSoftware
	}
	return k.key.Bytes()
}
func (k *SoftwareRecipientKey) Close() {
	if k != nil && k.key != nil {
		k.key.Close()
		k.key = nil
	}
}

type SoftwareSecret struct {
	Context  SoftwareContext
	Plan     SoftwarePlan
	nonce    []byte
	taskHash string
}

func (*SoftwareSecret) String() string               { return "[protected Windows software task]" }
func (s *SoftwareSecret) GoString() string           { return s.String() }
func (*SoftwareSecret) MarshalJSON() ([]byte, error) { return nil, ErrSoftware }
func (s *SoftwareSecret) Nonce() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.nonce)
}
func (s *SoftwareSecret) TaskHash() string {
	if s == nil {
		return ""
	}
	return s.taskHash
}
func (s *SoftwareSecret) Close() {
	if s != nil {
		clear(s.nonce)
		s.nonce = nil
		s.Plan = SoftwarePlan{}
	}
}

func (k *SoftwareRecipientKey) Open(t SoftwareTask, authority *x509.Certificate, identity SoftwareIdentity, recipient string, now time.Time) (*SoftwareSecret, error) {
	if k == nil || k.key == nil || k.key.key == nil || VerifySoftwareTask(t, authority, identity, recipient, now) != nil {
		return nil, ErrSoftware
	}
	info, _ := json.Marshal(t.Context)
	receiver, err := hpke.NewRecipient(t.Encapsulation, k.key.key, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte("openuem/windows-software/task/v1\x00"), info...))
	if err != nil {
		return nil, ErrSoftware
	}
	data, err := receiver.Open(info, t.Ciphertext)
	if err != nil {
		return nil, ErrSoftware
	}
	defer clear(data)
	var wire struct {
		Plan  softwarePlanWire `json:"plan"`
		Nonce []byte           `json:"nonce"`
	}
	if json.Unmarshal(data, &wire) != nil {
		return nil, ErrSoftware
	}
	canonical, err := json.Marshal(wire)
	defer clear(canonical)
	plan := SoftwarePlan(wire.Plan)
	hash, hashErr := plan.Digest()
	if err != nil || !bytes.Equal(data, canonical) || len(wire.Nonce) != 32 || hashErr != nil || hash != t.Context.PlanHash || !t.Context.Expectation.Equal(plan.Expectation()) {
		clear(wire.Nonce)
		return nil, ErrSoftware
	}
	taskHash, err := t.Digest()
	if err != nil {
		clear(wire.Nonce)
		return nil, ErrSoftware
	}
	return &SoftwareSecret{Context: t.Context, Plan: plan, nonce: wire.Nonce, taskHash: taskHash}, nil
}

func SignSoftwareRegistration(r SoftwareRegistration, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) ([]byte, error) {
	if !r.Valid(now) {
		return nil, ErrSoftware
	}
	data, _ := json.Marshal(r)
	signature, err := signRecovery(r.Identity, "openuem/windows-software/register/v1\x00", data, cert, key, now)
	if err != nil {
		return nil, ErrSoftware
	}
	return signature, nil
}
func VerifySoftwareRegistration(r SoftwareRegistration, signature []byte, cert *x509.Certificate, now time.Time) error {
	if !r.Valid(now) {
		return ErrSoftware
	}
	data, _ := json.Marshal(r)
	if verifyRecovery(r.Identity, "openuem/windows-software/register/v1\x00", data, signature, cert, now) != nil {
		return ErrSoftware
	}
	return nil
}

// A durable receipt may survive certificate renewal. Its signing identity and
// signing time are explicit and separately verified; context expiry authorizes
// no new execution. Server callers still require a current authenticated request
// in the same permanent scope and the exact retained task/nonce before accepting.
type SoftwareResult struct {
	Context     SoftwareContext  `json:"context"`
	Identity    SoftwareIdentity `json:"identity"`
	Certificate []byte           `json:"certificate"`
	TaskHash    string           `json:"task_hash"`
	Nonce       []byte           `json:"nonce"`
	Outcome     SoftwareOutcome  `json:"outcome"`
	SignedAt    int64            `json:"signed_at"`
	Signature   []byte           `json:"signature"`
}

func (r SoftwareResult) Valid(now time.Time) bool {
	return r.Context.ValidShape() && r.Identity.Valid() && r.Identity.AgentID == r.Context.Identity.AgentID && r.Identity.TenantID == r.Context.Identity.TenantID && r.Identity.SiteID == r.Context.Identity.SiteID && len(r.Certificate) > 0 && len(r.Certificate) <= 16384 && softwareDigest(r.TaskHash) && len(r.Nonce) == 32 && r.Outcome.ValidForExpectation(r.Context.Expectation) && r.SignedAt >= r.Context.CreatedAt-60 && r.SignedAt <= now.Add(time.Minute).Unix() && len(r.Signature) >= 384 && len(r.Signature) <= 512
}
func SignSoftwareResult(c SoftwareContext, identity SoftwareIdentity, taskHash string, nonce []byte, outcome SoftwareOutcome, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) (*SoftwareResult, error) {
	if cert == nil {
		return nil, ErrSoftware
	}
	r := &SoftwareResult{Context: c, Identity: identity, Certificate: bytes.Clone(cert.Raw), TaskHash: taskHash, Nonce: bytes.Clone(nonce), Outcome: outcome, SignedAt: now.Unix(), Signature: make([]byte, 384)}
	if !r.Valid(now) {
		clear(r.Nonce)
		return nil, ErrSoftware
	}
	r.Signature = nil
	data, _ := json.Marshal(r)
	signature, err := signRecovery(identity, "openuem/windows-software/result/v1\x00", data, cert, key, now)
	if err != nil {
		clear(r.Nonce)
		return nil, ErrSoftware
	}
	r.Signature = signature
	return r, nil
}
func VerifySoftwareResult(r SoftwareResult, cert *x509.Certificate, now time.Time) error {
	if !r.Valid(now) || cert == nil || !bytes.Equal(r.Certificate, cert.Raw) {
		return ErrSoftware
	}
	signature := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	if verifyRecovery(r.Identity, "openuem/windows-software/result/v1\x00", data, signature, cert, time.Unix(r.SignedAt, 0)) != nil {
		return ErrSoftware
	}
	return nil
}
