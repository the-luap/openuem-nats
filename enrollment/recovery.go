package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const RecoveryVersion = 1
const MaxRecoveryMessage = 8192

var ErrRecovery = errors.New("private recovery operation is unavailable")

// RecoveryIdentity names an exact currently authorized signing identity. Its
// certificate is used only for signatures, never as an encryption recipient.
type RecoveryIdentity struct {
	AgentID         string `json:"agent_id"`
	TenantID        int    `json:"tenant_id"`
	SiteID          int    `json:"site_id"`
	CertificateHash string `json:"certificate_hash"`
}

func (i RecoveryIdentity) Valid() bool {
	hash, err := hex.DecodeString(i.CertificateHash)
	return ValidDeviceID(i.AgentID) && i.TenantID > 0 && i.SiteID > 0 && err == nil && len(hash) == 32 && hex.EncodeToString(hash) == i.CertificateHash
}

type RecoveryRegistration struct {
	Version   int              `json:"version"`
	Identity  RecoveryIdentity `json:"identity"`
	ID        string           `json:"id"`
	PublicKey []byte           `json:"public_key"`
	Nonce     []byte           `json:"nonce"`
	ExpiresAt int64            `json:"expires_at"`
}

func (r RecoveryRegistration) Valid(now time.Time) bool {
	return r.Version == RecoveryVersion && r.Identity.Valid() && ValidDeviceID(r.ID) && ValidRecoveryPublicKey(r.PublicKey) && len(r.Nonce) == 32 && r.ExpiresAt > now.Unix() && r.ExpiresAt <= now.Add(10*time.Minute).Unix()
}

type RecoveryRecipient struct {
	ID        string           `json:"id"`
	Identity  RecoveryIdentity `json:"identity"`
	PublicKey []byte           `json:"public_key"`
}

func (r RecoveryRecipient) Valid() bool {
	return ValidDeviceID(r.ID) && r.Identity.Valid() && ValidRecoveryPublicKey(r.PublicKey)
}

type RecoveryContext struct {
	Version     int              `json:"version"`
	Identity    RecoveryIdentity `json:"identity"`
	TaskID      string           `json:"task_id"`
	NativeID    string           `json:"native_id"`
	KeyID       string           `json:"key_id"`
	RecipientID string           `json:"recipient_id"`
	ExpiresAt   int64            `json:"expires_at"`
}

func (c RecoveryContext) Valid(now time.Time) bool {
	return c.Version == RecoveryVersion && c.Identity.Valid() && ValidDeviceID(c.TaskID) && ValidDeviceID(c.NativeID) && ValidDeviceID(c.KeyID) && ValidDeviceID(c.RecipientID) && c.ExpiresAt > now.Unix() && c.ExpiresAt <= now.Add(24*time.Hour).Unix()
}

type RecoveryTask struct {
	Context       RecoveryContext `json:"context"`
	Encapsulation []byte          `json:"encapsulation"`
	Ciphertext    []byte          `json:"ciphertext"`
}

func (t RecoveryTask) Valid(now time.Time) bool {
	return t.Context.Valid(now) && len(t.Encapsulation) == 32 && len(t.Ciphertext) == 61+16
}

// RecoveryResult proves possession of the task secret and authenticates the
// exact outcome. A routing worker cannot change an invalid result into a valid
// result simply because it has seen the nonce in a previous response.
type RecoveryResult struct {
	Context   RecoveryContext `json:"context"`
	Outcome   string          `json:"outcome"`
	Nonce     []byte          `json:"nonce"`
	Signature []byte          `json:"signature"`
}

func (r RecoveryResult) Valid(now time.Time) bool {
	return r.Context.Valid(now) && recoveryOutcome(r.Outcome) && len(r.Nonce) == 32 && len(r.Signature) >= 384 && len(r.Signature) <= 512
}

func recoveryOutcome(value string) bool {
	return value == "valid" || value == "invalid" || value == "unavailable" || value == "unsupported"
}

// RecoveryRequest is sent only on the individual agent's recovery RPC. It
// contains no recovery key. Exactly one action-specific group is allowed.
type RecoveryRequest struct {
	Version      int                   `json:"version"`
	AgentID      string                `json:"agent_id"`
	Action       string                `json:"action"`
	PublicKey    []byte                `json:"public_key,omitempty"`
	Registration *RecoveryRegistration `json:"registration,omitempty"`
	Signature    []byte                `json:"signature,omitempty"`
	RecipientID  string                `json:"recipient_id,omitempty"`
	Result       *RecoveryResult       `json:"result,omitempty"`
}

func DecodeRecoveryRequest(data []byte, now time.Time) (*RecoveryRequest, error) {
	var r RecoveryRequest
	if decodeRecoveryJSON(data, &r) != nil || r.Version != RecoveryVersion || !ValidDeviceID(r.AgentID) {
		return nil, ErrRecovery
	}
	switch r.Action {
	case "challenge":
		if !ValidRecoveryPublicKey(r.PublicKey) || r.Registration != nil || len(r.Signature) != 0 || r.RecipientID != "" || r.Result != nil {
			return nil, ErrRecovery
		}
	case "register":
		if len(r.PublicKey) != 0 || r.Registration == nil || !r.Registration.Valid(now) || r.Registration.Identity.AgentID != r.AgentID || len(r.Signature) < 384 || len(r.Signature) > 512 || r.RecipientID != "" || r.Result != nil {
			return nil, ErrRecovery
		}
	case "poll":
		if len(r.PublicKey) != 0 || r.Registration != nil || len(r.Signature) != 0 || !ValidDeviceID(r.RecipientID) || r.Result != nil {
			return nil, ErrRecovery
		}
	case "result":
		if len(r.PublicKey) != 0 || r.Registration != nil || len(r.Signature) != 0 || r.RecipientID != "" || r.Result == nil || !r.Result.Valid(now) || r.Result.Context.Identity.AgentID != r.AgentID {
			return nil, ErrRecovery
		}
	default:
		return nil, ErrRecovery
	}
	return &r, nil
}

type RecoveryReply struct {
	Version      int                   `json:"version"`
	OK           bool                  `json:"ok"`
	Registration *RecoveryRegistration `json:"registration,omitempty"`
	Recipient    *RecoveryRecipient    `json:"recipient,omitempty"`
	Task         *RecoveryTask         `json:"task,omitempty"`
}

func DecodeRecoveryReply(data []byte) (*RecoveryReply, error) {
	var r RecoveryReply
	if decodeRecoveryJSON(data, &r) != nil || r.Version != RecoveryVersion || !r.OK {
		return nil, ErrRecovery
	}
	count := 0
	for _, present := range []bool{r.Registration != nil, r.Recipient != nil, r.Task != nil} {
		if present {
			count++
		}
	}
	if count > 1 {
		return nil, ErrRecovery
	}
	return &r, nil
}

func decodeRecoveryJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxRecoveryMessage || json.Unmarshal(data, target) != nil {
		return ErrRecovery
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrRecovery
	}
	return nil
}

// RecoveryRecipientKey is serialized only at the protected local-store boundary.
// Existing signing and broker keys are never repurposed as encryption keys.
type RecoveryRecipientKey struct{ key hpke.PrivateKey }

func (*RecoveryRecipientKey) String() string               { return "[protected recovery recipient key]" }
func (k *RecoveryRecipientKey) GoString() string           { return k.String() }
func (*RecoveryRecipientKey) MarshalJSON() ([]byte, error) { return nil, ErrRecovery }

func NewRecoveryRecipientKey() (*RecoveryRecipientKey, error) {
	key, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		return nil, ErrRecovery
	}
	return &RecoveryRecipientKey{key}, nil
}

func ParseRecoveryRecipientKey(data []byte) (*RecoveryRecipientKey, error) {
	if len(data) != 32 {
		return nil, ErrRecovery
	}
	key, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(data)
	if err != nil {
		return nil, ErrRecovery
	}
	return &RecoveryRecipientKey{key}, nil
}

func (k *RecoveryRecipientKey) Bytes() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, ErrRecovery
	}
	return k.key.Bytes()
}

func (k *RecoveryRecipientKey) PublicKey() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	return k.key.PublicKey().Bytes()
}

func (k *RecoveryRecipientKey) Close() {
	if k != nil {
		k.key = nil
	}
}

func ValidRecoveryPublicKey(data []byte) bool {
	if len(data) != 32 || data[31]&0x80 != 0 {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return false
	}
	// Reject low-order points rather than accepting a recipient that can never
	// complete a safe encapsulation. The temporary key carries no identity.
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	shared, err := probe.ECDH(public)
	clear(shared)
	return err == nil
}

func ValidFileVaultRecoveryKey(key []byte) bool {
	if len(key) != 29 {
		return false
	}
	for i, b := range key {
		if i%5 == 4 {
			if b != '-' {
				return false
			}
		} else if !(b >= 'A' && b <= 'Z' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}

// EncryptRecoveryTask uses RFC 9180 HPKE with fixed X25519/HKDF-SHA256/AES-256-GCM.
// All public routing fields are cryptographically bound to the ciphertext.
func EncryptRecoveryTask(recipient RecoveryRecipient, c RecoveryContext, key, nonce []byte, now time.Time) (*RecoveryTask, error) {
	if !recipient.Valid() || !c.Valid(now) || recipient.Identity != c.Identity || recipient.ID != c.RecipientID || !ValidFileVaultRecoveryKey(key) || len(nonce) != 32 {
		return nil, ErrRecovery
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(recipient.PublicKey)
	if err != nil {
		return nil, ErrRecovery
	}
	info, _ := json.Marshal(c)
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte("openuem/filevault/validate/v1\x00"), info...))
	if err != nil {
		return nil, ErrRecovery
	}
	plain := append(bytes.Clone(key), nonce...)
	defer clear(plain)
	ciphertext, err := sender.Seal(info, plain)
	if err != nil {
		return nil, ErrRecovery
	}
	return &RecoveryTask{Context: c, Encapsulation: enc, Ciphertext: ciphertext}, nil
}

type RecoverySecret struct {
	context    RecoveryContext
	key, nonce []byte
}

func (*RecoverySecret) String() string               { return "[private recovery validation task]" }
func (s *RecoverySecret) GoString() string           { return s.String() }
func (*RecoverySecret) MarshalJSON() ([]byte, error) { return nil, ErrRecovery }

// Key returns borrowed bytes valid until Close; callers must not log or persist them.
func (s *RecoverySecret) Key() []byte {
	if s == nil {
		return nil
	}
	return s.key
}
func (s *RecoverySecret) Close() {
	if s != nil {
		clear(s.key)
		clear(s.nonce)
		s.key = nil
		s.nonce = nil
	}
}

func (k *RecoveryRecipientKey) Open(task RecoveryTask, identity RecoveryIdentity, recipient string, now time.Time) (*RecoverySecret, error) {
	if k == nil || k.key == nil || !task.Valid(now) || task.Context.Identity != identity || task.Context.RecipientID != recipient {
		return nil, ErrRecovery
	}
	info, _ := json.Marshal(task.Context)
	receiver, err := hpke.NewRecipient(task.Encapsulation, k.key, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte("openuem/filevault/validate/v1\x00"), info...))
	if err != nil {
		return nil, ErrRecovery
	}
	plain, err := receiver.Open(info, task.Ciphertext)
	if err != nil || len(plain) != 61 {
		clear(plain)
		return nil, ErrRecovery
	}
	if !ValidFileVaultRecoveryKey(plain[:29]) {
		clear(plain)
		return nil, ErrRecovery
	}
	return &RecoverySecret{context: task.Context, key: plain[:29:29], nonce: plain[29:]}, nil
}

func SignRecoveryRegistration(r RecoveryRegistration, certificate *x509.Certificate, key *rsa.PrivateKey, now time.Time) ([]byte, error) {
	if !r.Valid(now) {
		return nil, ErrRecovery
	}
	data, _ := json.Marshal(r)
	return signRecovery(r.Identity, "openuem/recovery/register/v1\x00", data, certificate, key, now)
}

func VerifyRecoveryRegistration(r RecoveryRegistration, signature []byte, certificate *x509.Certificate, now time.Time) error {
	if !r.Valid(now) {
		return ErrRecovery
	}
	data, _ := json.Marshal(r)
	return verifyRecovery(r.Identity, "openuem/recovery/register/v1\x00", data, signature, certificate, now)
}

func (s *RecoverySecret) Result(outcome string, certificate *x509.Certificate, key *rsa.PrivateKey, now time.Time) (*RecoveryResult, error) {
	if s == nil || len(s.key) != 29 || len(s.nonce) != 32 || !s.context.Valid(now) || !recoveryOutcome(outcome) {
		return nil, ErrRecovery
	}
	c := s.context
	r := &RecoveryResult{Context: c, Outcome: outcome, Nonce: bytes.Clone(s.nonce)}
	data, _ := json.Marshal(r)
	signature, err := signRecovery(c.Identity, "openuem/recovery/result/v1\x00", data, certificate, key, now)
	if err != nil {
		clear(r.Nonce)
		return nil, err
	}
	r.Signature = signature
	return r, nil
}

func VerifyRecoveryResult(r RecoveryResult, certificate *x509.Certificate, now time.Time) error {
	if !r.Valid(now) {
		return ErrRecovery
	}
	signature := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	return verifyRecovery(r.Context.Identity, "openuem/recovery/result/v1\x00", data, signature, certificate, now)
}

func recoverySigningKey(i RecoveryIdentity, certificate *x509.Certificate, now time.Time) (*rsa.PublicKey, error) {
	if !i.Valid() || certificate == nil || certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) || certificate.Subject.CommonName != i.AgentID {
		return nil, ErrRecovery
	}
	hash := sha256.Sum256(certificate.Raw)
	if hex.EncodeToString(hash[:]) != i.CertificateHash {
		return nil, ErrRecovery
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || key == nil || key.N == nil || key.N.BitLen() < 3072 || key.N.BitLen() > 4096 || key.E != 65537 {
		return nil, ErrRecovery
	}
	return key, nil
}

func signRecovery(i RecoveryIdentity, domain string, data []byte, certificate *x509.Certificate, private *rsa.PrivateKey, now time.Time) ([]byte, error) {
	public, err := recoverySigningKey(i, certificate, now)
	if err != nil || private == nil || private.N == nil || private.N.Cmp(public.N) != 0 || private.E != public.E || private.Validate() != nil {
		return nil, ErrRecovery
	}
	hash := sha256.Sum256(append([]byte(domain), data...))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hash[:])
	if err != nil {
		return nil, ErrRecovery
	}
	return signature, nil
}

func verifyRecovery(i RecoveryIdentity, domain string, data, signature []byte, certificate *x509.Certificate, now time.Time) error {
	key, err := recoverySigningKey(i, certificate, now)
	if err != nil {
		return ErrRecovery
	}
	hash := sha256.Sum256(append([]byte(domain), data...))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) != nil {
		return ErrRecovery
	}
	return nil
}
