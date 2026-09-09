package enrollment

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"time"
)

const RotationVersion = 2
const RotationProtocol = "filevault-rotation"
const MaxRotationAttempts = 128
const RotationTaskLifetime = 15 * time.Minute

// RotationReceiptGrace reserves time for signing and durable encrypted receipt
// publication before the current enrollment certificate expires.
const RotationReceiptGrace = 2 * time.Minute

// RotationContext binds a mutation to one key version, a confirmed escrow
// destination and an immutable local journal slot. ReplyKey is a separate,
// per-attempt console X25519 recipient, encoded as canonical lower-case hex.
type RotationContext struct {
	Binding  RecoveryContext `json:"binding"`
	Ordinal  int             `json:"ordinal"`
	EscrowID string          `json:"escrow_id"`
	ReplyKey string          `json:"reply_key"`
}

func (c RotationContext) validShape() bool {
	key, err := hex.DecodeString(c.ReplyKey)
	return c.Ordinal >= 1 && c.Ordinal <= MaxRotationAttempts && ValidDeviceID(c.EscrowID) &&
		err == nil && hex.EncodeToString(key) == c.ReplyKey && ValidRecoveryPublicKey(key) &&
		c.Binding.ExpiresAt > 0 && c.Binding.Valid(time.Unix(c.Binding.ExpiresAt-1, 0))
}

func (c RotationContext) Valid(now time.Time) bool {
	return c.validShape() && c.Binding.Valid(now) && c.Binding.ExpiresAt <= now.Add(RotationTaskLifetime).Unix()
}

// ValidReceipt deliberately does not apply the mutation deadline. A locally
// journaled result may arrive after an outage. The receiver must still match its
// independent task record and the currently authorized certificate/recipient.
func (c RotationContext) ValidReceipt() bool { return c.validShape() }

type RotationEnvelope struct {
	Encapsulation []byte `json:"encapsulation"`
	Ciphertext    []byte `json:"ciphertext"`
}

func (e RotationEnvelope) valid() bool {
	return len(e.Encapsulation) == 32 && len(e.Ciphertext) == 61+16
}

type RotationTask struct {
	Context  RotationContext  `json:"context"`
	Envelope RotationEnvelope `json:"envelope"`
}

func (t RotationTask) Valid(now time.Time) bool { return t.Context.Valid(now) && t.Envelope.valid() }

// RotationResult always authenticates the nonce, outcome and encrypted new key.
// "rotated" means the endpoint also validated the returned key. "unverified"
// preserves a returned candidate key when its validation could not complete.
// "uncertain" means an admitted mutation has no recoverable output; it must not
// be retried automatically. Native MDM escrow remains the recovery fallback.
type RotationResult struct {
	Context RotationContext `json:"context"`
	Outcome string          `json:"outcome"`
	// ExecutionStopped is an authenticated stopping proof for uncertainty, not
	// a conclusion inferred from agent restart, deadline expiry or a free lease.
	ExecutionStopped bool              `json:"execution_stopped,omitempty"`
	Nonce            []byte            `json:"nonce"`
	NewKey           *RotationEnvelope `json:"new_key,omitempty"`
	Signature        []byte            `json:"signature"`
}

func rotationOutcome(value string) bool {
	return value == "rotated" || value == "unverified" || value == "uncertain" || value == "invalid" || value == "unavailable" || value == "unsupported"
}

func (r RotationResult) Valid() bool {
	if !r.Context.ValidReceipt() || !rotationOutcome(r.Outcome) || (r.ExecutionStopped && r.Outcome != "uncertain") || len(r.Nonce) != 32 || len(r.Signature) < 384 || len(r.Signature) > 512 {
		return false
	}
	withKey := r.Outcome == "rotated" || r.Outcome == "unverified"
	return withKey && r.NewKey != nil && r.NewKey.valid() || !withKey && r.NewKey == nil
}

type RotationRequest struct {
	Version     int             `json:"version"`
	Protocol    string          `json:"protocol"`
	AgentID     string          `json:"agent_id"`
	Action      string          `json:"action"`
	RecipientID string          `json:"recipient_id,omitempty"`
	Result      *RotationResult `json:"result,omitempty"`
}

func DecodeRotationRequest(data []byte) (*RotationRequest, error) {
	var r RotationRequest
	if decodeRecoveryJSON(data, &r) != nil || r.Version != RotationVersion || r.Protocol != RotationProtocol || !ValidDeviceID(r.AgentID) {
		return nil, ErrRecovery
	}
	switch r.Action {
	case "poll":
		if !ValidDeviceID(r.RecipientID) || r.Result != nil {
			return nil, ErrRecovery
		}
	case "result":
		if r.RecipientID != "" || r.Result == nil || !r.Result.Valid() || r.Result.Context.Binding.Identity.AgentID != r.AgentID {
			return nil, ErrRecovery
		}
	default:
		return nil, ErrRecovery
	}
	return &r, nil
}

type RotationReply struct {
	Version  int              `json:"version"`
	Protocol string           `json:"protocol"`
	OK       bool             `json:"ok"`
	Task     *RotationTask    `json:"task,omitempty"`
	Receipt  *RotationContext `json:"receipt,omitempty"`
}

func DecodeRotationReply(data []byte, now time.Time) (*RotationReply, error) {
	var r RotationReply
	if decodeRecoveryJSON(data, &r) != nil || r.Version != RotationVersion || r.Protocol != RotationProtocol || !r.OK || r.Task != nil && r.Receipt != nil {
		return nil, ErrRecovery
	}
	if r.Task != nil && !r.Task.Valid(now) || r.Receipt != nil && !r.Receipt.ValidReceipt() {
		return nil, ErrRecovery
	}
	return &r, nil
}

const rotationTaskDomain = "openuem/filevault/rotation/task/v1\x00"
const rotationKeyDomain = "openuem/filevault/rotation/key/v1\x00"
const rotationResultDomain = "openuem/filevault/rotation/result/v1\x00"

func sealRotation(c RotationContext, domain string, public, key, nonce []byte) (*RotationEnvelope, error) {
	if !c.ValidReceipt() || !ValidRecoveryPublicKey(public) || !ValidFileVaultRecoveryKey(key) || len(nonce) != 32 {
		return nil, ErrRecovery
	}
	recipient, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(public)
	if err != nil {
		return nil, ErrRecovery
	}
	info, _ := json.Marshal(c)
	enc, sender, err := hpke.NewSender(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte(domain), info...))
	if err != nil {
		return nil, ErrRecovery
	}
	plain := make([]byte, len(key)+len(nonce))
	copy(plain, key)
	copy(plain[len(key):], nonce)
	defer clear(plain)
	ciphertext, err := sender.Seal(info, plain)
	if err != nil {
		return nil, ErrRecovery
	}
	return &RotationEnvelope{Encapsulation: enc, Ciphertext: ciphertext}, nil
}

func EncryptRotationTask(r RecoveryRecipient, c RotationContext, key, nonce []byte, now time.Time) (*RotationTask, error) {
	if !r.Valid() || !c.Valid(now) || r.Identity != c.Binding.Identity || r.ID != c.Binding.RecipientID || hex.EncodeToString(r.PublicKey) == c.ReplyKey {
		return nil, ErrRecovery
	}
	envelope, err := sealRotation(c, rotationTaskDomain, r.PublicKey, key, nonce)
	if err != nil {
		return nil, err
	}
	return &RotationTask{Context: c, Envelope: *envelope}, nil
}

type RotationSecret struct {
	key, nonce []byte
}

func (*RotationSecret) String() string               { return "[private FileVault rotation material]" }
func (s *RotationSecret) GoString() string           { return s.String() }
func (*RotationSecret) MarshalJSON() ([]byte, error) { return nil, ErrRecovery }

// Key and Nonce are borrowed byte slices. Close clears both. A journal may
// retain the nonce to authenticate an uncertain result after process restart;
// it must never retain the old or new plaintext recovery key.
func (s *RotationSecret) Key() []byte {
	if s == nil {
		return nil
	}
	return s.key
}

func (s *RotationSecret) Nonce() []byte {
	if s == nil {
		return nil
	}
	return s.nonce
}

func (s *RotationSecret) Close() {
	if s != nil {
		clear(s.key)
		clear(s.nonce)
		s.key, s.nonce = nil, nil
	}
}

func (k *RecoveryRecipientKey) openRotation(c RotationContext, e RotationEnvelope, domain string) (*RotationSecret, error) {
	if k == nil || k.key == nil || !c.ValidReceipt() || !e.valid() {
		return nil, ErrRecovery
	}
	info, _ := json.Marshal(c)
	receiver, err := hpke.NewRecipient(e.Encapsulation, k.key, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte(domain), info...))
	if err != nil {
		return nil, ErrRecovery
	}
	plain, err := receiver.Open(info, e.Ciphertext)
	if err != nil || len(plain) != 61 || !ValidFileVaultRecoveryKey(plain[:29]) {
		clear(plain)
		return nil, ErrRecovery
	}
	return &RotationSecret{key: plain[:29:29], nonce: plain[29:]}, nil
}

func (k *RecoveryRecipientKey) OpenRotationTask(t RotationTask, identity RecoveryIdentity, recipient string, now time.Time) (*RotationSecret, error) {
	if !t.Valid(now) || t.Context.Binding.Identity != identity || t.Context.Binding.RecipientID != recipient || k == nil || hex.EncodeToString(k.PublicKey()) == t.Context.ReplyKey {
		return nil, ErrRecovery
	}
	return k.openRotation(t.Context, t.Envelope, rotationTaskDomain)
}

func NewRotationResult(c RotationContext, outcome string, nonce, newKey []byte, certificate *x509.Certificate, signer *rsa.PrivateKey, now time.Time) (*RotationResult, error) {
	return newRotationResult(c, outcome, nonce, newKey, false, certificate, signer, now)
}

// NewStoppedRotationResult is only for callers that observed the mutation
// process terminate, or proved a different kernel boot session from admission.
// Acquiring an agent process lease after a crash is insufficient: an orphaned
// command can outlive its parent. The stopping evidence is part of the signature.
func NewStoppedRotationResult(c RotationContext, nonce []byte, certificate *x509.Certificate, signer *rsa.PrivateKey, now time.Time) (*RotationResult, error) {
	return newRotationResult(c, "uncertain", nonce, nil, true, certificate, signer, now)
}

func newRotationResult(c RotationContext, outcome string, nonce, newKey []byte, stopped bool, certificate *x509.Certificate, signer *rsa.PrivateKey, now time.Time) (*RotationResult, error) {
	if !c.ValidReceipt() || !rotationOutcome(outcome) || len(nonce) != 32 {
		return nil, ErrRecovery
	}
	r := &RotationResult{Context: c, Outcome: outcome, ExecutionStopped: stopped, Nonce: bytes.Clone(nonce)}
	if outcome == "rotated" || outcome == "unverified" {
		public, _ := hex.DecodeString(c.ReplyKey)
		var err error
		r.NewKey, err = sealRotation(c, rotationKeyDomain, public, newKey, nonce)
		if err != nil {
			clear(r.Nonce)
			return nil, err
		}
	} else if len(newKey) != 0 {
		clear(r.Nonce)
		return nil, ErrRecovery
	}
	data, _ := json.Marshal(r)
	signature, err := signRecovery(c.Binding.Identity, rotationResultDomain, data, certificate, signer, now)
	if err != nil {
		clear(r.Nonce)
		return nil, err
	}
	r.Signature = signature
	return r, nil
}

func VerifyRotationResult(r RotationResult, certificate *x509.Certificate, now time.Time) error {
	if !r.Valid() {
		return ErrRecovery
	}
	signature := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	return verifyRecovery(r.Context.Binding.Identity, rotationResultDomain, data, signature, certificate, now)
}

// OpenRotationResult requires the independently stored console context and the
// authorized signing certificate. It cannot be used as an unauthenticated
// decryption oracle for arbitrary routing-worker ciphertext.
func (k *RecoveryRecipientKey) OpenRotationResult(r RotationResult, expected RotationContext, nonceHash string, certificate *x509.Certificate, now time.Time) (*RotationSecret, error) {
	hash := sha256.Sum256(r.Nonce)
	if r.Context != expected || r.NewKey == nil || k == nil || hex.EncodeToString(k.PublicKey()) != expected.ReplyKey || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(nonceHash)) != 1 || VerifyRotationResult(r, certificate, now) != nil {
		return nil, ErrRecovery
	}
	secret, err := k.openRotation(expected, *r.NewKey, rotationKeyDomain)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(secret.Nonce(), r.Nonce) != 1 {
		secret.Close()
		return nil, ErrRecovery
	}
	return secret, nil
}
