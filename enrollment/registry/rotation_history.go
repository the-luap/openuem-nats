package registry

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

const MaxHistoricalRotationChecks = 256

// HistoricalRotationCheck admits one fresh read-only challenge after inspecting
// an exact completed rotation. KeyDigest binds the console's encrypted current
// recovery-key record, which the caller must authenticate and retain in the same
// transaction. Neither a prior validation nor an unsigned key/status label is
// evidence of this admission. This type contains no plaintext recovery key.
type HistoricalRotationCheck struct {
	RotationID  string
	ReceiptHash string
	Task        enrollment.RecoveryTask
	NonceHash   string
	KeyDigest   string
}

type historicalRotationCheckRecord struct {
	Version                 int                        `json:"version"`
	RotationID              string                     `json:"rotation_id"`
	ReceiptHash             string                     `json:"receipt_hash"`
	RotationCertificateHash string                     `json:"rotation_certificate_hash"`
	RotationCompletedAt     time.Time                  `json:"rotation_completed_at"`
	Context                 enrollment.RecoveryContext `json:"context"`
	NonceHash               string                     `json:"nonce_hash"`
	KeyDigest               string                     `json:"key_digest"`
	Certificate             []byte                     `json:"certificate"`
	Actor                   string                     `json:"actor"`
	CreatedAt               time.Time                  `json:"created_at"`
}

func historicalRotationCheckPurpose(device, id string) string {
	return "rotation-recovery-check/v1/" + device + "/" + id
}

func validRotationDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func (s *Store) openHistoricalRotationCheck(encoded []byte, device, id string) (*historicalRotationCheckRecord, error) {
	if len(encoded) > 32768 {
		return nil, ErrUnavailable
	}
	plain, err := s.open(encoded, historicalRotationCheckPurpose(device, id))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	var r historicalRotationCheckRecord
	if strictjson.Unmarshal(plain, &r) != nil || r.Version != 1 || !enrollment.ValidDeviceID(r.RotationID) || !r.Context.Valid(r.CreatedAt) || r.Context.Identity.AgentID != device || r.Context.TaskID != id || !validRotationDigest(r.ReceiptHash) || !validRotationDigest(r.RotationCertificateHash) || !validRotationDigest(r.NonceHash) || !validRotationDigest(r.KeyDigest) || len(r.Certificate) > 16<<10 || r.CreatedAt.IsZero() || r.RotationCompletedAt.IsZero() || r.CreatedAt.Before(r.RotationCompletedAt) || r.Actor == "" || len(r.Actor) > 255 {
		return nil, ErrUnavailable
	}
	cert, err := x509.ParseCertificate(r.Certificate)
	if err != nil || digest(cert.Raw) != r.Context.Identity.CertificateHash || r.CreatedAt.Before(cert.NotBefore) || !r.CreatedAt.Before(cert.NotAfter) || !time.Unix(r.Context.ExpiresAt, 0).After(r.CreatedAt) || time.Unix(r.Context.ExpiresAt, 0).After(cert.NotAfter) || time.Unix(r.Context.ExpiresAt, 0).After(r.CreatedAt.Add(15*time.Minute)) {
		return nil, ErrUnavailable
	}
	return &r, nil
}

type historicalRotationReceipt struct {
	result    enrollment.RotationResult
	wire      []byte
	completed time.Time
}

// A retained source in an authenticated issuance record was the registry's
// authorized identity when preparation occurred. An unconfirmed candidate is
// never used as historical authority. Missing/corrupt evidence fails closed.
func (s *Store) historicalRotationCertificate(ctx context.Context, tx *sql.Tx, current *identityRenewalCurrent, hash string) (*x509.Certificate, error) {
	if current.hash == hash {
		return x509.ParseCertificate(current.source.Certificate)
	}
	records, err := s.identityRenewalRecords(ctx, tx, current.source.DeviceID)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		q := record.Request
		if q.SourceCertificateHash == hash && q.TenantID == current.source.TenantID && q.SiteID == current.source.SiteID && q.Origin == current.source.Origin && q.Platform == current.source.Platform && q.Architecture == current.source.Architecture {
			return x509.ParseCertificate(record.SourceCertificate)
		}
	}
	return nil, ErrUnavailable
}

func (s *Store) historicalRotationReceipt(ctx context.Context, tx *sql.Tx, current *identityRenewalCurrent, native, task, expectedHash string) (*historicalRotationReceipt, error) {
	if !enrollment.ValidDeviceID(native) || !enrollment.ValidDeviceID(task) || !validRotationDigest(expectedHash) {
		return nil, ErrDenied
	}
	var bound, wire []byte
	var hash, nonceHash, key, recipient, resolution string
	var ordinal int
	var created, delivered, completed, expires time.Time
	var resolved sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT context,result,certificate_hash,nonce_hash,key_id,recipient_id,ordinal,created_at,delivered_at,completed_at,expires_at,COALESCE(resolution_task_id::text,''),resolved_at FROM uem_agent_rotation_tasks WHERE id=$1 AND device_id=$2 AND native_id=$3 AND tenant_id=$4 AND site_id=$5 AND status='completed' AND delivered_at IS NOT NULL AND completed_at IS NOT NULL FOR UPDATE`, task, current.source.DeviceID, native, current.source.TenantID, current.source.SiteID).Scan(&bound, &wire, &hash, &nonceHash, &key, &recipient, &ordinal, &created, &delivered, &completed, &expires, &resolution, &resolved)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDenied
	}
	if err != nil {
		return nil, err
	}
	if len(bound) > 4096 || len(wire) > enrollment.MaxRecoveryMessage || digest(wire) != expectedHash || delivered.Before(created) || !delivered.Before(expires) || completed.Before(delivered) || completed.After(s.identityRenewalTime()) {
		return nil, ErrDenied
	}
	var receipt enrollment.RotationResult
	if strictjson.Unmarshal(wire, &receipt) != nil {
		return nil, ErrDenied
	}
	canonical, _ := json.Marshal(receipt)
	contextWire, _ := json.Marshal(receipt.Context)
	b := receipt.Context.Binding
	if !bytes.Equal(canonical, wire) || !bytes.Equal(contextWire, bound) || b.TaskID != task || b.NativeID != native || b.Identity.AgentID != current.source.DeviceID || b.Identity.TenantID != current.source.TenantID || b.Identity.SiteID != current.source.SiteID || b.Identity.CertificateHash != hash || b.KeyID != key || b.RecipientID != recipient || receipt.Context.Ordinal != ordinal || b.ExpiresAt != expires.Unix() || digest(receipt.Nonce) != nonceHash {
		return nil, ErrDenied
	}
	cert, err := s.historicalRotationCertificate(ctx, tx, current, hash)
	if err != nil {
		return nil, err
	}
	if enrollment.VerifyRotationResult(receipt, cert, completed) != nil {
		return nil, ErrDenied
	}
	// Older resolution writers used separate clock_timestamp() expressions for
	// completion and resolution. Both must precede this admission; equality is
	// not guaranteed and grants no additional signed execution evidence.
	if receipt.Outcome == "uncertain" && (!receipt.ExecutionStopped || resolution == "" || !resolved.Valid || resolved.Time.Before(delivered) || resolved.Time.After(s.identityRenewalTime())) {
		return nil, ErrDenied
	}
	return &historicalRotationReceipt{result: receipt, wire: wire, completed: completed}, nil
}

// QueueHistoricalRotationCheckInTransaction is a trusted console operation.
// Call after locking the native Mac, checking its current canonical agent and
// decrypting its current retained key. The same transaction must store the
// console validation expectation and audit. AccessStore/routing workers cannot
// create this authenticated admission. Every error requires rollback.
func (s *Store) QueueHistoricalRotationCheckInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device string, check HistoricalRotationCheck, actor string) error {
	if s == nil || tx == nil || !scope.valid() || scope.SiteID <= 0 || actor == "" || len(actor) > 255 || !validRotationDigest(check.NonceHash) || !validRotationDigest(check.KeyDigest) || !check.Task.Valid(s.identityRenewalTime()) {
		return ErrDenied
	}
	current, err := loadIdentityRenewalCurrent(ctx, tx, device)
	if err != nil {
		return err
	}
	if current.validate(s.identityRenewalTime()) != nil || current.source.Platform != "macos" || current.source.TenantID != scope.TenantID || current.source.SiteID != scope.SiteID || check.Task.Context.Identity != (enrollment.RecoveryIdentity{AgentID: device, TenantID: scope.TenantID, SiteID: scope.SiteID, CertificateHash: current.hash}) {
		return ErrDenied
	}
	rotation, err := s.historicalRotationReceipt(ctx, tx, current, check.Task.Context.NativeID, check.RotationID, check.ReceiptHash)
	if err != nil {
		return err
	}
	if rotation.result.Outcome != "rotated" && rotation.result.Outcome != "unverified" && rotation.result.Outcome != "uncertain" {
		return ErrDenied
	}
	var count int
	var acknowledged bool
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM uem_agent_rotation_recovery_checks WHERE device_id=$1),EXISTS(SELECT 1 FROM uem_agent_rotation_reconciliations WHERE task_id=$2)`, device, check.RotationID).Scan(&count, &acknowledged); err != nil {
		return err
	}
	if count >= MaxHistoricalRotationChecks || acknowledged {
		return ErrDenied
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_recovery_tasks WHERE device_id=$1 AND status='pending')`, device).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrDenied
	}
	var at time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	if at.Before(rotation.completed) || !time.Unix(check.Task.Context.ExpiresAt, 0).After(at) || time.Unix(check.Task.Context.ExpiresAt, 0).After(at.Add(15*time.Minute)) {
		return ErrDenied
	}
	access, err := NewAccessStore(s.db)
	if err != nil {
		return err
	}
	if err = access.QueueRecoveryTask(ctx, tx, check.Task, check.NonceHash); err != nil {
		return err
	}
	r := historicalRotationCheckRecord{Version: 1, RotationID: check.RotationID, ReceiptHash: check.ReceiptHash, RotationCertificateHash: rotation.result.Context.Binding.Identity.CertificateHash, RotationCompletedAt: rotation.completed, Context: check.Task.Context, NonceHash: check.NonceHash, KeyDigest: check.KeyDigest, Certificate: bytes.Clone(current.source.Certificate), Actor: actor, CreatedAt: at}
	plain, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(plain)
	encoded, err := s.seal(plain, historicalRotationCheckPurpose(device, r.Context.TaskID))
	if err != nil {
		return ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_rotation_recovery_checks(id,device_id,rotation_task_id,encrypted_record,created_at) VALUES($1,$2,$3,$4,$5)`, r.Context.TaskID, device, r.RotationID, encoded, at); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope, actor, "recovery.rotation.historical-check", r.RotationID); err != nil {
		return err
	}
	return current.validate(s.identityRenewalTime())
}

// AcknowledgeHistoricalRotationCheckInTransaction proves current recoverability;
// it does not reconstruct an erased historical return key. The caller must still
// hold the same native/agent association and decrypt the same current key record
// identified by keyDigest, then finish validation/audit in this transaction.
func (s *Store) AcknowledgeHistoricalRotationCheckInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device, checkID, keyDigest, actor string) error {
	if s == nil || tx == nil || !scope.valid() || scope.SiteID <= 0 || !enrollment.ValidDeviceID(checkID) || !validRotationDigest(keyDigest) || actor == "" || len(actor) > 255 {
		return ErrDenied
	}
	current, err := loadIdentityRenewalCurrent(ctx, tx, device)
	if err != nil {
		return err
	}
	if current.source.TenantID != scope.TenantID || current.source.SiteID != scope.SiteID || current.source.Platform != "macos" || current.validate(s.identityRenewalTime()) != nil {
		return ErrDenied
	}
	var encoded []byte
	var task string
	var created time.Time
	err = tx.QueryRowContext(ctx, `SELECT rotation_task_id,encrypted_record,created_at FROM uem_agent_rotation_recovery_checks WHERE id=$1 AND device_id=$2`, checkID, device).Scan(&task, &encoded, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	check, err := s.openHistoricalRotationCheck(encoded, device, checkID)
	if err != nil || check.RotationID != task || !check.CreatedAt.Equal(created) || check.KeyDigest != keyDigest || check.Context.Identity.CertificateHash != current.hash || check.Context.Identity.TenantID != scope.TenantID || check.Context.Identity.SiteID != scope.SiteID {
		return ErrDenied
	}
	recipient, err := recoveryRecipient(ctx, tx, check.Context.Identity)
	if err != nil || recipient.ID != check.Context.RecipientID {
		return ErrDenied
	}
	rotation, err := s.historicalRotationReceipt(ctx, tx, current, check.Context.NativeID, task, check.ReceiptHash)
	if err != nil {
		return err
	}
	if !rotation.completed.Equal(check.RotationCompletedAt) || rotation.result.Context.Binding.Identity.CertificateHash != check.RotationCertificateHash {
		return ErrDenied
	}
	var wire []byte
	var delivered, completed, expires, queued time.Time
	var nonceHash string
	err = tx.QueryRowContext(ctx, `SELECT result,delivered_at,completed_at,expires_at,created_at,nonce_hash FROM uem_agent_recovery_tasks WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 AND native_id=$5 AND key_id=$6 AND recipient_id=$7 AND certificate_hash=$8 AND status='completed' AND delivered_at IS NOT NULL AND completed_at IS NOT NULL FOR UPDATE`, checkID, device, scope.TenantID, scope.SiteID, check.Context.NativeID, check.Context.KeyID, check.Context.RecipientID, check.Context.Identity.CertificateHash).Scan(&wire, &delivered, &completed, &expires, &queued, &nonceHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if queued.Before(check.CreatedAt) || delivered.Before(queued) || completed.Before(delivered) || !completed.Before(expires) || expires.Unix() != check.Context.ExpiresAt || nonceHash != check.NonceHash || completed.After(s.identityRenewalTime()) || !validHistoricalRotationResult(check, wire, completed) {
		return ErrDenied
	}
	var previous []byte
	var previousCheck sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT encrypted_record,recovery_check_id FROM uem_agent_rotation_reconciliations WHERE task_id=$1 AND device_id=$2`, task, device).Scan(&previous, &previousCheck)
	if err == nil {
		r, err := s.openRotationReconciliation(previous, device, task)
		if err != nil || r.Version != 2 || r.TenantID != scope.TenantID || r.SiteID != scope.SiteID || r.CertificateHash != check.RotationCertificateHash || r.ReconciledAt.Before(completed) || r.RecoveryCheckID != checkID || !previousCheck.Valid || previousCheck.String != checkID || r.ReceiptHash != check.ReceiptHash || r.RecoveryReceiptHash != digest(wire) || !r.RecoveryCompletedAt.Equal(completed) {
			return ErrUnavailable
		}
		return current.validate(s.identityRenewalTime())
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var at time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	if at.Before(completed) {
		return ErrDenied
	}
	r := rotationReconciliation{Version: 2, TaskID: task, DeviceID: device, TenantID: scope.TenantID, SiteID: scope.SiteID, CertificateHash: check.RotationCertificateHash, ReceiptHash: check.ReceiptHash, Actor: actor, ReconciledAt: at, RecoveryCheckID: checkID, RecoveryReceiptHash: digest(wire), RecoveryCompletedAt: completed}
	plain, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(plain)
	sealed, err := s.seal(plain, rotationReconciliationPurpose(device, task))
	if err != nil {
		return ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_rotation_reconciliations(task_id,device_id,encrypted_record,recovery_check_id) VALUES($1,$2,$3,$4)`, task, device, sealed, checkID); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope, actor, "recovery.rotation.historically-reconciled", task); err != nil {
		return err
	}
	return current.validate(s.identityRenewalTime())
}

func validHistoricalRotationResult(check *historicalRotationCheckRecord, wire []byte, completed time.Time) bool {
	if check == nil || len(wire) > enrollment.MaxRecoveryMessage || completed.Before(check.CreatedAt) || !completed.Before(time.Unix(check.Context.ExpiresAt, 0)) {
		return false
	}
	var result enrollment.RecoveryResult
	if strictjson.Unmarshal(wire, &result) != nil || result.Outcome != "valid" || result.Context != check.Context || subtle.ConstantTimeCompare([]byte(digest(result.Nonce)), []byte(check.NonceHash)) != 1 {
		return false
	}
	canonical, _ := json.Marshal(result)
	cert, err := x509.ParseCertificate(check.Certificate)
	return err == nil && bytes.Equal(canonical, wire) && enrollment.VerifyRecoveryResult(result, cert, completed) == nil
}

func (s *Store) validateHistoricalRotationAcknowledgement(ctx context.Context, tx *sql.Tx, ack *rotationReconciliation, rotationWire []byte, rotationCompleted time.Time) error {
	var encoded, wire []byte
	var task, device, status, native, key, recipient, certificateHash, nonceHash string
	var tenant, site int
	var created, queued, expires time.Time
	var delivered, completed sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT c.rotation_task_id,c.device_id,c.encrypted_record,c.created_at,p.result,p.status,p.tenant_id,p.site_id,p.native_id,p.key_id,p.recipient_id,p.certificate_hash,p.nonce_hash,p.created_at,p.delivered_at,p.completed_at,p.expires_at FROM uem_agent_rotation_recovery_checks c JOIN uem_agent_recovery_tasks p ON p.id=c.id AND p.device_id=c.device_id WHERE c.id=$1 AND c.device_id=$2`, ack.RecoveryCheckID, ack.DeviceID).Scan(&task, &device, &encoded, &created, &wire, &status, &tenant, &site, &native, &key, &recipient, &certificateHash, &nonceHash, &queued, &delivered, &completed, &expires)
	if err != nil {
		return ErrUnavailable
	}
	check, err := s.openHistoricalRotationCheck(encoded, device, ack.RecoveryCheckID)
	if err != nil || task != ack.TaskID || check.RotationID != task || check.ReceiptHash != ack.ReceiptHash || check.RotationCertificateHash != ack.CertificateHash || !check.RotationCompletedAt.Equal(rotationCompleted) || !check.CreatedAt.Equal(created) || check.Context.Identity.TenantID != ack.TenantID || check.Context.Identity.SiteID != ack.SiteID {
		return ErrUnavailable
	}
	var rotation enrollment.RotationResult
	if strictjson.Unmarshal(rotationWire, &rotation) != nil || rotation.Context.Binding.NativeID != check.Context.NativeID {
		return ErrUnavailable
	}
	c := check.Context
	if status != "completed" || tenant != c.Identity.TenantID || site != c.Identity.SiteID || native != c.NativeID || key != c.KeyID || recipient != c.RecipientID || certificateHash != c.Identity.CertificateHash || nonceHash != check.NonceHash || expires.Unix() != c.ExpiresAt || queued.Before(created) || !delivered.Valid || delivered.Time.Before(queued) || !completed.Valid || completed.Time.Before(delivered.Time) || !completed.Time.Equal(ack.RecoveryCompletedAt) || digest(wire) != ack.RecoveryReceiptHash || !validHistoricalRotationResult(check, wire, completed.Time) {
		return ErrUnavailable
	}
	return nil
}

// AcknowledgeHistoricalRotationWithoutKeyInTransaction admits only a verified
// non-mutating outcome. A returned key or uncertain execution always requires
// the dedicated current-key challenge instead. The console must reconcile its
// final state and audit in this same transaction.
func (s *Store) AcknowledgeHistoricalRotationWithoutKeyInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device, native, task, receiptHash, actor string) error {
	if s == nil || tx == nil || !scope.valid() || scope.SiteID <= 0 || actor == "" || len(actor) > 255 {
		return ErrDenied
	}
	current, err := loadIdentityRenewalCurrent(ctx, tx, device)
	if err != nil {
		return err
	}
	if current.source.Platform != "macos" || current.source.TenantID != scope.TenantID || current.source.SiteID != scope.SiteID || current.validate(s.identityRenewalTime()) != nil {
		return ErrDenied
	}
	rotation, err := s.historicalRotationReceipt(ctx, tx, current, native, task, receiptHash)
	if err != nil {
		return err
	}
	switch rotation.result.Outcome {
	case "invalid", "unavailable", "unsupported":
	default:
		return ErrDenied
	}
	var previous []byte
	var previousCheck sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT encrypted_record,recovery_check_id FROM uem_agent_rotation_reconciliations WHERE task_id=$1 AND device_id=$2`, task, device).Scan(&previous, &previousCheck)
	if err == nil {
		r, err := s.openRotationReconciliation(previous, device, task)
		if err != nil || r.Version != 1 || previousCheck.Valid || r.TenantID != scope.TenantID || r.SiteID != scope.SiteID || r.CertificateHash != rotation.result.Context.Binding.Identity.CertificateHash || r.ReceiptHash != receiptHash || r.ReconciledAt.Before(rotation.completed) {
			return ErrUnavailable
		}
		return current.validate(s.identityRenewalTime())
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var at time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	if at.Before(rotation.completed) {
		return ErrDenied
	}
	r := rotationReconciliation{Version: 1, TaskID: task, DeviceID: device, TenantID: scope.TenantID, SiteID: scope.SiteID, CertificateHash: rotation.result.Context.Binding.Identity.CertificateHash, ReceiptHash: receiptHash, Actor: actor, ReconciledAt: at}
	plain, err := json.Marshal(r)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(plain)
	sealed, err := s.seal(plain, rotationReconciliationPurpose(device, task))
	if err != nil {
		return ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_rotation_reconciliations(task_id,device_id,encrypted_record) VALUES($1,$2,$3)`, task, device, sealed); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope, actor, "recovery.rotation.historically-reconciled", task); err != nil {
		return err
	}
	return current.validate(s.identityRenewalTime())
}
