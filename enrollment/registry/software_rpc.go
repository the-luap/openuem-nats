package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

// HandleSoftwareInTransaction requires an authenticated, subject-bound request.
// Production workers lock SoftwareIdentity, then their inventory/site rows, and
// retain all locks through this operation, the audit and the response commit.
func (s *AccessStore) HandleSoftwareInTransaction(ctx context.Context, tx *sql.Tx, identity Identity, request enrollment.SoftwareRequest) (*enrollment.SoftwareReply, error) {
	if tx == nil || identity.Platform != "windows" || request.AgentID != identity.ID {
		return nil, ErrDenied
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err = enrollment.DecodeSoftwareRequest(data, time.Now()); err != nil {
		return nil, ErrDenied
	}
	current, certificate, authority, err := s.SoftwareIdentity(ctx, tx, identity.Scope, identity.ID)
	if err != nil {
		return nil, err
	}
	if err = expireSoftwareForAgent(ctx, tx, identity.ID); err != nil {
		return nil, err
	}
	reply := &enrollment.SoftwareReply{Version: enrollment.SoftwareVersion, Protocol: enrollment.SoftwareProtocol, OK: true}
	newDelivery := false
	switch request.Action {
	case "challenge":
		reply.Recipient, err = softwareRecipient(ctx, tx, current)
		if err == nil && bytes.Equal(reply.Recipient.PublicKey, request.PublicKey) {
			break
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		reply.Recipient = nil
		registration := &enrollment.SoftwareRegistration{Version: enrollment.SoftwareVersion, Protocol: enrollment.SoftwareProtocol, Identity: current}
		var expires, created time.Time
		err = tx.QueryRowContext(ctx, `SELECT id,public_key,nonce,expires_at,created_at FROM uem_agent_software_challenges WHERE device_id=$1 AND certificate_hash=$2 AND consumed_at IS NULL`, identity.ID, current.CertificateHash).Scan(&registration.ID, &registration.PublicKey, &registration.Nonce, &expires, &created)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil && bytes.Equal(registration.PublicKey, request.PublicKey) && expires.After(time.Now()) {
			registration.ExpiresAt = expires.Unix()
			reply.Registration = registration
			break
		}
		if err == nil && created.After(time.Now().Add(-5*time.Second)) {
			return nil, ErrDenied
		}
		expires = time.Now().Add(5 * time.Minute).Truncate(time.Second)
		if certificate.NotAfter.Before(expires) {
			expires = certificate.NotAfter
		}
		registration.ID = uuid.NewString()
		registration.PublicKey = bytes.Clone(request.PublicKey)
		registration.Nonce = make([]byte, 32)
		registration.ExpiresAt = expires.Unix()
		if _, err = rand.Read(registration.Nonce); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_software_challenges(device_id,id,certificate_hash,public_key,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,certificate_hash=EXCLUDED.certificate_hash,public_key=EXCLUDED.public_key,nonce=EXCLUDED.nonce,expires_at=EXCLUDED.expires_at,created_at=clock_timestamp(),consumed_at=NULL`, identity.ID, registration.ID, current.CertificateHash, registration.PublicKey, registration.Nonce, expires)
		if err != nil {
			return nil, err
		}
		reply.Registration = registration
	case "register":
		registration := request.Registration
		if registration.Identity != current || enrollment.VerifySoftwareRegistration(*registration, request.Signature, certificate, time.Now()) != nil {
			return nil, ErrDenied
		}
		previous, err := softwareRecipient(ctx, tx, current)
		if err == nil && previous.ID == registration.ID && bytes.Equal(previous.PublicKey, registration.PublicKey) {
			reply.Recipient = previous
			break
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		var matches bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_challenges WHERE device_id=$1 AND id=$2 AND certificate_hash=$3 AND public_key=$4 AND nonce=$5 AND expires_at=to_timestamp($6) AND expires_at>clock_timestamp() AND consumed_at IS NULL)`, identity.ID, registration.ID, current.CertificateHash, registration.PublicKey, registration.Nonce, registration.ExpiresAt).Scan(&matches); err != nil || !matches {
			return nil, ErrDenied
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_software_tasks SET status='cancelled',completed_at=clock_timestamp() WHERE device_id=$1 AND status='pending'`, identity.ID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_software_tasks SET status='uncertain' WHERE device_id=$1 AND status='delivered'`, identity.ID); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_software_recipients(device_id,tenant_id,site_id,id,certificate_hash,public_key) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET id=EXCLUDED.id,certificate_hash=EXCLUDED.certificate_hash,public_key=EXCLUDED.public_key,registered_at=clock_timestamp()`, identity.ID, identity.TenantID, identity.SiteID, registration.ID, current.CertificateHash, registration.PublicKey)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_software_challenges SET consumed_at=clock_timestamp() WHERE device_id=$1`, identity.ID); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.recipient.registered", registration.ID); err != nil {
			return nil, err
		}
		reply.Recipient = &enrollment.SoftwareRecipient{ID: registration.ID, Identity: current, PublicKey: bytes.Clone(registration.PublicKey)}
	case "poll":
		recipient, err := softwareRecipient(ctx, tx, current)
		if err != nil || recipient.ID != request.RecipientID {
			return nil, ErrDenied
		}
		var id string
		err = tx.QueryRowContext(ctx, `SELECT id FROM uem_agent_software_tasks WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND status IN ('pending','delivered','uncertain') AND result IS NULL ORDER BY created_at,id LIMIT 1`, identity.ID, identity.TenantID, identity.SiteID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, err
		}
		record, err := loadSoftwareTask(ctx, tx, identity.Scope, id)
		if err != nil {
			return nil, err
		}
		if record.task.Context.Identity.AgentID != identity.ID || !bytes.Equal(record.authority.Raw, authority.Raw) {
			return nil, ErrDenied
		}
		if record.status == "pending" {
			if enrollment.VerifySoftwareTask(*record.task, authority, current, recipient.ID, time.Now()) != nil {
				return nil, ErrDenied
			}
			if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_software_tasks SET status='delivered',delivered_at=clock_timestamp() WHERE id=$1`, id); err != nil {
				return nil, err
			}
			if err = audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.task.delivered", id); err != nil {
				return nil, err
			}
			newDelivery = true
		} else if record.status != "delivered" && record.status != "uncertain" {
			return nil, ErrDenied
		}
		reply.Task = record.task
	case "result":
		result := request.Result
		if enrollment.VerifySoftwareSubmission(*request.Submission, *result, current, certificate, time.Now()) != nil {
			return nil, ErrDenied
		}
		record, err := loadSoftwareTask(ctx, tx, identity.Scope, result.Context.TaskID)
		if err != nil {
			return nil, err
		}
		if !result.Context.Equal(record.task.Context) || result.TaskHash != record.taskHash || result.Context.Identity.AgentID != identity.ID || !bytes.Equal(record.authority.Raw, authority.Raw) || record.deliveredAt == nil || subtle.ConstantTimeCompare([]byte(record.nonceHash), []byte(digest(result.Nonce))) != 1 {
			return nil, ErrDenied
		}
		signing, err := verifiedSoftwareResultCertificate(*result, authority, time.Now())
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, ErrDenied
		}
		receipt, err := enrollment.SoftwareResultReceipt(*result, time.Now())
		if err != nil {
			return nil, ErrDenied
		}
		if record.result != nil {
			if !bytes.Equal(record.result, encoded) || record.resultHash != receipt.ResultHash {
				return nil, ErrDenied
			}
			reply.Receipt = receipt
			break
		}
		if record.status != "delivered" && record.status != "uncertain" {
			return nil, ErrDenied
		}
		status := "reported"
		if result.Outcome.State == "uncertain" {
			status = "uncertain"
		}
		if result.Outcome.State == "restart_required" {
			status = "restart_required"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_software_tasks SET status=$2,result=$3,result_certificate=$4,result_hash=$5,completed_at=clock_timestamp() WHERE id=$1`, result.Context.TaskID, status, encoded, signing.Raw, receipt.ResultHash); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, identity.Scope, "device:"+identity.ID, "software.task.reported", result.Context.TaskID); err != nil {
			return nil, err
		}
		reply.Receipt = receipt
	default:
		return nil, ErrDenied
	}
	if err = softwareIdentityCurrent(ctx, tx, current); err != nil {
		return nil, err
	}
	if newDelivery && (reply.Task == nil || !reply.Task.Context.Valid(time.Now())) {
		return nil, ErrDenied
	}
	if reply.Registration != nil && !reply.Registration.Valid(time.Now()) {
		return nil, ErrDenied
	}
	if request.Submission != nil && enrollment.VerifySoftwareSubmission(*request.Submission, *request.Result, current, certificate, time.Now()) != nil {
		return nil, ErrDenied
	}
	return reply, nil
}

func verifiedSoftwareResultCertificate(result enrollment.SoftwareResult, authority *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	cert, err := softwareCertificate(result.Certificate)
	if err != nil || authority == nil || cert.Subject.CommonName != result.Identity.AgentID || cert.IsCA || cert.CheckSignatureFrom(authority) != nil || enrollment.VerifySoftwareResult(result, cert, now) != nil {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(result.SignedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrDenied
	}
	return cert, nil
}
