package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/open-uem/nats/enrollment"
)

type softwareTaskRecord struct {
	task                                           *enrollment.SoftwareTask
	source, authority                              *x509.Certificate
	nonceHash, taskHash, status, actor, resultHash string
	result                                         []byte
	resultCertificate                              *x509.Certificate
	deliveredAt                                    *time.Time
}

func loadSoftwareTask(ctx context.Context, tx *sql.Tx, scope Scope, id string) (*softwareTaskRecord, error) {
	var envelope, contextWire, certificate, authority, resultCertificate []byte
	var agent, preparation, revision, recipient, certificateHash string
	var created, expires time.Time
	var resultHash sql.NullString
	record := new(softwareTaskRecord)
	err := tx.QueryRowContext(ctx, `SELECT device_id,preparation_id,revision_id,recipient_id,certificate_hash,certificate,authority,nonce_hash,task_hash,task_context,envelope,actor,status,created_at,expires_at,delivered_at,result,result_certificate,result_hash FROM uem_agent_software_tasks WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&agent, &preparation, &revision, &recipient, &certificateHash, &certificate, &authority, &record.nonceHash, &record.taskHash, &contextWire, &envelope, &record.actor, &record.status, &created, &expires, &record.deliveredAt, &record.result, &resultCertificate, &resultHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	record.task, err = enrollment.DecodeSoftwareTask(envelope)
	if err != nil {
		return nil, ErrDenied
	}
	c := record.task.Context
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(contextWire, canonical) || c.Identity.AgentID != agent || c.Identity.TenantID != scope.TenantID || c.Identity.SiteID != scope.SiteID || c.Identity.CertificateHash != certificateHash || c.TaskID != id || c.PreparationID != preparation || c.RevisionID != revision || c.RecipientID != recipient || c.CreatedAt != created.Unix() || c.ExpiresAt != expires.Unix() {
		return nil, ErrDenied
	}
	record.source, err = softwareCertificate(certificate)
	if err != nil {
		return nil, err
	}
	record.authority, err = softwareCertificate(authority)
	if err != nil {
		return nil, err
	}
	hash, err := record.task.Digest()
	if err != nil || hash != record.taskHash || digest(record.source.Raw) != certificateHash || record.source.Subject.CommonName != agent || record.source.CheckSignatureFrom(record.authority) != nil || enrollment.VerifySoftwareTaskHistory(*record.task, record.authority) != nil {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	roots.AddCert(record.authority)
	if c.ExpiresAt > record.source.NotAfter.Unix() {
		return nil, ErrDenied
	}
	if _, err = record.source.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(c.CreatedAt, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, ErrDenied
	}
	if len(record.result) > 0 {
		record.resultCertificate, err = softwareCertificate(resultCertificate)
		if err != nil {
			return nil, err
		}
		var result enrollment.SoftwareResult
		if json.Unmarshal(record.result, &result) != nil || !result.Context.Equal(c) || result.TaskHash != hash || digest(result.Nonce) != record.nonceHash || result.Identity.AgentID != agent || result.Identity.TenantID != scope.TenantID || result.Identity.SiteID != scope.SiteID || enrollment.VerifySoftwareResult(result, record.resultCertificate, time.Now()) != nil {
			return nil, ErrDenied
		}
		if _, err = verifiedSoftwareResultCertificate(result, record.authority, time.Now()); err != nil {
			return nil, ErrDenied
		}
		canonical, err := json.Marshal(result)
		if err != nil || !bytes.Equal(canonical, record.result) {
			return nil, ErrDenied
		}
		receipt, err := enrollment.SoftwareResultReceipt(result, time.Now())
		if err != nil || !resultHash.Valid || receipt.ResultHash != resultHash.String {
			return nil, ErrDenied
		}
		record.resultHash = resultHash.String
	} else if len(resultCertificate) > 0 || resultHash.Valid {
		return nil, ErrDenied
	}
	return record, nil
}

// QueueSoftwareTaskInTransaction is a trusted console boundary. Its caller has
// already locked and authorized the catalog revision, preparation, inventory
// scope and explicit dispatch intent. No routing worker receives the CA key.
func (s *Store) QueueSoftwareTaskInTransaction(ctx context.Context, tx *sql.Tx, scope Scope, device, id, preparation, revision string, plan enrollment.SoftwarePlan, expires time.Time, actor string) (*enrollment.SoftwareTask, error) {
	if tx == nil || !scope.valid() || scope.SiteID <= 0 || actor == "" || !enrollment.ValidDeviceID(device) || !enrollment.ValidDeviceID(id) || !enrollment.ValidDeviceID(preparation) || !enrollment.ValidDeviceID(revision) || !plan.Valid() {
		return nil, ErrDenied
	}
	access, _ := NewAccessStore(s.db)
	identity, certificate, pinned, err := access.SoftwareIdentity(ctx, tx, scope, device)
	if err != nil {
		return nil, err
	}
	recipient, err := softwareRecipient(ctx, tx, identity)
	if err != nil {
		return nil, err
	}
	var architecture string
	if err = tx.QueryRowContext(ctx, `SELECT architecture FROM uem_agent_identities WHERE id=$1`, device).Scan(&architecture); err != nil || architecture != plan.Architecture {
		return nil, ErrDenied
	}
	expires = expires.Truncate(time.Second)
	now := time.Now().Truncate(time.Second)
	if !expires.After(now.Add(time.Minute)) || expires.After(now.Add(time.Hour)) || expires.After(certificate.NotAfter) {
		return nil, ErrDenied
	}
	hash, err := plan.Digest()
	if err != nil {
		return nil, ErrDenied
	}
	previous, err := loadSoftwareTask(ctx, tx, scope, id)
	if err == nil {
		c := previous.task.Context
		if previous.actor != actor || c.Identity != identity || c.PlanHash != hash || c.PreparationID != preparation || c.RevisionID != revision || c.RecipientID != recipient.ID || c.ExpiresAt != expires.Unix() {
			return nil, ErrDenied
		}
		return previous.task, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err = expireSoftwareForAgent(ctx, tx, device); err != nil {
		return nil, err
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_agent_software_tasks WHERE device_id=$1 AND status IN ('pending','delivered','uncertain','restart_required'))`, device).Scan(&active); err != nil {
		return nil, err
	}
	if active {
		return nil, ErrDenied
	}
	var authorityPEM, encrypted []byte
	if err = tx.QueryRowContext(ctx, `SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=$1 FOR SHARE`, scope.TenantID).Scan(&authorityPEM, &encrypted); err != nil {
		return nil, err
	}
	private, err := s.open(encrypted, fmt.Sprintf("%d/authority/key", scope.TenantID))
	if err != nil {
		return nil, ErrDenied
	}
	defer clear(private)
	authority, issuer, err := parseAuthority(authorityPEM, private)
	if err != nil || !bytes.Equal(authority.Raw, pinned.Raw) {
		return nil, ErrDenied
	}
	c := enrollment.SoftwareContext{Version: enrollment.SoftwareVersion, Protocol: enrollment.SoftwareProtocol, Identity: identity, TaskID: id, PreparationID: preparation, RevisionID: revision, RecipientID: recipient.ID, PlanHash: hash, Expectation: plan.Expectation(), CreatedAt: now.Unix(), ExpiresAt: expires.Unix()}
	nonce := make([]byte, 32)
	defer clear(nonce)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	task, err := enrollment.SealSoftwareTask(*recipient, c, plan, nonce, authority, issuer, now)
	if err != nil {
		return nil, ErrDenied
	}
	envelope, err := json.Marshal(task)
	if err != nil || len(envelope) > enrollment.MaxSoftwareMessage {
		return nil, ErrDenied
	}
	taskHash, err := task.Digest()
	if err != nil {
		return nil, ErrDenied
	}
	contextWire, _ := json.Marshal(c)
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_software_tasks(id,tenant_id,site_id,device_id,preparation_id,revision_id,recipient_id,certificate_hash,certificate,authority,nonce_hash,task_hash,task_context,envelope,actor,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, id, scope.TenantID, scope.SiteID, device, preparation, revision, recipient.ID, identity.CertificateHash, certificate.Raw, pinned.Raw, digest(nonce), taskHash, contextWire, envelope, actor, now, expires)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, scope, actor, "software.task.queued", id); err != nil {
		return nil, err
	}
	if err = softwareIdentityCurrent(ctx, tx, identity); err != nil {
		return nil, err
	}
	if !expires.After(time.Now()) {
		return nil, ErrDenied
	}
	return task, nil
}

func expireSoftwareForAgent(ctx context.Context, tx *sql.Tx, device string) error {
	rows, err := tx.QueryContext(ctx, `UPDATE uem_agent_software_tasks SET status=CASE WHEN status='pending' THEN 'expired' ELSE 'uncertain' END,completed_at=CASE WHEN status='pending' THEN clock_timestamp() ELSE NULL END WHERE device_id=$1 AND status IN ('pending','delivered') AND expires_at<=clock_timestamp() RETURNING id,tenant_id,site_id,status`, device)
	if err != nil {
		return err
	}
	type expired struct {
		id, status string
		scope      Scope
	}
	var items []expired
	for rows.Next() {
		var item expired
		if err = rows.Scan(&item.id, &item.scope.TenantID, &item.scope.SiteID, &item.status); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		if err = audit(ctx, tx, item.scope, "system", "software.task."+item.status, item.id); err != nil {
			return err
		}
	}
	return nil
}

// ExpireSoftwareTasks never releases a delivered mutation on timeout. Unknown
// execution remains reserved, with its signed envelope available for receipts.
func (s *AccessStore) ExpireSoftwareTasks(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM uem_agent_software_tasks WHERE status IN ('pending','delivered') AND expires_at<=clock_timestamp() ORDER BY device_id LIMIT 128`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = expireSoftwareForAgent(ctx, tx, id)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			return err
		}
	}
	return nil
}
