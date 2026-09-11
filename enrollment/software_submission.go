package enrollment

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"time"
)

// A broker session can briefly outlive certificate rotation while disconnect is
// retried. A historical signed result therefore needs a fresh submission proof
// from the current certificate, not merely a request on the same device subject.
type SoftwareSubmission struct {
	Identity   SoftwareIdentity `json:"identity"`
	TaskID     string           `json:"task_id"`
	ResultHash string           `json:"result_hash"`
	IssuedAt   int64            `json:"issued_at"`
	ExpiresAt  int64            `json:"expires_at"`
	Signature  []byte           `json:"signature"`
}

func (s SoftwareSubmission) Valid(now time.Time) bool {
	return s.Identity.Valid() && ValidDeviceID(s.TaskID) && softwareDigest(s.ResultHash) && s.IssuedAt > 0 && s.IssuedAt <= now.Add(time.Minute).Unix() && s.ExpiresAt > s.IssuedAt && s.ExpiresAt-s.IssuedAt <= 300 && s.ExpiresAt > now.Unix() && len(s.Signature) >= 384 && len(s.Signature) <= 512
}
func (s SoftwareSubmission) Matches(r SoftwareResult, now time.Time) bool {
	receipt, err := SoftwareResultReceipt(r, now)
	return err == nil && s.TaskID == receipt.TaskID && s.ResultHash == receipt.ResultHash && s.Identity.AgentID == r.Context.Identity.AgentID && s.Identity.TenantID == r.Context.Identity.TenantID && s.Identity.SiteID == r.Context.Identity.SiteID
}
func SignSoftwareSubmission(result SoftwareResult, identity SoftwareIdentity, cert *x509.Certificate, key *rsa.PrivateKey, now time.Time) (*SoftwareSubmission, error) {
	receipt, err := SoftwareResultReceipt(result, now)
	if err != nil || cert == nil {
		return nil, ErrSoftware
	}
	expires := now.Add(5 * time.Minute).Unix()
	if cert.NotAfter.Unix() < expires {
		expires = cert.NotAfter.Unix()
	}
	proof := &SoftwareSubmission{Identity: identity, TaskID: receipt.TaskID, ResultHash: receipt.ResultHash, IssuedAt: now.Unix(), ExpiresAt: expires, Signature: make([]byte, 384)}
	if !proof.Valid(now) || !proof.Matches(result, now) {
		return nil, ErrSoftware
	}
	proof.Signature = nil
	data, _ := json.Marshal(proof)
	proof.Signature, err = signRecovery(identity, "openuem/windows-software/submission/v1\x00", data, cert, key, now)
	if err != nil {
		return nil, ErrSoftware
	}
	return proof, nil
}
func VerifySoftwareSubmission(proof SoftwareSubmission, result SoftwareResult, current SoftwareIdentity, cert *x509.Certificate, now time.Time) error {
	if !proof.Valid(now) || proof.Identity != current || !proof.Matches(result, now) || cert == nil || proof.ExpiresAt > cert.NotAfter.Unix() {
		return ErrSoftware
	}
	signature := proof.Signature
	proof.Signature = nil
	data, _ := json.Marshal(proof)
	if verifyRecovery(current, "openuem/windows-software/submission/v1\x00", data, signature, cert, now) != nil {
		return ErrSoftware
	}
	return nil
}
