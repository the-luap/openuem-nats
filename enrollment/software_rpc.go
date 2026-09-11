package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type SoftwareRequest struct {
	Version      int                   `json:"version"`
	Protocol     string                `json:"protocol"`
	AgentID      string                `json:"agent_id"`
	Action       string                `json:"action"`
	PublicKey    []byte                `json:"public_key,omitempty"`
	Registration *SoftwareRegistration `json:"registration,omitempty"`
	Signature    []byte                `json:"signature,omitempty"`
	RecipientID  string                `json:"recipient_id,omitempty"`
	Result       *SoftwareResult       `json:"result,omitempty"`
	Submission   *SoftwareSubmission   `json:"submission,omitempty"`
}
type SoftwareReceipt struct {
	TaskID     string `json:"task_id"`
	ResultHash string `json:"result_hash"`
}

func (r SoftwareReceipt) Valid() bool { return ValidDeviceID(r.TaskID) && softwareDigest(r.ResultHash) }

type SoftwareReply struct {
	Version      int                   `json:"version"`
	Protocol     string                `json:"protocol"`
	OK           bool                  `json:"ok"`
	Registration *SoftwareRegistration `json:"registration,omitempty"`
	Recipient    *SoftwareRecipient    `json:"recipient,omitempty"`
	Task         *SoftwareTask         `json:"task,omitempty"`
	Receipt      *SoftwareReceipt      `json:"receipt,omitempty"`
}

func decodeSoftwareJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxSoftwareMessage || json.Unmarshal(data, target) != nil {
		return ErrSoftware
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrSoftware
	}
	return nil
}
func DecodeSoftwareRequest(data []byte, now time.Time) (*SoftwareRequest, error) {
	var r SoftwareRequest
	if decodeSoftwareJSON(data, &r) != nil || r.Version != SoftwareVersion || r.Protocol != SoftwareProtocol || !ValidDeviceID(r.AgentID) {
		return nil, ErrSoftware
	}
	switch r.Action {
	case "challenge":
		if !ValidRecoveryPublicKey(r.PublicKey) || r.Registration != nil || len(r.Signature) != 0 || r.RecipientID != "" || r.Result != nil || r.Submission != nil {
			return nil, ErrSoftware
		}
	case "register":
		if len(r.PublicKey) != 0 || r.Registration == nil || !r.Registration.Valid(now) || r.Registration.Identity.AgentID != r.AgentID || len(r.Signature) < 384 || len(r.Signature) > 512 || r.RecipientID != "" || r.Result != nil || r.Submission != nil {
			return nil, ErrSoftware
		}
	case "poll":
		if len(r.PublicKey) != 0 || r.Registration != nil || len(r.Signature) != 0 || !ValidDeviceID(r.RecipientID) || r.Result != nil || r.Submission != nil {
			return nil, ErrSoftware
		}
	case "result":
		if len(r.PublicKey) != 0 || r.Registration != nil || len(r.Signature) != 0 || r.RecipientID != "" || r.Result == nil || !r.Result.Valid(now) || r.Result.Identity.AgentID != r.AgentID || r.Submission == nil || !r.Submission.Valid(now) || !r.Submission.Matches(*r.Result, now) || r.Submission.Identity.AgentID != r.AgentID {
			return nil, ErrSoftware
		}
	default:
		return nil, ErrSoftware
	}
	return &r, nil
}
func DecodeSoftwareReply(data []byte, now time.Time) (*SoftwareReply, error) {
	var r SoftwareReply
	if decodeSoftwareJSON(data, &r) != nil || r.Version != SoftwareVersion || r.Protocol != SoftwareProtocol || !r.OK {
		return nil, ErrSoftware
	}
	count := 0
	for _, present := range []bool{r.Registration != nil, r.Recipient != nil, r.Task != nil, r.Receipt != nil} {
		if present {
			count++
		}
	}
	if count > 1 || (r.Registration != nil && !r.Registration.Valid(now)) || (r.Recipient != nil && !r.Recipient.Valid()) || (r.Task != nil && !r.Task.ValidShape()) || (r.Receipt != nil && !r.Receipt.Valid()) {
		return nil, ErrSoftware
	}
	// Expired task envelopes may be returned solely to recover a durable receipt
	// or record uncertain execution. Open/Verify still prohibit starting old work.
	return &r, nil
}
func SoftwareResultReceipt(r SoftwareResult, now time.Time) (*SoftwareReceipt, error) {
	if !r.Valid(now) {
		return nil, ErrSoftware
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, ErrSoftware
	}
	hash := sha256.Sum256(data)
	return &SoftwareReceipt{TaskID: r.Context.TaskID, ResultHash: hex.EncodeToString(hash[:])}, nil
}
