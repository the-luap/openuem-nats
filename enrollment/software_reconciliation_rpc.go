package enrollment

import "time"

// This grammar uses the existing private software subject with a separate
// protocol discriminator. A worker must opt in explicitly; an executable-task
// decoder cannot accept it or turn a reconciliation into an installer request.
type SoftwareReconciliationRequest struct {
	Version    int                               `json:"version"`
	Protocol   string                            `json:"protocol"`
	AgentID    string                            `json:"agent_id"`
	Action     string                            `json:"action"`
	Result     *SoftwareReconciliationResult     `json:"result,omitempty"`
	Submission *SoftwareReconciliationSubmission `json:"submission,omitempty"`
}

type SoftwareReconciliationReply struct {
	Version  int                         `json:"version"`
	Protocol string                      `json:"protocol"`
	OK       bool                        `json:"ok"`
	Task     *SoftwareReconciliationTask `json:"task,omitempty"`
	Receipt  *SoftwareReceipt            `json:"receipt,omitempty"`
}

func DecodeSoftwareReconciliationRequest(data []byte, now time.Time) (*SoftwareReconciliationRequest, error) {
	var request SoftwareReconciliationRequest
	if decodeSoftwareJSON(data, &request) != nil || request.Version != SoftwareReconciliationVersion || request.Protocol != SoftwareReconciliationProtocol || !ValidDeviceID(request.AgentID) {
		return nil, ErrSoftware
	}
	switch request.Action {
	case "poll":
		if request.Result != nil || request.Submission != nil {
			return nil, ErrSoftware
		}
	case "result":
		if request.Result == nil || request.Submission == nil || !request.Result.Valid(now) || !request.Submission.Valid(now) || !request.Submission.Matches(*request.Result, now) || request.Result.Context.Identity.AgentID != request.AgentID || request.Submission.Identity.AgentID != request.AgentID {
			return nil, ErrSoftware
		}
	default:
		return nil, ErrSoftware
	}
	return &request, nil
}

func DecodeSoftwareReconciliationReply(data []byte, now time.Time) (*SoftwareReconciliationReply, error) {
	var reply SoftwareReconciliationReply
	if decodeSoftwareJSON(data, &reply) != nil || reply.Version != SoftwareReconciliationVersion || reply.Protocol != SoftwareReconciliationProtocol || !reply.OK || reply.Task != nil && reply.Receipt != nil || reply.Task != nil && (!reply.Task.ValidShape() || !reply.Task.Context.Valid(now)) || reply.Receipt != nil && !reply.Receipt.Valid() {
		return nil, ErrSoftware
	}
	return &reply, nil
}
