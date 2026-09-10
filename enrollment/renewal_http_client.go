package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/open-uem/nats/enrollment/internal/strictjson"
)

// PrepareIdentityRenewal performs one HTTPS request to the previously authorized
// origin. Source and candidate keys/request ID must already be durable. Returned
// issuance does not change local or server-side current authorization by itself.
func (c *HTTPClient) PrepareIdentityRenewal(ctx context.Context, request RenewalRequest, source RenewalSource) (*PreparedIdentityRenewal, error) {
	if c == nil || ctx == nil || source.Origin != c.origin {
		return nil, ErrRenewalProof
	}
	if _, err := ValidateRenewalProof(request, source, time.Now()); err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxRenewalRequestBytes {
		return nil, ErrRenewalProof
	}
	data, err := c.identityRenewalJSON(ctx, IdentityRenewalPath(source.DeviceID, "prepare"), body, MaxPreparedIdentityRenewalBytes)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	response, err := DecodePreparedIdentityRenewal(data)
	if err != nil {
		return nil, err
	}
	if _, err := ValidatePreparedIdentityRenewal(*response, request, source, time.Now()); err != nil {
		return nil, err
	}
	return response, nil
}

// ConfirmIdentityRenewal performs no implicit retries, key installation or old-key
// fallback. Any failed/cancelled request may have committed: retain the candidate
// and recover using a fresh proof for the SAME persisted target. A conflict or
// transport error alone does not authorize discarding a confirmation intent.
func (c *HTTPClient) ConfirmIdentityRenewal(ctx context.Context, request RenewalConfirmation, target RenewalConfirmationTarget) (*ConfirmedIdentityRenewal, error) {
	if c == nil || ctx == nil || target.Candidate.Origin != c.origin {
		return nil, ErrRenewalConfirmation
	}
	if err := ValidateRenewalConfirmation(request, target, time.Now()); err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxRenewalConfirmationBytes {
		return nil, ErrRenewalConfirmation
	}
	data, err := c.identityRenewalJSON(ctx, IdentityRenewalPath(request.DeviceID, "confirm"), body, MaxConfirmedIdentityRenewalBytes)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	response, err := DecodeConfirmedIdentityRenewal(data)
	if err != nil {
		return nil, err
	}
	if err := ValidateConfirmedIdentityRenewal(*response, request, target, time.Now()); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *HTTPClient) identityRenewalJSON(ctx context.Context, path string, body []byte, limit int64) ([]byte, error) {
	if path == "" {
		return nil, ErrInvalidResponse
	}
	// The transport may finish closing the immutable public-proof buffer after
	// this call returns; do not clear or reuse it while that reader can still run.
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrEnrollmentTransport
	}
	r.Header.Set("Content-Type", "application/json")
	data, status, err := c.doJSONStatuses(r, limit, http.StatusConflict)
	if errors.Is(err, ErrEnrollmentUnavailable) || status == http.StatusForbidden {
		return nil, ErrIdentityRenewalDenied
	}
	if err != nil {
		return nil, err
	}
	if status == http.StatusConflict {
		defer clear(data)
		var failure RenewalConflict
		if len(data) > 1024 || strictjson.Unmarshal(data, &failure) != nil {
			return nil, ErrInvalidResponse
		}
		return nil, failure.ErrorValue()
	}
	return data, nil
}
