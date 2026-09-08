package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrEnrollmentTransport   = errors.New("the enrollment service could not be reached securely")
	ErrEnrollmentUnavailable = errors.New("the installation invitation is unavailable")
	ErrEnrollmentBusy        = errors.New("the enrollment service is temporarily unavailable; retry later")
	ErrEnrollmentRejected    = errors.New("the enrollment service rejected the request")
)

const maxResponseBody = 96 << 10

// HTTPClient claims identities only at an independently authorized origin. It
// owns its transport, has no cookies, redirects or environment proxy, and never
// exposes request URLs, invitation tokens or server error bodies in errors.
type HTTPClient struct {
	origin    string
	client    *http.Client
	transport *http.Transport
}

// NewHTTPClient uses system HTTPS roots when roots is nil, otherwise a snapshot
// of the explicitly supplied server roots. Returned identity authorities never
// replace these roots. The caller must separately authorize expectedOrigin and
// durably protect its pending endpoint keys before calling Claim.
func NewHTTPClient(expectedOrigin string, roots *x509.CertPool) (*HTTPClient, error) {
	if !ValidOrigin(expectedOrigin) {
		return nil, ErrInvalidResponse
	}
	if roots != nil {
		roots = roots.Clone()
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 25 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: 2, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		IdleConnTimeout: 30 * time.Second, DisableCompression: true, ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &HTTPClient{origin: expectedOrigin, client: client, transport: transport}, nil
}

// CloseIdleConnections releases reusable connections; callers cancel their own
// active request contexts. No endpoint private keys are held by this client.
func (c *HTTPClient) CloseIdleConnections() { c.transport.CloseIdleConnections() }

// Claim does not automatically retry or persist keys. Repeat it with the same
// durably stored keys after an interrupted response. Both request proofs are
// validated before transport, and the response is bound to that CSR's public key.
func (c *HTTPClient) Claim(ctx context.Context, request Request) (*Response, error) {
	identity, err := Validate(request)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > 16<<10 {
		return nil, ErrInvalidProof
	}
	// This immutable buffer contains public proofs and the invitation, no private
	// keys. The HTTP transport can finish closing its request body asynchronously;
	// do not clear/reuse the buffer while it may still be reading it.
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/enroll/desktop/"+request.Invitation+"/claim", bytes.NewReader(body))
	if err != nil {
		return nil, ErrEnrollmentTransport
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, err := c.client.Do(r)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrEnrollmentTransport
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusNotFound, http.StatusGone:
			return nil, ErrEnrollmentUnavailable
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
			return nil, ErrEnrollmentBusy
		default:
			return nil, ErrEnrollmentRejected
		}
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(response.Header.Values("Content-Type")) != 1 || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || response.Header.Get("Content-Encoding") != "" || response.ContentLength > maxResponseBody {
		return nil, ErrInvalidResponse
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrEnrollmentTransport
	}
	issued, err := decodeResponse(data)
	if err != nil {
		return nil, err
	}
	if _, err = ValidateResponse(issued, c.origin, identity.CertificateKey, time.Now()); err != nil {
		return nil, err
	}
	return &issued, nil
}

func decodeResponse(data []byte) (Response, error) {
	var result Response
	if len(data) > maxResponseBody || !utf8.Valid(data) {
		return result, ErrInvalidResponse
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return result, ErrInvalidResponse
	}
	fields := map[string]any{"version": &result.Version, "device_id": &result.DeviceID, "tenant_id": &result.TenantID, "site_id": &result.SiteID, "endpoint": &result.Endpoint, "certificate": &result.Certificate, "authority": &result.Authority, "expires_at": &result.ExpiresAt}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return result, ErrInvalidResponse
		}
		name, ok := key.(string)
		target := fields[name]
		if !ok || target == nil {
			return result, ErrInvalidResponse
		}
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return result, ErrInvalidResponse
		}
		if err = json.Unmarshal(raw, target); err != nil {
			return result, ErrInvalidResponse
		}
		delete(fields, name)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(fields) != 0 {
		return result, ErrInvalidResponse
	}
	if _, err = d.Token(); err != io.EOF {
		return result, ErrInvalidResponse
	}
	return result, nil
}
