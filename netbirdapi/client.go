package netbirdapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrUnavailable = errors.New("NetBird request could not be confirmed")

const MaxResponse = 1 << 20

// Reserve room for fixed setup-key fields around the 32 KiB legacy group list.
const MaxRequest = 64 << 10

var defaultTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
	IdleConnTimeout:       30 * time.Second,
	MaxIdleConns:          16, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4,
	ForceAttemptHTTP2: true,
}

// ValidBase accepts an explicit HTTPS origin and optional unescaped path prefix.
// Credentials, query strings, fragments and path traversal are not configuration.
func ValidBase(base string) bool {
	if base == "" || len(base) > 2048 || !utf8.ValidString(base) || strings.ContainsAny(base, "\x00\r\n\\") {
		return false
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(base, "#") || u.RawPath != "" {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validToken(token string) bool {
	return token != "" && len(token) <= 16384 && utf8.ValidString(token) && !strings.ContainsAny(token, "\x00\r\n")
}

func identifier(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// request never follows redirects, forwards provider errors, or retries a
// changing request. A POST failure can be an unconfirmed remote side effect.
func request(ctx context.Context, transport http.RoundTripper, base, token, method, path string, query url.Values, payload any) ([]byte, error) {
	data, _, err := requestObserved(ctx, transport, base, token, method, path, query, payload, false)
	return data, err
}

func requestObserved(ctx context.Context, transport http.RoundTripper, base, token, method, path string, query url.Values, payload any, allowMissing bool) ([]byte, bool, error) {
	if !ValidBase(base) || !validToken(token) {
		return nil, false, ErrUnavailable
	}
	u, _ := url.Parse(base)
	u.Path = strings.TrimRight(u.Path, "/") + "/api/" + path
	u.RawQuery = query.Encode()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil || len(data) > MaxRequest {
			return nil, false, ErrUnavailable
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, false, ErrUnavailable
	}
	// Disable replay of changing bodies by the transport after a broken reused
	// connection. No idempotency header is supplied for provider mutations.
	if method != http.MethodGet {
		req.GetBody = nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if transport == nil {
		transport = defaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, false, ErrUnavailable
	}
	defer response.Body.Close()
	valid := response.StatusCode == http.StatusOK
	if method == http.MethodPost {
		valid = valid || response.StatusCode == http.StatusCreated
	}
	if method == http.MethodDelete {
		valid = valid || response.StatusCode == http.StatusNoContent
	}
	missing := allowMissing && method == http.MethodGet && response.StatusCode == http.StatusNotFound
	valid = valid || missing
	if !valid {
		return nil, false, ErrUnavailable
	}
	if response.ContentLength > MaxResponse {
		return nil, false, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponse+1))
	if err != nil || len(data) > MaxResponse || !utf8.Valid(data) {
		return nil, false, ErrUnavailable
	}
	return data, missing, nil
}

type peer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	IPv6 string `json:"ipv6"`
}

func peers(ctx context.Context, transport http.RoundTripper, base, token string, filter url.Values) ([]peer, error) {
	body, err := request(ctx, transport, base, token, http.MethodGet, "peers", filter, nil)
	if err != nil {
		return nil, err
	}
	body = bytes.TrimSpace(body)
	var result []peer
	if len(body) == 0 || body[0] != '[' || json.Unmarshal(body, &result) != nil || len(result) > 1000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, p := range result {
		if !identifier(p.ID) || seen[p.ID] || len(p.Name) > 1024 || !utf8.ValidString(p.Name) || strings.ContainsAny(p.Name, "\x00\r\n") {
			return nil, ErrUnavailable
		}
		seen[p.ID] = true
	}
	return result, nil
}

func PeerExists(ctx context.Context, transport http.RoundTripper, base, token, name string) (bool, error) {
	if name == "" || len(name) > 253 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return false, ErrUnavailable
	}
	list, err := peers(ctx, transport, base, token, url.Values{"name": {name}})
	if err != nil {
		return false, err
	}
	if len(list) == 0 {
		return false, nil
	}
	if len(list) != 1 || !strings.EqualFold(list[0].Name, name) {
		return false, ErrUnavailable
	}
	return true, nil
}

// PeerIDByIP binds deletion to exactly one matching provider observation.
func PeerIDByIP(ctx context.Context, transport http.RoundTripper, base, token, address string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return "", ErrUnavailable
	}
	list, err := peers(ctx, transport, base, token, url.Values{"ip": {ip.String()}})
	if err != nil {
		return "", err
	}
	if len(list) != 1 || !(ip.Equal(net.ParseIP(list[0].IP)) || ip.Equal(net.ParseIP(list[0].IPv6))) {
		return "", ErrUnavailable
	}
	return list[0].ID, nil
}

type SetupKey struct{ ID, Key string }
type setupRequest struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	ExpiresIn  int      `json:"expires_in"`
	Groups     []string `json:"auto_groups"`
	UsageLimit int      `json:"usage_limit"`
	Ephemeral  bool     `json:"ephemeral"`
	ExtraDNS   bool     `json:"allow_extra_dns_labels"`
}

// ParseGroups decodes the historical comma-separated JSON-string task column.
func ParseGroups(raw string) ([]string, error) {
	if len(raw) > 32768 {
		return nil, ErrUnavailable
	}
	groups := []string{}
	if json.Unmarshal([]byte("["+raw+"]"), &groups) != nil || len(groups) > 1000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, id := range groups {
		if !identifier(id) || seen[id] {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	return groups, nil
}

func CreateOneOffKey(ctx context.Context, transport http.RoundTripper, base, token, agentID string, groups []string, extraDNS bool) (*SetupKey, error) {
	if !identifier(agentID) || len(groups) > 1000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, id := range groups {
		if !identifier(id) || seen[id] {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	copyGroups := append([]string{}, groups...)
	body, err := request(ctx, transport, base, token, http.MethodPost, "setup-keys", nil, setupRequest{"OpenUEM " + agentID + " key", "one-off", 86400, copyGroups, 1, false, extraDNS})
	if err != nil {
		return nil, err
	}
	var result struct {
		ID         json.RawMessage `json:"id"`
		Key        string          `json:"key"`
		Valid      bool            `json:"valid"`
		Revoked    bool            `json:"revoked"`
		Type       string          `json:"type"`
		UsageLimit int             `json:"usage_limit"`
	}
	if json.Unmarshal(body, &result) != nil || !result.Valid || result.Revoked || result.Type != "one-off" || result.UsageLimit != 1 || result.Key == "" || len(result.Key) > 512 || strings.ContainsAny(result.Key, "\x00\r\n\t *") {
		return nil, ErrUnavailable
	}
	var id string
	if json.Unmarshal(result.ID, &id) != nil {
		// Older API examples use numeric IDs; retain the exact integer spelling.
		id = string(result.ID)
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
			return nil, ErrUnavailable
		}
	}
	if !identifier(id) {
		return nil, ErrUnavailable
	}
	return &SetupKey{ID: id, Key: result.Key}, nil
}

func DeleteKey(ctx context.Context, transport http.RoundTripper, base, token, id string) error {
	if !identifier(id) {
		return ErrUnavailable
	}
	_, err := request(ctx, transport, base, token, http.MethodDelete, "setup-keys/"+id, nil, nil)
	return err
}
func DeletePeer(ctx context.Context, transport http.RoundTripper, base, token, id string) error {
	if !identifier(id) {
		return ErrUnavailable
	}
	_, err := request(ctx, transport, base, token, http.MethodDelete, "peers/"+id, nil, nil)
	return err
}
