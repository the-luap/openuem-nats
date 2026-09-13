package netbirdapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOwnedNetbirdTLSProtocol(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Token owned-token" || r.Header.Get("Accept") != "application/json" {
			t.Error("request lost its explicit authorization or media type")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /prefix/api/groups":
			_, _ = io.WriteString(w, `[{"id":"owned-group","name":"Owned group","peers_count":1}]`)
		case "GET /prefix/api/peers":
			if r.URL.Query().Get("name") == "owned & ? name" {
				if len(r.URL.Query()) != 1 {
					t.Error("peer name injected a query parameter")
				}
				_, _ = io.WriteString(w, `[{"id":"owned-peer","name":"owned & ? name","ip":"100.64.0.1"}]`)
			} else if r.URL.Query().Get("ip") == "100.64.0.1" {
				_, _ = io.WriteString(w, `[{"id":"owned-peer","name":"owned","ip":"100.64.0.1"}]`)
			} else {
				t.Error("unexpected peer filter")
				http.Error(w, "invalid", 400)
			}
		case "POST /prefix/api/setup-keys":
			var body setupRequest
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name != "OpenUEM owned-agent key" || body.Type != "one-off" || body.UsageLimit != 1 || body.ExpiresIn != 86400 || body.Ephemeral || !body.ExtraDNS || len(body.Groups) != 1 || body.Groups[0] != "owned-group" {
				t.Error("setup-key request lost its fixed policy")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":123456,"key":"owned-new-key","valid":true,"type":"one-off","usage_limit":1}`)
		case "DELETE /prefix/api/setup-keys/123456", "DELETE /prefix/api/peers/owned-peer":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected provider method or path")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.GetBody != nil {
			t.Error("changing request permits body replay")
		}
		return server.Client().Transport.RoundTrip(r)
	})
	base := server.URL + "/prefix/"
	groups, err := Groups(t.Context(), transport, base, "owned-token")
	if err != nil || len(groups) != 1 || groups[0].ID != "owned-group" {
		t.Fatal("group lookup failed")
	}
	exists, err := PeerExists(t.Context(), transport, base, "owned-token", "owned & ? name")
	if err != nil || !exists {
		t.Fatal("encoded peer lookup failed")
	}
	key, err := CreateOneOffKey(t.Context(), transport, base, "owned-token", "owned-agent", []string{"owned-group"}, true)
	if err != nil || key.ID != "123456" || key.Key != "owned-new-key" {
		t.Fatal("numeric setup-key identity was lost")
	}
	if err = DeleteKey(t.Context(), transport, base, "owned-token", key.ID); err != nil {
		t.Fatal("key deletion failed")
	}
	id, err := PeerIDByIP(t.Context(), transport, base, "owned-token", "100.64.0.1")
	if err != nil || id != "owned-peer" {
		t.Fatal("peer identity binding failed")
	}
	if err = DeletePeer(t.Context(), transport, base, "owned-token", id); err != nil {
		t.Fatal("peer deletion failed")
	}
	if calls.Load() != 6 {
		t.Fatal("unexpected request count")
	}
}

func TestNetbirdRejectsRedirectErrorsAndOversizedResponses(t *testing.T) {
	var redirects atomic.Int64
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1) }))
	defer redirect.Close()
	for _, status := range []int{http.StatusFound, http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", redirect.URL)
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = io.WriteString(w, strings.Repeat("x", MaxResponse+1))
				} else {
					_, _ = io.WriteString(w, "private-provider-detail")
				}
			}))
			defer server.Close()
			for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
				_, err := request(t.Context(), server.Client().Transport, server.URL, "owned", method, "groups", nil, nil)
				if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private-provider-detail") {
					t.Fatal("provider response escaped neutral failure")
				}
			}
		})
	}
	if redirects.Load() != 0 {
		t.Fatal("provider redirect received a request")
	}
}

func TestNetbirdBindsPeerDeletionToExactlyOneMatchingIP(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `{}`, `[{"id":"first","ip":"100.64.0.1"},{"id":"second","ip":"100.64.0.1"}]`, `[{"id":"wrong","ip":"100.64.0.2"}]`, `[{"id":"../injected","ip":"100.64.0.1"}]`, `[{"id":"owned","ip":"100.64.0.1"}] []`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		id, err := PeerIDByIP(t.Context(), server.Client().Transport, server.URL, "owned", "100.64.0.1")
		server.Close()
		if id != "" || !errors.Is(err, ErrUnavailable) {
			t.Fatal("ambiguous or mismatched peer acquired a deletion identity")
		}
	}
}

func TestNetbirdRejectsInvalidConfigurationBeforeTransport(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid request reached transport")
		return nil, ErrUnavailable
	})
	for _, base := range []string{"", "http://provider.invalid", "https://user:password@provider.invalid", "https://provider.invalid?", "https://provider.invalid#", "https://provider.invalid/a/../b", "https://provider.invalid/%2e%2e", "https://provider.invalid:65536", strings.Repeat("x", 2049)} {
		if ValidBase(base) {
			t.Error("invalid base was accepted")
		}
		if _, err := Groups(t.Context(), transport, base, "owned"); !errors.Is(err, ErrUnavailable) {
			t.Error("invalid base produced a provider result")
		}
	}
	for _, token := range []string{"", "bad\r\nheader", strings.Repeat("x", 16385), string([]byte{0xff})} {
		if _, err := Groups(t.Context(), transport, "https://provider.invalid", token); !errors.Is(err, ErrUnavailable) {
			t.Error("invalid token was accepted")
		}
	}
	for _, id := range []string{"", "../peer", "query?value", strings.Repeat("x", 129)} {
		if err := DeletePeer(t.Context(), transport, "https://provider.invalid", "owned", id); !errors.Is(err, ErrUnavailable) {
			t.Error("invalid deletion identity was accepted")
		}
	}
	for _, raw := range []string{`"one","one"`, `"../group"`, `{"injected":true}`, strings.Repeat("x", 32769)} {
		if _, err := ParseGroups(raw); !errors.Is(err, ErrUnavailable) {
			t.Error("invalid group encoding was accepted")
		}
	}
	if groups, err := ParseGroups(`"one", "two"`); err != nil || len(groups) != 2 {
		t.Fatal("legacy group list was lost")
	}
}

func TestNetbirdCancellationAndUnconfirmedCreateAreNotRetried(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := CreateOneOffKey(ctx, server.Client().Transport, server.URL, "owned", "owned-agent", nil, false)
	if !errors.Is(err, ErrUnavailable) || time.Since(start) > time.Second || calls.Load() != 1 {
		t.Fatal("unconfirmed setup-key creation was retried or exceeded cancellation")
	}
}

func TestNetbirdRejectsUnsafeSetupKeyResults(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"id":1.5,"key":"owned","valid":true,"type":"one-off","usage_limit":1}`, `{"id":"owned","key":"masked****","valid":true,"type":"one-off","usage_limit":1}`, `{"id":"owned","key":"owned","valid":true,"revoked":true,"type":"one-off","usage_limit":1}`, `{"id":"owned","key":"owned","valid":true,"type":"reusable","usage_limit":0}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		result, err := CreateOneOffKey(t.Context(), server.Client().Transport, server.URL, "owned", "owned-agent", nil, false)
		server.Close()
		if result != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("unsafe setup-key result was accepted")
		}
	}
}

func TestNetbirdFullLegacyGroupListFitsStructuredRequest(t *testing.T) {
	groups := make([]string, 250)
	for i := range groups {
		groups[i] = fmt.Sprintf("%0128d", i)
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGroups(string(encoded[1 : len(encoded)-1]))
	if err != nil {
		t.Fatal("valid legacy group list was rejected")
	}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequest+1))
		if err != nil || len(body) > MaxRequest {
			t.Error("setup-key request exceeded its bound")
		}
		var payload setupRequest
		if json.Unmarshal(body, &payload) != nil || len(payload.Groups) != len(groups) {
			t.Error("structured request lost legacy groups")
		}
		_, _ = io.WriteString(w, `{"id":"owned-key","key":"owned-new-key","valid":true,"type":"one-off","usage_limit":1}`)
	}))
	defer server.Close()
	result, err := CreateOneOffKey(t.Context(), server.Client().Transport, server.URL, "owned", "owned-agent", parsed, false)
	if err != nil || result == nil || calls.Load() != 1 {
		t.Fatal("fixed request fields made a valid legacy group list unusable")
	}
}
