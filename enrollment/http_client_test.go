package enrollment

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSClaimValidatesProofAndResponseWithoutForwardingCredentials(t *testing.T) {
	f := newResponseFixture(t)
	request, err := f.keys.Request(testToken(t), "windows", "amd64", "Fixture endpoint")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 2 || r.Method != "POST" || r.URL.Path != "/enroll/desktop/"+request.Invitation+"/claim" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" {
			t.Error("native request changed its transport or credential boundary")
		}
		var received Request
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		if _, err := Validate(received); err != nil || received != *request {
			t.Error("transport changed the endpoint proof", err)
		}
		result := f.response
		result.Endpoint = "wss://" + r.Host + "/agent-channel"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var first *Response
	for i := 0; i < 2; i++ {
		issued, err := client.Claim(context.Background(), *request)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = issued
		} else if *first != *issued {
			t.Fatal("same-key retry changed the response")
		}
	}
	forged := *request
	forged.DeviceName = "Modified after proof"
	if _, err = client.Claim(context.Background(), forged); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("forged proof was not rejected locally", err)
	}
	if requests.Load() != 2 {
		t.Fatal("invalid proof reached the server or requests retried implicitly")
	}
}

func TestHTTPSClaimRejectsRedirectsUntrustedTLSAndUnsafeResponses(t *testing.T) {
	f := newResponseFixture(t)
	request, err := f.keys.Request(testToken(t), "macos", "arm64", "Fixture Mac")
	if err != nil {
		t.Fatal(err)
	}
	var redirected atomic.Int32
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		http.Error(w, "must not receive credentials", 500)
	}))
	defer redirect.Close()
	for _, tc := range []struct {
		name   string
		status int
		header map[string]string
		modify func(Response) []byte
		want   error
	}{
		{"redirect", 307, map[string]string{"Location": redirect.URL}, nil, ErrEnrollmentRejected},
		{"unknown invitation", 404, nil, nil, ErrEnrollmentUnavailable},
		{"rate limit", 429, nil, nil, ErrEnrollmentBusy},
		{"server failure", 503, nil, nil, ErrEnrollmentBusy},
		{"rejected", 400, nil, nil, ErrEnrollmentRejected},
		{"wrong content type", 200, map[string]string{"Content-Type": "text/html"}, nil, ErrInvalidResponse},
		{"compressed response", 200, map[string]string{"Content-Encoding": "gzip"}, nil, ErrInvalidResponse},
		{"large response", 200, nil, func(Response) []byte { return bytes.Repeat([]byte("x"), maxResponseBody+1) }, ErrInvalidResponse},
		{"other endpoint", 200, nil, func(r Response) []byte {
			r.Endpoint = "wss://other.example.test/agent-channel"
			b, _ := json.Marshal(r)
			return b
		}, ErrInvalidResponse},
		{"unbound certificate", 200, nil, func(r Response) []byte { r.Certificate = r.Authority; b, _ := json.Marshal(r); return b }, ErrInvalidResponse},
		{"duplicate identity", 200, nil, func(r Response) []byte {
			b, _ := json.Marshal(r)
			return append(b[:len(b)-1], []byte(`,"device_id":"other"}`)...)
		}, ErrInvalidResponse},
		{"case alias", 200, nil, func(r Response) []byte {
			b, _ := json.Marshal(r)
			return bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1)
		}, ErrInvalidResponse},
		{"trailing JSON", 200, nil, func(r Response) []byte { b, _ := json.Marshal(r); return append(b, []byte(`{}`)...) }, ErrInvalidResponse},
		{"null expiry", 200, nil, func(r Response) []byte {
			b, _ := json.Marshal(r)
			var m map[string]any
			json.Unmarshal(b, &m)
			m["expires_at"] = nil
			b, _ = json.Marshal(m)
			return b
		}, ErrInvalidResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				if tc.status != 200 {
					io.WriteString(w, "sensitive diagnostic "+request.Invitation)
					return
				}
				result := f.response
				result.Endpoint = "wss://" + r.Host + "/agent-channel"
				if tc.modify != nil {
					w.Write(tc.modify(result))
				} else {
					json.NewEncoder(w).Encode(result)
				}
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			roots.AddCert(redirect.Certificate())
			client, err := NewHTTPClient(server.URL, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if _, err = client.Claim(context.Background(), *request); !errors.Is(err, tc.want) {
				t.Fatal("unsafe response accepted", err)
			}
			if strings.Contains(err.Error(), request.Invitation) || strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "sensitive diagnostic") {
				t.Fatal("client error leaked remote diagnostic or token")
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect received the invitation or proof")
	}
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); http.Error(w, "untrusted", 500) }))
	defer server.Close()
	client, err := NewHTTPClient(server.URL, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err = client.Claim(context.Background(), *request); !errors.Is(err, ErrEnrollmentTransport) || received.Load() != 0 {
		t.Fatal("untrusted HTTPS server received enrollment", err)
	}
}

func TestHTTPSClaimCancellationDoesNotWaitForServerResponse(t *testing.T) {
	f := newResponseFixture(t)
	request, err := f.keys.Request(testToken(t), "windows", "amd64", "Cancellable endpoint")
	if err != nil {
		t.Fatal(err)
	}
	entered, stopped := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Claim(ctx, *request); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach cancellation fixture")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("caller cancellation was not preserved", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP connection remained active after cancellation")
	}
}
