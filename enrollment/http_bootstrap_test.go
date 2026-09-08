package enrollment

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func bootstrapTestClient(t *testing.T, server *httptest.Server) *HTTPClient {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestHTTPSBootstrapUsesExactReadOnlyRoutesAndResponseLimits(t *testing.T) {
	token := testToken(t)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 2 || r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength != 0 || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" {
			t.Error("bootstrap request changed its transport/credential boundary")
		}
		limit := 0
		switch r.URL.Path {
		case "/enroll/desktop/bootstrap-keys":
			limit = MaxBootstrapKeysSize
		case "/enroll/desktop/" + token + "/configuration":
			limit = MaxBootstrapConfigurationSize
		default:
			t.Error("unexpected bootstrap path")
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Boundary-sized valid JSON exercises transport framing; the bootstrap
		// package separately rejects documents with the wrong schema/signature.
		io.WriteString(w, `"`+strings.Repeat("x", limit-2)+`"`)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := bootstrapTestClient(t, server)
	for _, tc := range []struct {
		get  func(context.Context) ([]byte, error)
		size int
	}{
		{client.BootstrapKeys, MaxBootstrapKeysSize},
		{func(ctx context.Context) ([]byte, error) { return client.Configuration(ctx, token) }, MaxBootstrapConfigurationSize},
	} {
		data, err := tc.get(context.Background())
		if err != nil || len(data) != tc.size {
			t.Fatal("boundary-sized document was not fetched", err)
		}
		clear(data)
	}
	for _, invalid := range []string{"", token + "/claim", token + "?other=1", token + "#fragment", "../bootstrap-keys", strings.Repeat("A", 42)} {
		if _, err := client.Configuration(context.Background(), invalid); !errors.Is(err, ErrInvalidProof) {
			t.Fatal("invalid invitation accepted", err)
		}
	}
	if requests.Load() != 2 {
		t.Fatal("invalid invitation reached server or a request retried")
	}
}

func TestHTTPSBootstrapRejectsUnsafeResponsesBeforeReturningDocuments(t *testing.T) {
	token := testToken(t)
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.Write([]byte(`{}`)) }))
	defer target.Close()
	for _, kind := range []string{"keys", "configuration"} {
		limit := MaxBootstrapKeysSize
		if kind == "configuration" {
			limit = MaxBootstrapConfigurationSize
		}
		for _, tc := range []struct {
			name    string
			status  int
			headers map[string][]string
			body    []byte
			chunked bool
			want    error
		}{
			{"redirect", 307, map[string][]string{"Location": {target.URL}}, nil, false, ErrEnrollmentRejected},
			{"unknown", 404, nil, nil, false, ErrEnrollmentUnavailable},
			{"expired", 410, nil, nil, false, ErrEnrollmentUnavailable},
			{"busy", 429, nil, nil, false, ErrEnrollmentBusy},
			{"unavailable", 503, nil, nil, false, ErrEnrollmentBusy},
			{"wrong content type", 200, map[string][]string{"Content-Type": {"text/html"}}, []byte(`{}`), false, ErrInvalidResponse},
			{"duplicate content type", 200, map[string][]string{"Content-Type": {"application/json", "application/json"}}, []byte(`{}`), false, ErrInvalidResponse},
			{"content encoding", 200, map[string][]string{"Content-Encoding": {"", "gzip"}}, []byte(`{}`), false, ErrInvalidResponse},
			{"oversized", 200, nil, append([]byte(`"`), append(bytes.Repeat([]byte("x"), limit), byte('"'))...), false, ErrInvalidResponse},
			{"chunked oversized", 200, nil, bytes.Repeat([]byte(" "), limit+1), true, ErrInvalidResponse},
			{"empty", 200, nil, nil, false, ErrInvalidResponse},
			{"malformed", 200, nil, []byte(`{"schema":`), false, ErrInvalidResponse},
			{"trailing", 200, nil, []byte(`{} {}`), false, ErrInvalidResponse},
			{"invalid UTF8", 200, nil, []byte{'"', 0xff, '"'}, false, ErrInvalidResponse},
			{"truncated", 200, map[string][]string{"Content-Length": {"1000"}}, []byte(`{}`), false, ErrEnrollmentTransport},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					for key, values := range tc.headers {
						w.Header()[key] = values
					}
					w.WriteHeader(tc.status)
					if tc.chunked {
						w.(http.Flusher).Flush()
					}
					if tc.status != 200 {
						io.WriteString(w, "private diagnostic "+token)
						return
					}
					w.Write(tc.body)
				}))
				defer server.Close()
				client := bootstrapTestClient(t, server)
				var data []byte
				var err error
				if kind == "keys" {
					data, err = client.BootstrapKeys(context.Background())
				} else {
					data, err = client.Configuration(context.Background(), token)
				}
				if !errors.Is(err, tc.want) || data != nil {
					t.Fatal("unsafe document returned", err)
				}
				if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "private diagnostic") {
					t.Fatal("response failure leaked credentials or diagnostics")
				}
			})
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("bootstrap followed a redirect")
	}
}

func TestHTTPSBootstrapRejectsUntrustedTLSAndCancelsActiveRequests(t *testing.T) {
	token := testToken(t)
	for _, configuration := range []bool{false, true} {
		get := func(ctx context.Context, client *HTTPClient) ([]byte, error) {
			if configuration {
				return client.Configuration(ctx, token)
			}
			return client.BootstrapKeys(ctx)
		}
		var requests atomic.Int32
		entered, stopped := make(chan struct{}), make(chan struct{})
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			close(entered)
			<-r.Context().Done()
			close(stopped)
		}))
		defer server.Close()
		untrusted, err := NewHTTPClient(server.URL, x509.NewCertPool())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := get(context.Background(), untrusted); !errors.Is(err, ErrEnrollmentTransport) || requests.Load() != 0 {
			t.Fatal("untrusted origin received bootstrap request", err)
		}
		untrusted.CloseIdleConnections()
		client := bootstrapTestClient(t, server)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := get(ctx, client); done <- err }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("request did not arrive")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation changed", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("request did not cancel")
		}
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("canceled connection remained active")
		}
	}
}
