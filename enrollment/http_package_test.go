package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
)

func packageTestRelease(t *testing.T, content []byte, lifetime time.Duration) *artifacts.Verified {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	digest := sha256.Sum256(content)
	now := time.Now().UTC()
	manifest := artifacts.Manifest{Schema: 1, Sequence: 42, Version: "0.12.0", PublishedAt: now.Add(-time.Hour), ExpiresAt: now.Add(lifetime), Artifacts: []artifacts.Artifact{{Platform: "windows", Architecture: "amd64", Format: "exe", Filename: "openuem-agent-0.12.0-windows-amd64.exe", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}}}
	data, err := artifacts.Sign(manifest, key, now)
	if err != nil {
		t.Fatal(err)
	}
	release, err := artifacts.Verify(data, []ed25519.PublicKey{public}, now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func TestNativePackageDownloadUsesVerifiedTargetAndBoundedSameOriginStream(t *testing.T) {
	content := bytes.Repeat([]byte("non-executable package fixture"), 4096)
	release := packageTestRelease(t, content, time.Hour)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 2 || r.Method != "GET" || r.URL.Path != "/enroll/desktop/releases/"+release.Digest()+"/windows/amd64" || r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/octet-stream" || r.Header.Get("Range") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" {
			t.Error("download left its transport/credential boundary")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(content)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := bootstrapTestClient(t, server)
	var destination bytes.Buffer
	if err := client.DownloadPackage(context.Background(), release, "windows", "amd64", &destination); err != nil || !bytes.Equal(destination.Bytes(), content) {
		t.Fatal("verified bytes did not arrive", err)
	}
	if client.Origin() != server.URL || client.client.Timeout != 30*time.Second {
		t.Fatal("stream changed the shared claim transport")
	}
	for _, target := range [][2]string{{"windows", "arm64"}, {"macos", "amd64"}, {"windows/other", "amd64"}} {
		if err := client.DownloadPackage(context.Background(), release, target[0], target[1], io.Discard); !errors.Is(err, artifacts.ErrTarget) {
			t.Fatal("unsupported target accepted", err)
		}
	}
	if err := client.DownloadPackage(context.Background(), nil, "windows", "amd64", io.Discard); err == nil {
		t.Fatal("nil release accepted")
	}
	if err := client.DownloadPackage(context.Background(), &artifacts.Verified{}, "windows", "amd64", io.Discard); err == nil {
		t.Fatal("unverified release accepted")
	}
	if err := client.DownloadPackage(context.Background(), release, "windows", "amd64", nil); err == nil {
		t.Fatal("nil destination accepted")
	}
	if requests.Load() != 1 {
		t.Fatal("invalid target reached server or downloaded implicitly again")
	}
}

func TestNativePackageDownloadRejectsRedirectsUnsafeHeadersAndChangedBytes(t *testing.T) {
	content := []byte("non-executable approved fixture package")
	release := packageTestRelease(t, content, time.Hour)
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	for _, tc := range []struct {
		name    string
		status  int
		headers map[string][]string
		body    []byte
		chunked bool
		want    error
	}{
		{"redirect", 307, map[string][]string{"Location": {target.URL}}, nil, false, ErrEnrollmentRejected},
		{"withdrawn", 404, nil, nil, false, ErrEnrollmentUnavailable},
		{"busy", 429, nil, nil, false, ErrEnrollmentBusy},
		{"unexpected partial", 206, nil, content, false, ErrEnrollmentRejected},
		{"wrong content type", 200, map[string][]string{"Content-Type": {"text/html"}}, content, false, artifacts.ErrPackage},
		{"duplicate content type", 200, map[string][]string{"Content-Type": {"application/octet-stream", "application/octet-stream"}}, content, false, artifacts.ErrPackage},
		{"content encoding", 200, map[string][]string{"Content-Encoding": {"gzip"}}, content, false, artifacts.ErrPackage},
		{"short", 200, nil, content[:len(content)-1], false, artifacts.ErrPackage},
		{"changed", 200, nil, bytes.Repeat([]byte("x"), len(content)), false, artifacts.ErrPackage},
		{"extra chunk", 200, nil, append(bytes.Clone(content), bytes.Repeat([]byte("x"), 100000)...), true, artifacts.ErrPackage},
		{"truncated chunk", 200, nil, content[:len(content)-1], true, artifacts.ErrPackage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				for key, values := range tc.headers {
					w.Header()[key] = values
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				if tc.status != 200 {
					io.WriteString(w, "private remote diagnostic")
					return
				}
				w.Write(tc.body)
			}))
			defer server.Close()
			client := bootstrapTestClient(t, server)
			var destination bytes.Buffer
			err := client.DownloadPackage(context.Background(), release, "windows", "amd64", &destination)
			if !errors.Is(err, tc.want) || destination.Len() > len(content)+1 {
				t.Fatal("unsafe package returned or exceeded byte bound", err)
			}
			if strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "private remote diagnostic") {
				t.Fatal("download error leaked remote details")
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("installer request followed redirect")
	}
}

func TestNativePackageDownloadCancelsActiveStreamAndRejectsExpiredRelease(t *testing.T) {
	content := []byte("fixture package")
	for _, cancelStream := range []bool{true, false} {
		lifetime := time.Hour
		if !cancelStream {
			lifetime = 3 * time.Second
		}
		release := packageTestRelease(t, content, lifetime)
		entered, stopped := make(chan struct{}), make(chan struct{})
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(stopped)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(content[:1])
			w.(http.Flusher).Flush()
			close(entered)
			if cancelStream {
				<-r.Context().Done()
				return
			}
			timer := time.NewTimer(time.Until(release.Manifest().ExpiresAt.Add(10 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
				w.Write(content[1:])
			case <-r.Context().Done():
			}
		}))
		defer server.Close()
		client := bootstrapTestClient(t, server)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- client.DownloadPackage(ctx, release, "windows", "amd64", io.Discard) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("stream did not start")
		}
		want := artifacts.ErrExpired
		if cancelStream {
			cancel()
			want = context.Canceled
		}
		select {
		case err := <-done:
			if !errors.Is(err, want) {
				t.Fatal("stream lifetime was ignored", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stream did not finish")
		}
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("stream connection was not closed")
		}
	}
}
