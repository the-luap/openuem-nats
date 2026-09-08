package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/artifacts"
)

func currentDownloadFixture(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t)
	release, err := artifacts.Verify(f.config.ReleaseEnvelope, f.trust.ReleaseKeys, f.now, f.trust.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.now = time.Now().UTC()
	manifest := release.Manifest()
	manifest.PublishedAt = f.now.Add(-time.Hour)
	manifest.ExpiresAt = f.now.Add(24 * time.Hour)
	f.config.ReleaseEnvelope, err = artifacts.Sign(manifest, f.releaseKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	release, err = artifacts.Verify(f.config.ReleaseEnvelope, f.trust.ReleaseKeys, f.now, artifacts.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	f.config.ReleaseDigest = release.Digest()
	f.trust.Checkpoint = release.Checkpoint()
	f.config.IssuedAt = f.now
	f.config.ExpiresAt = f.now.Add(time.Hour)
	return f
}

func TestSignedConfigurationDownloadsOnlyFromItsAuthorizedOrigin(t *testing.T) {
	f := currentDownloadFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/enroll/desktop/releases/"+f.config.ReleaseDigest+"/windows/amd64" {
			t.Error("configuration selected wrong release or target")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(f.content)
	}))
	defer server.Close()
	f.config.Origin = server.URL
	f.trust.Origin = server.URL
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, f.trust, f.now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := enrollment.NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var destination bytes.Buffer
	if err := verified.DownloadPackage(context.Background(), client, &destination); err != nil || !bytes.Equal(destination.Bytes(), f.content) {
		t.Fatal("configuration package download failed", err)
	}
	foreign, err := enrollment.NewHTTPClient("https://other.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.CloseIdleConnections()
	if err := verified.DownloadPackage(context.Background(), foreign, io.Discard); !errors.Is(err, ErrTarget) {
		t.Fatal("configuration accepted another origin", err)
	}
	for _, invalid := range []*Verified{nil, {}} {
		if err := invalid.DownloadPackage(context.Background(), client, io.Discard); !errors.Is(err, ErrInvalid) {
			t.Fatal("unverified configuration accepted", err)
		}
	}
	if err := verified.DownloadPackage(context.Background(), nil, io.Discard); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil client accepted", err)
	}
	if requests.Load() != 1 {
		t.Fatal("invalid configuration triggered another download")
	}
}

func TestSignedConfigurationCannotExpireDuringPackageDownload(t *testing.T) {
	f := currentDownloadFixture(t)
	f.config.ExpiresAt = time.Now().UTC().Add(3 * time.Second)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(f.content[:1])
		w.(http.Flusher).Flush()
		timer := time.NewTimer(time.Until(f.config.ExpiresAt.Add(10 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
			w.Write(f.content[1:])
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	f.config.Origin = server.URL
	f.trust.Origin = server.URL
	data, err := Sign(f.config, f.bootstrapKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(data, f.trust, f.now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := enrollment.NewHTTPClient(server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := verified.DownloadPackage(ctx, client, io.Discard); !errors.Is(err, ErrExpired) {
		t.Fatal("expired configuration approved downloaded package", err)
	}
	// The independently signed release still passes; configuration lifetime is
	// the boundary that must prevent using these otherwise valid package bytes.
	if _, err := artifacts.Verify(f.config.ReleaseEnvelope, []ed25519.PublicKey{f.trust.ReleaseKeys[0]}, time.Now(), f.trust.Checkpoint); err != nil {
		t.Fatal("fixture release expired unexpectedly", err)
	}
}
