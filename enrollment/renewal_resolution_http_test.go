package enrollment

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPSIdentityRenewalResolutionRequiresExplicitBoundOutcome(t *testing.T) {
	f := newRenewalHTTPFixture(t, nil)
	for range 2 {
		result, err := f.client.ResolveIdentityRenewal(t.Context(), *f.resolution, f.target, f.source)
		if err != nil || *result != f.resolved {
			t.Fatal("resolution changed durable outcome", err)
		}
	}
	for _, mutation := range []string{"origin", "source certificate", "source scope", "candidate", "proof"} {
		source, target, request := f.source, f.target, *f.resolution
		switch mutation {
		case "origin":
			source.Origin = "https://other.example.test"
		case "source certificate":
			source.Certificate = f.target.Candidate.Certificate
		case "source scope":
			source.SiteID++
		case "candidate":
			target.Candidate.DeviceID = "11111111-1111-4111-8111-111111111111"
		case "proof":
			request.CertificateProof = f.confirmation.CertificateProof
		}
		if _, err := f.client.ResolveIdentityRenewal(t.Context(), request, target, source); !errors.Is(err, ErrRenewalResolution) {
			t.Fatal("invalid resolution reached HTTPS", mutation, err)
		}
	}
	if f.requests.Load() != 2 {
		t.Fatal("resolution transport retried or sent invalid proof")
	}
}

func TestHTTPSIdentityRenewalResolutionRejectsAmbiguousOrUnboundReplies(t *testing.T) {
	for _, mode := range []string{"redirect", "denied", "busy", "conflict", "HTML", "compression", "oversized", "duplicate", "unknown field", "null", "different target", "different source", "unknown outcome", "future", "before issuance", "wrong TLS"} {
		t.Run(mode, func(t *testing.T) {
			f := newRenewalHTTPFixture(t, func(f *renewalHTTPFixture, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "redirect":
					w.Header().Set("Location", f.server.URL+"/must-not-receive-proof")
					w.WriteHeader(307)
					return
				case "denied":
					http.Error(w, "sensitive diagnostic", 404)
					return
				case "busy":
					http.Error(w, "sensitive diagnostic", 503)
					return
				case "conflict":
					w.WriteHeader(409)
					json.NewEncoder(w).Encode(RenewalConflict{Version: 1, Code: "recovery_pending"})
					return
				case "HTML":
					w.Header().Set("Content-Type", "text/html")
				case "compression":
					w.Header().Set("Content-Encoding", "gzip")
				case "oversized":
					w.Write(bytes.Repeat([]byte("x"), MaxResolvedIdentityRenewalBytes+1))
					return
				}
				result := f.resolved
				switch mode {
				case "different target":
					result.CertificateHash = strings.Repeat("a", 64)
				case "different source":
					result.SourceCertificateHash = strings.Repeat("a", 64)
				case "unknown outcome":
					result.Outcome = "not_found"
				case "future":
					result.ResolvedAt = time.Now().Add(2 * time.Minute)
				case "before issuance":
					result.ResolvedAt = time.Unix(1, 0)
				}
				wire, _ := json.Marshal(result)
				switch mode {
				case "duplicate":
					wire = append(wire[:len(wire)-1], []byte(`,"outcome":"confirmed"}`)...)
				case "unknown field":
					wire = append(wire[:len(wire)-1], []byte(`,"fallback":true}`)...)
				case "null":
					wire = bytes.Replace(wire, []byte(`"outcome":"cancelled"`), []byte(`"outcome":null`), 1)
				}
				w.Write(wire)
			})
			if mode == "wrong TLS" {
				f.client.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			result, err := f.client.ResolveIdentityRenewal(t.Context(), *f.resolution, f.target, f.source)
			if result != nil || err == nil || strings.Contains(err.Error(), "sensitive diagnostic") {
				t.Fatal("unsafe resolution granted fallback", err)
			}
			if f.requests.Load() > 1 {
				t.Fatal("ambiguous resolution was automatically retried")
			}
		})
	}
}

func TestHTTPSIdentityRenewalResolutionCancellationDoesNotGrantFallback(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	f := newRenewalHTTPFixture(t, func(f *renewalHTTPFixture, w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := f.client.ResolveIdentityRenewal(ctx, *f.resolution, f.target, f.source)
		if result != nil {
			t.Error("cancelled transport granted fallback")
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("resolution did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolution did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("resolution connection remained open")
	}
	if f.requests.Load() != 1 {
		t.Fatal("cancelled transport retried")
	}
}
