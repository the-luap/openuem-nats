package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type renewalHTTPFixture struct {
	source       RenewalSource
	request      *RenewalRequest
	prepared     PreparedIdentityRenewal
	target       RenewalConfirmationTarget
	confirmation *RenewalConfirmation
	confirmed    ConfirmedIdentityRenewal
	server       *httptest.Server
	client       *HTTPClient
	requests     atomic.Int32
}

func newRenewalHTTPFixture(t *testing.T, respond func(*renewalHTTPFixture, http.ResponseWriter, *http.Request)) *renewalHTTPFixture {
	t.Helper()
	f := &renewalHTTPFixture{}
	identity := newResponseFixture(t)
	oldBlock, _ := pem.Decode([]byte(identity.response.Certificate))
	now := time.Now().UTC().Truncate(time.Second)
	// The same synthetic issuer extends a same-key certificate. Registry tests
	// separately cover fresh RSA/NKeys; both wire protocols bind exact issuance.
	ca := *identity.authority
	ca.NotAfter = now.Add(96 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &identity.signer.PublicKey, identity.signer)
	if err != nil {
		t.Fatal(err)
	}
	identity.authority, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := *identity.leaf
	leaf.SerialNumber, leaf.NotAfter = big.NewInt(3), now.Add(72*time.Hour)
	response := identity.response
	response.Certificate = identity.sign(t, leaf)
	response.Authority = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	response.ExpiresAt = leaf.NotAfter
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodPost || r.ProtoMajor != 2 || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" {
			t.Error("renewal crossed its native HTTPS boundary")
		}
		if respond != nil {
			respond(f, w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case IdentityRenewalPath(f.source.DeviceID, "prepare"):
			q, err := DecodeRenewalRequest(body)
			if err != nil || *q != *f.request {
				t.Error("preparation transport changed proof", err)
			}
			json.NewEncoder(w).Encode(f.prepared)
		case IdentityRenewalPath(f.source.DeviceID, "confirm"):
			q, err := DecodeRenewalConfirmation(body)
			if err != nil || *q != *f.confirmation {
				t.Error("confirmation transport changed proof", err)
			}
			json.NewEncoder(w).Encode(f.confirmed)
		default:
			t.Error("renewal used another route")
			http.Error(w, "unknown", 404)
		}
	}))
	f.server.EnableHTTP2 = true
	f.server.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	f.client, err = NewHTTPClient(f.server.URL, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.client.CloseIdleConnections(); f.server.CloseClientConnections(); f.server.Close() })
	broker, _ := identity.keys.Broker.PublicKey()
	f.source = RenewalSource{DeviceID: response.DeviceID, TenantID: response.TenantID, SiteID: response.SiteID, Origin: f.server.URL, Platform: "windows", Architecture: "amd64", BrokerKey: broker, Certificate: oldBlock.Bytes}
	f.request, err = NewRenewalRequest(f.source, identity.keys, identity.keys, uuid.NewString(), now)
	if err != nil {
		t.Fatal(err)
	}
	response.Endpoint = "wss" + strings.TrimPrefix(f.server.URL, "https") + "/agent-channel"
	f.prepared = PreparedIdentityRenewal{ID: f.request.RequestID, SourceCertificateHash: f.request.SourceCertificateHash, ExpiresAt: identity.leaf.NotAfter, Response: response}
	target, err := ValidatePreparedIdentityRenewal(f.prepared, *f.request, f.source, now)
	if err != nil {
		t.Fatal(err)
	}
	f.target = *target
	f.confirmation, err = NewRenewalConfirmation(f.target, identity.keys, now)
	if err != nil {
		t.Fatal(err)
	}
	f.confirmed = ConfirmedIdentityRenewal{ID: f.prepared.ID, DeviceID: f.source.DeviceID, CertificateHash: f.confirmation.CertificateHash, ConfirmedAt: now}
	return f
}

func TestHTTPSIdentityRenewalBindsBothResponsesAndDoesNotRetryImplicitly(t *testing.T) {
	f := newRenewalHTTPFixture(t, nil)
	for range 2 {
		prepared, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source)
		if err != nil || !reflect.DeepEqual(*prepared, f.prepared) {
			t.Fatal("preparation response lost binding", err)
		}
		confirmed, err := f.client.ConfirmIdentityRenewal(t.Context(), *f.confirmation, f.target)
		if err != nil || *confirmed != f.confirmed {
			t.Fatal("confirmation response lost binding", err)
		}
	}
	changed := *f.request
	changed.SiteID++
	if _, err := f.client.PrepareIdentityRenewal(t.Context(), changed, f.source); !errors.Is(err, ErrRenewalProof) {
		t.Fatal("bad source proof reached transport", err)
	}
	confirmation := *f.confirmation
	confirmation.CertificateHash = strings.Repeat("a", 64)
	if _, err := f.client.ConfirmIdentityRenewal(t.Context(), confirmation, f.target); !errors.Is(err, ErrRenewalConfirmation) {
		t.Fatal("bad candidate proof reached transport", err)
	}
	source := f.source
	source.Origin = "https://other.example.test"
	if _, err := f.client.PrepareIdentityRenewal(t.Context(), *f.request, source); !errors.Is(err, ErrRenewalProof) {
		t.Fatal("foreign source reached transport", err)
	}
	if f.requests.Load() != 4 {
		t.Fatal("invalid request was sent or client retried automatically", f.requests.Load())
	}
}

func TestHTTPSIdentityRenewalRejectsResponseSubstitutionAndUnsafeTransport(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		for _, mode := range []string{"redirect", "denied", "busy", "conflict", "unknown conflict", "HTML", "compression", "oversized", "duplicate", "null", "different target", "timestamp", "wrong TLS"} {
			t.Run(map[bool]string{false: "prepare", true: "confirm"}[confirm]+"/"+mode, func(t *testing.T) {
				f := newRenewalHTTPFixture(t, func(f *renewalHTTPFixture, w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch mode {
					case "redirect":
						w.Header().Set("Location", f.server.URL+"/should-not-receive-proof")
						w.WriteHeader(307)
						return
					case "denied":
						http.Error(w, "sensitive diagnostic", 404)
						return
					case "busy":
						http.Error(w, "sensitive diagnostic", 503)
						return
					case "conflict", "unknown conflict":
						code := "recovery_pending"
						if mode == "unknown conflict" {
							code = "sensitive diagnostic"
						}
						w.WriteHeader(409)
						json.NewEncoder(w).Encode(RenewalConflict{Version: 1, Code: code})
						return
					case "HTML":
						w.Header().Set("Content-Type", "text/html")
					case "compression":
						w.Header().Set("Content-Encoding", "gzip")
					case "oversized":
						w.Write(bytes.Repeat([]byte("x"), MaxPreparedIdentityRenewalBytes+1))
						return
					}
					var body []byte
					if confirm {
						value := f.confirmed
						if mode == "different target" {
							value.CertificateHash = strings.Repeat("a", 64)
						}
						if mode == "timestamp" {
							value.ConfirmedAt = time.Now().Add(2 * time.Minute)
						}
						body, _ = json.Marshal(value)
					} else {
						value := f.prepared
						if mode == "different target" {
							value.Response.SiteID++
						}
						if mode == "timestamp" {
							value.ExpiresAt = time.Now().Add(-time.Minute)
						}
						body, _ = json.Marshal(value)
					}
					if mode == "duplicate" {
						body = append(body[:len(body)-1], []byte(`,"id":"`+f.request.RequestID+`"}`)...)
					}
					if mode == "null" {
						body = bytes.Replace(body, []byte(`"id":"`+f.request.RequestID+`"`), []byte(`"id":null`), 1)
					}
					w.Write(body)
				})
				if mode == "wrong TLS" {
					f.client.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
				}
				var err error
				if confirm {
					_, err = f.client.ConfirmIdentityRenewal(t.Context(), *f.confirmation, f.target)
				} else {
					_, err = f.client.PrepareIdentityRenewal(t.Context(), *f.request, f.source)
				}
				want := ErrInvalidResponse
				switch mode {
				case "redirect":
					want = ErrEnrollmentRejected
				case "denied":
					want = ErrIdentityRenewalDenied
				case "busy":
					want = ErrEnrollmentBusy
				case "conflict":
					want = ErrIdentityRenewalRecoveryPending
				case "wrong TLS":
					want = ErrEnrollmentTransport
				}
				if !errors.Is(err, want) {
					t.Fatal("unsafe renewal response accepted", err)
				}
				if strings.Contains(err.Error(), "sensitive diagnostic") || strings.Contains(err.Error(), f.server.URL) || strings.Contains(err.Error(), f.request.RequestID) {
					t.Fatal("renewal leaked peer-controlled diagnostic")
				}
				expected := int32(1)
				if mode == "wrong TLS" {
					expected = 0
				}
				if f.requests.Load() != expected {
					t.Fatal("renewal proof was redirected, leaked or retried", f.requests.Load())
				}
			})
		}
	}
}

func TestHTTPSIdentityRenewalConfirmationCancellationKeepsCommitAmbiguous(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	f := newRenewalHTTPFixture(t, func(_ *renewalHTTPFixture, w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(stopped)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := f.client.ConfirmIdentityRenewal(ctx, *f.confirmation, f.target); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("confirmation did not reach fixture")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("confirmation lost cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmation did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled confirmation connection remained open")
	}
	if f.requests.Load() != 1 {
		t.Fatal("ambiguous confirmation was retried automatically")
	}
}

func FuzzIdentityRenewalResponses(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"id":"11111111-1111-4111-8111-111111111111","device_id":"22222222-2222-4222-8222-222222222222","certificate_hash":"` + strings.Repeat("a", 64) + `","confirmed_at":"2026-09-10T10:00:00Z"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if value, err := DecodePreparedIdentityRenewal(data); err == nil {
			wire, _ := json.Marshal(value)
			again, err := DecodePreparedIdentityRenewal(wire)
			reencoded, _ := json.Marshal(again)
			if err != nil || !bytes.Equal(wire, reencoded) {
				t.Fatal("preparation response did not round trip")
			}
		}
		if value, err := DecodeConfirmedIdentityRenewal(data); err == nil {
			wire, _ := json.Marshal(value)
			again, err := DecodeConfirmedIdentityRenewal(wire)
			reencoded, _ := json.Marshal(again)
			if err != nil || !bytes.Equal(wire, reencoded) {
				t.Fatal("confirmation response did not round trip")
			}
		}
	})
}

func TestIdentityRenewalResponseRequiresActualExtensionAndExactCandidate(t *testing.T) {
	f := newRenewalHTTPFixture(t, nil)
	changed := f.prepared
	changed.Response.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.source.Certificate}))
	old, _ := x509.ParseCertificate(f.source.Certificate)
	changed.Response.ExpiresAt = old.NotAfter
	if _, err := ValidatePreparedIdentityRenewal(changed, *f.request, f.source, time.Now()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("unextended original certificate accepted", err)
	}
	changed = f.prepared
	hash := sha256.Sum256([]byte("other source"))
	changed.SourceCertificateHash = hex.EncodeToString(hash[:])
	if _, err := ValidatePreparedIdentityRenewal(changed, *f.request, f.source, time.Now()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("foreign source accepted", err)
	}
	for _, code := range []string{"not_due", "pending", "recovery_pending"} {
		if errors.Is((RenewalConflict{Version: 1, Code: code}).ErrorValue(), ErrInvalidResponse) {
			t.Fatal("valid bounded conflict rejected")
		}
	}
}
