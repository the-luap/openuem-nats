package netbirdapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func ownedManagedResponse(r ManagedKeyRequest) map[string]any {
	return map[string]any{"id": "owned-key-id", "name": "OpenUEM registration " + r.RequestID, "type": "one-off", "key": "owned-private-setup-key", "expires": time.Now().UTC().Add(ManagedKeyLifetime).Format(time.RFC3339Nano), "valid": true, "revoked": false, "used_times": 0, "usage_limit": 1, "auto_groups": r.Groups, "ephemeral": false, "allow_extra_dns_labels": r.ExtraDNS}
}

func TestManagedSetupKeyCreationAndScopedObservation(t *testing.T) {
	r := ManagedKeyRequest{RequestID: uuid.NewString(), Groups: []string{"second", "first"}, ExtraDNS: true}
	body := ownedManagedResponse(r)
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Token owned-provider-token" {
			t.Error("missing provider authority")
		}
		switch request.Method + " " + request.URL.Path {
		case "POST /prefix/api/setup-keys":
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			var got setupRequest
			if json.Unmarshal(data, &got) != nil || got.Name != body["name"] || got.Type != "one-off" || got.UsageLimit != 1 || got.ExpiresIn != 86400 || got.Ephemeral || !got.ExtraDNS || !slices.Equal(got.Groups, []string{"first", "second"}) {
				t.Error("creation policy changed")
			}
		case "GET /prefix/api/setup-keys/owned-key-id":
			body["key"] = "masked****"
			body["used_times"] = 1
			body["valid"] = false
		case "DELETE /prefix/api/setup-keys/owned-key-id":
			w.WriteHeader(204)
			return
		default:
			t.Error("unexpected provider request")
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && request.GetBody != nil {
			t.Error("creation body can be replayed")
		}
		return server.Client().Transport.RoundTrip(request)
	})
	key, err := CreateManagedKey(t.Context(), transport, server.URL+"/prefix", "owned-provider-token", r)
	if err != nil || key == nil || key.Secret != "owned-private-setup-key" {
		t.Fatal("owned creation did not retain its result")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", key, key), "owned-private-setup-key") {
		t.Fatal("default formatting disclosed a credential")
	}
	if !slices.Equal(r.Groups, []string{"second", "first"}) {
		t.Fatal("creation reordered the caller's groups")
	}
	observed, missing, err := ObserveManagedKey(t.Context(), transport, server.URL+"/prefix", "owned-provider-token", key.ID)
	if err != nil || missing || observed == nil || !key.SameOwnership(*observed) || observed.UsedTimes != 1 {
		t.Fatal("matching cleanup identity was lost after usage")
	}
	if err = DeleteKey(t.Context(), transport, server.URL+"/prefix", "owned-provider-token", key.ID); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("provider request was retried")
	}
}

func TestManagedSetupKeyRejectsCreationDrift(t *testing.T) {
	r := ManagedKeyRequest{RequestID: uuid.NewString(), Groups: []string{"owned-group"}}
	for _, change := range []string{"wrong-name", "wrong-type", "reusable", "revoked", "used", "invalid", "groups", "dns", "ephemeral", "expired", "long-lifetime", "masked", "missing-flag", "null-groups", "duplicate-id", "alias", "wrong-id"} {
		t.Run(change, func(t *testing.T) {
			body := ownedManagedResponse(r)
			switch change {
			case "wrong-name":
				body["name"] = "another request"
			case "wrong-type":
				body["type"] = "reusable"
			case "reusable":
				body["usage_limit"] = 0
			case "revoked":
				body["revoked"] = true
			case "used":
				body["used_times"] = 1
			case "invalid":
				body["valid"] = false
			case "groups":
				body["auto_groups"] = []string{"another-group"}
			case "dns":
				body["allow_extra_dns_labels"] = true
			case "ephemeral":
				body["ephemeral"] = true
			case "expired":
				body["expires"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
			case "long-lifetime":
				body["expires"] = time.Now().Add(2 * ManagedKeyLifetime).Format(time.RFC3339Nano)
			case "masked":
				body["key"] = "private****"
			case "missing-flag":
				delete(body, "ephemeral")
			case "null-groups":
				body["auto_groups"] = nil
			case "alias":
				body["Valid"] = false
			case "wrong-id":
				body["id"] = "../owned-key"
			}
			data, _ := json.Marshal(body)
			if change == "duplicate-id" {
				data = append([]byte(`{"id":"other",`), data[1:]...)
			}
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write(data) }))
			defer server.Close()
			key, err := CreateManagedKey(t.Context(), server.Client().Transport, server.URL, "owned", r)
			if key != nil || !errors.Is(err, ErrUnavailable) || calls.Load() != 1 {
				t.Fatal("unconfirmed creation was accepted or retried")
			}
		})
	}
}

func TestManagedSetupKeyAbsenceIsReadOnlyAndBounded(t *testing.T) {
	for _, status := range []int{200, 401, 403, 404, 429, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" {
					t.Error("observation mutated provider state")
				}
				w.Header().Set("Location", "https://uncontacted.example.test")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "private-provider-detail")
			}))
			defer server.Close()
			result, missing, err := ObserveManagedKey(t.Context(), server.Client().Transport, server.URL, "owned", "owned-key")
			if calls.Load() != 1 || result != nil {
				t.Fatal("observation returned unmatched metadata or followed a redirect")
			}
			if status == 404 {
				if err != nil || !missing {
					t.Fatal("known-key absence was not distinguished")
				}
			} else if !errors.Is(err, ErrUnavailable) || missing {
				t.Fatal("provider failure became proof of absence")
			}
		})
	}
	noCall := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid creation reached provider")
		return nil, ErrUnavailable
	})
	for _, r := range []ManagedKeyRequest{{RequestID: "invalid"}, {RequestID: uuid.NewString(), Groups: []string{"one", "one"}}, {RequestID: uuid.NewString(), Groups: []string{"../one"}}, {RequestID: uuid.NewString(), Groups: make([]string, 101)}} {
		if _, err := CreateManagedKey(t.Context(), noCall, "https://owned.example.test", "owned", r); err == nil {
			t.Fatal("invalid creation accepted")
		}
	}
}

func TestManagedSetupKeyDigestAndNoRetryAfterCancellation(t *testing.T) {
	r := ManagedKeyRequest{RequestID: uuid.NewString(), Groups: []string{"second", "first"}}
	first, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.Groups = []string{"first", "second"}
	second, err := r.Digest()
	if err != nil || first != second {
		t.Fatal("equivalent groups changed the body digest")
	}
	r.ExtraDNS = true
	second, err = r.Digest()
	if err != nil || first == second {
		t.Fatal("body digest omitted registration policy")
	}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		<-request.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err = CreateManagedKey(ctx, server.Client().Transport, server.URL, "owned", r); !errors.Is(err, ErrUnavailable) || calls.Load() != 1 {
		t.Fatal("cancelled creation was retried")
	}
}

func FuzzManagedSetupKey(f *testing.F) {
	r := ManagedKeyRequest{RequestID: uuid.NewString(), Groups: []string{}}
	body, _ := json.Marshal(ownedManagedResponse(r))
	f.Add(body)
	f.Add([]byte(`{"id":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		k, err := decodeManagedKey(body, true)
		if err == nil {
			if !identifier(k.ID) || k.Secret == "" || k.Type != "one-off" || k.UsageLimit != 1 {
				t.Fatal("decoded key escaped managed policy")
			}
		}
	})
}
