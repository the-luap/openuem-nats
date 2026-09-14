package netbirdapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ownedPeerEvent(at time.Time) map[string]any {
	return map[string]any{"id": "owned-event", "activity_code": "peer.setupkey.add", "initiator_id": "owned-key", "target_id": "owned-peer", "timestamp": at.Format(time.RFC3339Nano), "initiator_email": "private@example.test", "meta": map[string]any{"setup_key_name": "untrusted-name", "ip": "192.0.2.1"}}
}

func TestManagedPeerEventRequiresExactProviderEvidence(t *testing.T) {
	for _, change := range []string{"valid", "numeric-event", "missing", "wrong-activity", "wrong-key", "old", "future", "two-peers", "two-events", "duplicate-id", "duplicate-field", "alias", "null-time", "bad-peer", "float-id", "zero-id", "object", "trailing", "oversize"} {
		t.Run(change, func(t *testing.T) {
			at := time.Now().UTC()
			row := ownedPeerEvent(at)
			rows := []map[string]any{row}
			switch change {
			case "numeric-event":
				row["id"] = uint64(18446744073709551615)
			case "missing":
				rows = []map[string]any{}
			case "wrong-activity":
				row["activity_code"] = "peer.user.add"
			case "wrong-key":
				row["initiator_id"] = "another-key"
			case "old":
				row["timestamp"] = at.Add(-2 * time.Hour)
			case "future":
				row["timestamp"] = at.Add(2 * time.Hour)
			case "two-peers", "two-events", "duplicate-id":
				other := ownedPeerEvent(at)
				if change != "duplicate-id" {
					other["id"] = "other-event"
				}
				if change == "two-peers" {
					other["target_id"] = "other-peer"
				}
				rows = append(rows, other)
			case "alias":
				row["Initiator_ID"] = "another-key"
			case "null-time":
				row["timestamp"] = nil
			case "bad-peer":
				row["target_id"] = "../other"
			case "float-id":
				row["id"] = 1.5
			case "zero-id":
				row["id"] = 0
			}
			body, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "duplicate-field":
				body = []byte(strings.Replace(string(body), `"target_id":"owned-peer"`, `"target_id":"owned-peer","target_id":"other-peer"`, 1))
			case "object":
				body = []byte(`{}`)
			case "trailing":
				body = append(body, []byte(`[]`)...)
			case "oversize":
				body = []byte(`[` + strings.Repeat(" ", MaxResponse) + `]`)
			}
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/prefix/api/events/audit" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Token owned-token" {
					t.Error("wrong event endpoint or authority")
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			event, err := ManagedKeyPeer(t.Context(), server.Client().Transport, server.URL+"/prefix", "owned-token", "owned-key", at.Add(-time.Hour), at.Add(time.Hour))
			switch change {
			case "valid", "numeric-event":
				if err != nil || event == nil || event.KeyID != "owned-key" || event.PeerID != "owned-peer" || !event.Timestamp.Equal(at) {
					t.Fatalf("missing exact provider evidence: %v", err)
				}
				encoded, _ := json.Marshal(event)
				if strings.Contains(string(encoded), "private@example.test") || strings.Contains(string(encoded), "untrusted-name") || strings.Contains(string(encoded), "192.0.2.1") {
					t.Fatal("unrelated provider data escaped projection")
				}
			case "missing", "wrong-activity", "wrong-key", "old", "future":
				if err != nil || event != nil {
					t.Fatal("missing positive evidence was inferred from unrelated metadata")
				}
			default:
				if err == nil || event != nil {
					t.Fatal("ambiguous or invalid provider response was accepted")
				}
			}
			if calls.Load() != 1 {
				t.Fatal("event reader repeated the request")
			}
		})
	}
}

func TestManagedPeerExactObservation(t *testing.T) {
	for _, change := range []string{"present", "absent", "wrong-id", "missing-created", "null-name", "alias", "control-name", "redirect", "forbidden", "error"} {
		t.Run(change, func(t *testing.T) {
			at := time.Now().UTC()
			row := map[string]any{"id": "owned-peer", "name": "Office <Berlin>", "created_at": at, "user_id": "", "ephemeral": false, "public_key": "untrusted-ignored", "ip": "192.0.2.1"}
			switch change {
			case "wrong-id":
				row["id"] = "another-peer"
			case "missing-created":
				delete(row, "created_at")
			case "null-name":
				row["name"] = nil
			case "alias":
				row["Created_At"] = at
			case "control-name":
				row["name"] = "bad\nname"
			}
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/prefix/api/peers/owned-peer" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Token owned-token" {
					t.Error("peer was selected by mutable metadata")
				}
				switch change {
				case "absent":
					w.WriteHeader(404)
					return
				case "redirect":
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(302)
					return
				case "forbidden":
					w.WriteHeader(403)
					return
				case "error":
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(row)
			}))
			defer server.Close()
			peer, absent, err := ObserveManagedPeer(t.Context(), server.Client().Transport, server.URL+"/prefix", "owned-token", "owned-peer")
			if change == "present" {
				if err != nil || absent || peer == nil || peer.ID != "owned-peer" || !peer.CreatedAt.Equal(at) || peer.Name != "Office <Berlin>" {
					t.Fatal("exact peer observation lost")
				}
				if strings.Contains(fmt.Sprintf("%+v", peer), "untrusted-ignored") {
					t.Fatal("unverified public key became evidence")
				}
			} else if change == "absent" {
				if err != nil || !absent || peer != nil {
					t.Fatal("exact absence lost")
				}
			} else if err == nil || absent || peer != nil {
				t.Fatal("invalid peer or provider error became evidence")
			}
			if calls.Load() != 1 {
				t.Fatal("peer request retried or redirected")
			}
		})
	}
}

func TestManagedPeerInvalidInputsDoNotContactProvider(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("owned unavailable transport")
	})
	at := time.Now()
	for _, id := range []string{"", "../peer", "peer?next=other", strings.Repeat("p", 129)} {
		if _, _, err := ObserveManagedPeer(t.Context(), transport, "https://provider.example.test", "owned", id); err == nil {
			t.Fatal("invalid peer ID accepted")
		}
		if _, err := ManagedKeyPeer(t.Context(), transport, "https://provider.example.test", "owned", id, at, at.Add(time.Hour)); err == nil {
			t.Fatal("invalid key ID accepted")
		}
	}
	for _, end := range []time.Time{at, at.Add(-time.Hour), at.Add(48 * time.Hour), {}} {
		if _, err := ManagedKeyPeer(t.Context(), transport, "https://provider.example.test", "owned", "owned-key", at, end); err == nil {
			t.Fatal("invalid evidence interval accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid evidence request contacted provider")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ManagedKeyPeer(ctx, nil, "https://provider.example.test", "owned", "owned-key", at, at.Add(time.Hour)); err == nil {
		t.Fatal("cancelled event read succeeded")
	}
}
