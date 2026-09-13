// Package netbirdapi provides bounded NetBird requests to a configured HTTPS origin.
package netbirdapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/open-uem/nats"
)

// Groups only contacts the configured HTTPS origin. Redirects and response
// bodies are never forwarded to the caller, including provider error bodies.
func Groups(ctx context.Context, transport http.RoundTripper, base, token string) ([]nats.NetBirdGroups, error) {
	body, err := request(ctx, transport, base, token, http.MethodGet, "groups", nil, nil)
	if err != nil {
		return nil, err
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '[' {
		return nil, ErrUnavailable
	}
	groups := []nats.NetBirdGroups{}
	if json.Unmarshal(body, &groups) != nil || len(groups) > 1000 {
		return nil, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, group := range groups {
		if !identifier(group.ID) || seen[group.ID] || len(group.Name) > 1024 || !utf8.ValidString(group.Name) || strings.ContainsRune(group.Name, 0) || group.PeersCount < 0 {
			return nil, ErrUnavailable
		}
		seen[group.ID] = true
	}
	return groups, nil
}
