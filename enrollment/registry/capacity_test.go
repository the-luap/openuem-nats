package registry

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func TestDistinctConcurrentDevicesCannotExceedInvitationCapacity(t *testing.T) {
	s := testStore(t)
	i, token := invite(t, s, Scope{TenantID: 1, SiteID: 1}, 2)
	requests := make([]*enrollment.Request, 5)
	for index := range requests {
		keys, err := enrollment.GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		requests[index] = proof(t, token, keys)
	}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	var jobs sync.WaitGroup
	for _, request := range requests {
		jobs.Go(func() {
			<-start
			_, err := s.Claim(context.Background(), *request)
			results <- err
		})
	}
	close(start)
	jobs.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	var uses, count int
	if err := s.db.QueryRow(`SELECT uses FROM uem_agent_invitations WHERE id=$1`, i.ID).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM uem_agent_identities WHERE invitation_id=$1`, i.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if accepted != 2 || uses != 2 || count != 2 {
		t.Fatalf("capacity exceeded or leaked: accepted=%d uses=%d identities=%d", accepted, uses, count)
	}
}
