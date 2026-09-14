package enrollment

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestLinuxEnrollmentProofRetainsExactTargetAndBothKeyBindings(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			request, err := keys.Request(testToken(t), "linux", architecture, "Owned Linux endpoint")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := Validate(*request)
			if err != nil || !identity.CertificateKey.Equal(&keys.Certificate.PublicKey) || identity.BrokerKey != request.BrokerKey {
				t.Fatal("Linux proof lost its local keys", err)
			}
			for _, platform := range []string{"windows", "macos", "Linux", "freebsd"} {
				changed := *request
				changed.Platform = platform
				if _, err := Validate(changed); !errors.Is(err, ErrInvalidProof) {
					t.Fatal("changed platform reused a Linux proof", err)
				}
			}
			changed := *request
			changed.Architecture = "amd64"
			if architecture == "amd64" {
				changed.Architecture = "arm64"
			}
			if _, err := Validate(changed); !errors.Is(err, ErrInvalidProof) {
				t.Fatal("changed architecture reused a Linux proof", err)
			}
		})
	}
}

func TestLinuxRenewalWireRetainsSourceAndCandidateProofs(t *testing.T) {
	source, current, candidate, now := renewalTestSource(t)
	source.Platform = "linux"
	for _, architecture := range []string{"amd64", "arm64"} {
		source.Architecture = architecture
		request, err := NewRenewalRequest(source, current, candidate, uuid.NewString(), now)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRenewalRequest(encoded)
		if err != nil || *decoded != *request {
			t.Fatal("Linux renewal changed on the wire", err)
		}
		proof, err := ValidateRenewalProof(*decoded, source, now)
		if err != nil || !proof.CertificateKey.Equal(&candidate.Certificate.PublicKey) {
			t.Fatal("Linux renewal lost candidate ownership", err)
		}
		changed := *decoded
		changed.Platform = "macos"
		if _, err := ValidateRenewalProof(changed, source, now); err == nil {
			t.Fatal("Linux renewal accepted another platform")
		}
		changed = *decoded
		changed.SourceBrokerProof = changed.CandidateBrokerProof
		if _, err := ValidateRenewalProof(changed, source, now); err == nil {
			t.Fatal("Linux renewal substituted candidate for source authority")
		}
	}
}
