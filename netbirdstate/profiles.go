// Package netbirdstate preserves bounded NetBird profile identities in legacy
// text storage without interpreting commas or labels as identifiers.
package netbirdstate

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	nats "github.com/open-uem/nats"
)

const MaxProfiles = 256
const MaxText = 256
const MaxStored = 1 << 20
const prefix = "openuem-netbird-profiles:v1:"

var ErrProfiles = errors.New("NetBird profiles could not be read")

func ValidText(value string) bool {
	if value == "" || len(value) > MaxText || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func ValidID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func Validate(profiles []nats.NetbirdProfile) error {
	if len(profiles) > MaxProfiles {
		return ErrProfiles
	}
	seen := map[string]bool{}
	active := 0
	for _, profile := range profiles {
		if !ValidText(profile.Name) || profile.ID != "" && !ValidID(profile.ID) || seen[profile.Handle()] {
			return ErrProfiles
		}
		seen[profile.Handle()] = true
		if profile.Active {
			active++
		}
	}
	if active > 1 {
		return ErrProfiles
	}
	return nil
}

func Encode(report nats.Netbird) (string, error) {
	profiles := report.ProfileDetails
	if profiles == nil {
		profiles = make([]nats.NetbirdProfile, 0, len(report.Profiles))
		for _, name := range report.Profiles {
			// Older collectors split an empty profile list into one empty string.
			if len(report.Profiles) == 1 && name == "" {
				continue
			}
			profiles = append(profiles, nats.NetbirdProfile{Name: name})
		}
	}
	if err := Validate(profiles); err != nil {
		return "", err
	}
	data, err := json.Marshal(profiles)
	if err != nil || len(data)+len(prefix) > MaxStored {
		return "", ErrProfiles
	}
	return prefix + string(data), nil
}

func Decode(stored string) ([]nats.NetbirdProfile, error) {
	if len(stored) > MaxStored || !utf8.ValidString(stored) {
		return nil, ErrProfiles
	}
	var profiles []nats.NetbirdProfile
	if strings.HasPrefix(stored, prefix) {
		raw := strings.TrimPrefix(stored, prefix)
		if raw == "null" || json.Unmarshal([]byte(raw), &profiles) != nil {
			return nil, ErrProfiles
		}
	} else if strings.HasPrefix(stored, "openuem-netbird-profiles:") {
		return nil, ErrProfiles
	} else if stored != "" {
		// Existing rows used comma-separated names. A subsequent current report
		// replaces this format; old ambiguous comma-containing names cannot be
		// reconstructed from those rows.
		for _, name := range strings.Split(stored, ",") {
			profiles = append(profiles, nats.NetbirdProfile{Name: name})
		}
	}
	if err := Validate(profiles); err != nil {
		return nil, err
	}
	return profiles, nil
}
