package enrollment

import (
	"encoding/hex"
	"errors"
	"strings"
)

var ErrInvalidSubject = errors.New("invalid individual-agent subject")

var requestOperations = []string{
	"report", "hardware", "recovery", "deployresult", "agentconfig", "wingetcfg.profiles",
	"ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report",
}

func ValidDeviceID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || id != strings.ToLower(id) {
		return false
	}
	data, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(data) != 16 {
		return false
	}
	for _, b := range data {
		if b != 0 {
			return true
		}
	}
	return false
}

func Operations() []string { return append([]string(nil), requestOperations...) }

func RequestSubject(deviceID, operation string) (string, error) {
	if !ValidDeviceID(deviceID) {
		return "", ErrInvalidSubject
	}
	for _, allowed := range requestOperations {
		if operation == allowed {
			return "uem.v1.agent." + deviceID + ".request." + operation, nil
		}
	}
	return "", ErrInvalidSubject
}

func ParseRequestSubject(subject string) (deviceID, operation string, err error) {
	parts := strings.SplitN(subject, ".", 6)
	if len(parts) != 6 || parts[0] != "uem" || parts[1] != "v1" || parts[2] != "agent" || parts[4] != "request" {
		return "", "", ErrInvalidSubject
	}
	canonical, err := RequestSubject(parts[3], parts[5])
	if err != nil || canonical != subject {
		return "", "", ErrInvalidSubject
	}
	return parts[3], parts[5], nil
}

func ReplyPrefix(deviceID string) (string, error) {
	if !ValidDeviceID(deviceID) {
		return "", ErrInvalidSubject
	}
	return "uem.v1.agent." + deviceID + ".reply", nil
}

// ValidReply prevents a request from turning its privileged worker's response
// into a command or a message to another device's inbox.
func ValidReply(deviceID, reply string) bool {
	prefix, err := ReplyPrefix(deviceID)
	if err != nil || len(reply) > 512 || !strings.HasPrefix(reply, prefix+".") {
		return false
	}
	suffix := strings.TrimPrefix(reply, prefix+".")
	for _, part := range strings.Split(suffix, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

func ConsumerName(deviceID string) (string, error) {
	if !ValidDeviceID(deviceID) {
		return "", ErrInvalidSubject
	}
	return "AgentConsumer" + deviceID, nil
}

type SubjectPolicy struct {
	Publish, Subscribe                []string
	ReplyMaxMessages, ReplyMaxSeconds int
}

// DeviceSubjects deliberately grants no consumer-creation API. The service must
// provision the fixed consumer and its filters before the endpoint connects.
func DeviceSubjects(deviceID string) (*SubjectPolicy, error) {
	consumer, err := ConsumerName(deviceID)
	if err != nil {
		return nil, err
	}
	inbox, _ := ReplyPrefix(deviceID)
	p := &SubjectPolicy{ReplyMaxMessages: 1, ReplyMaxSeconds: 900}
	for _, operation := range requestOperations {
		subject, _ := RequestSubject(deviceID, operation)
		p.Publish = append(p.Publish, subject)
	}
	p.Publish = append(p.Publish,
		"$JS.API.CONSUMER.INFO.AGENTS_STREAM."+consumer,
		"$JS.API.CONSUMER.MSG.NEXT.AGENTS_STREAM."+consumer,
		"$JS.ACK.AGENTS_STREAM."+consumer+".>",
		"$JS.ACK.*.*.AGENTS_STREAM."+consumer+".>",
	)
	p.Subscribe = []string{inbox + ".>", "agent.*." + deviceID, "agent.*.*." + deviceID, "agent.*.*.*." + deviceID}
	return p, nil
}
