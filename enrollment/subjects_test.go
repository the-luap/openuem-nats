package enrollment

import (
	"strings"
	"testing"
)

func TestAgentRequestAndReplyIdentityCannotBeExpanded(t *testing.T) {
	id := "12345678-1234-4234-8234-123456789abc"
	foreign := "12345678-1234-4234-8234-123456789abd"
	for _, operation := range Operations() {
		subject, err := RequestSubject(id, operation)
		if err != nil {
			t.Fatal(err)
		}
		gotID, gotOperation, err := ParseRequestSubject(subject)
		if err != nil || gotID != id || gotOperation != operation {
			t.Fatal("request identity lost", subject, err)
		}
	}
	for _, subject := range []string{"report", "uem.v1.agent.*.request.report", "uem.v1.agent." + id + ".request.report.more", "uem.v1.agent." + id + ".request.agent.reboot", "uem.v2.agent." + id + ".request.report", "uem.v1.agent." + strings.ToUpper(id) + ".request.report"} {
		if _, _, err := ParseRequestSubject(subject); err == nil {
			t.Fatal("unbounded request accepted", subject)
		}
	}
	inbox, _ := ReplyPrefix(id)
	if !ValidReply(id, inbox+".AbCd0123.abc") {
		t.Fatal("private request inbox rejected")
	}
	for _, reply := range []string{"_INBOX.administrator", "agent.reboot." + foreign, "uem.v1.agent." + foreign + ".reply.abc", inbox + ".*", inbox + ".>", inbox + ".", inbox + ".a..b", inbox + ".a\r\n"} {
		if ValidReply(id, reply) {
			t.Fatal("confused-deputy reply accepted", reply)
		}
	}
	for _, bad := range []string{"", "*", id + ".>", "00000000-0000-0000-0000-000000000000"} {
		if _, err := DeviceSubjects(bad); err == nil {
			t.Fatal("invalid identity received permissions", bad)
		}
	}
	operations := Operations()
	operations[0] = "certificates.agent"
	if _, err := RequestSubject(id, "certificates.agent"); err == nil {
		t.Fatal("caller mutated permitted operations")
	}
}
