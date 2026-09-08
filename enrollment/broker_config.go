package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nkeys"
)

// BrokerConfiguration describes a dedicated individual-agent broker. Its public
// service keys are separate from all legacy certificates and shared agent keys.
type BrokerConfiguration struct {
	Name, Listen, WebsocketListen                                                       string
	CertificateFile, KeyFile, GatewayCAFile, StoreDirectory                             string
	Issuer, AuthorizationUser, RevocationUser, WorkerUser, ConsoleUser, ProvisionerUser string
}

// Render produces stock NATS configuration with no private service seeds. The
// deployment must keep both listeners private and expose WSS only via the gateway.
func (config BrokerConfiguration) Render() ([]byte, error) {
	if config.Name == "" || len(config.Name) > 64 || unsafeConfigString(config.Name) || !nkeys.IsValidPublicAccountKey(config.Issuer) {
		return nil, errors.New("invalid individual broker identity")
	}
	seen := map[string]bool{}
	for _, public := range []string{config.AuthorizationUser, config.RevocationUser, config.WorkerUser, config.ConsoleUser, config.ProvisionerUser} {
		if !nkeys.IsValidPublicUserKey(public) || seen[public] {
			return nil, errors.New("broker services require distinct public user NKeys")
		}
		seen[public] = true
	}
	for _, address := range []string{config.Listen, config.WebsocketListen} {
		parsed, err := netip.ParseAddrPort(address)
		if err != nil || parsed.Port() == 0 || parsed.Addr().IsMulticast() {
			return nil, errors.New("broker listeners require numeric IP addresses and ports")
		}
	}
	if config.Listen == config.WebsocketListen {
		return nil, errors.New("broker listener addresses must differ")
	}
	for _, path := range []string{config.CertificateFile, config.KeyFile, config.GatewayCAFile, config.StoreDirectory} {
		if !filepath.IsAbs(path) || unsafeConfigString(path) {
			return nil, errors.New("broker TLS and storage paths must be absolute")
		}
	}
	type object = map[string]any
	user := func(public string, publish, subscribe []string, responseSeconds int) object {
		permissions := object{"subscribe": subscribe}
		if len(publish) == 0 {
			permissions["publish"] = object{"deny": []string{">"}}
		} else {
			permissions["publish"] = publish
		}
		if responseSeconds > 0 {
			permissions["allow_responses"] = object{"max": 1, "expires": (time.Duration(responseSeconds) * time.Second).String()}
		}
		return object{"nkey": public, "permissions": permissions}
	}
	requests := make([]string, 0, len(requestOperations))
	for _, operation := range requestOperations {
		requests = append(requests, "uem.v1.agent.*.request."+operation)
	}
	// The console issues commands but cannot authorize devices or rewrite their
	// consumers. Only the separately held provisioning user manages this stream.
	consolePublish := []string{"agent.*.*", "agent.*.*.*", "agent.*.*.*.*"}
	provisionPublish := []string{
		"$JS.API.STREAM.CREATE.AGENTS_STREAM", "$JS.API.STREAM.INFO.AGENTS_STREAM",
		"$JS.API.CONSUMER.CREATE.AGENTS_STREAM.>", "$JS.API.CONSUMER.INFO.AGENTS_STREAM.*",
		"$JS.API.CONSUMER.DELETE.AGENTS_STREAM.*",
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	// Stock NATS accepts JSON objects but not JSON's Unicode escape syntax.
	// Keep subject wildcards literal instead of encoding ">" as a Unicode escape.
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(object{
		"server_name": config.Name, "listen": config.Listen, "max_payload": 8 << 20,
		"max_connections": 8192, "max_pending": 64 << 20, "write_deadline": "10s",
		"tls": object{"cert_file": config.CertificateFile, "key_file": config.KeyFile, "timeout": 3},
		"websocket": object{"listen": config.WebsocketListen, "handshake_timeout": "5s",
			"tls": object{"cert_file": config.CertificateFile, "key_file": config.KeyFile, "ca_file": config.GatewayCAFile, "verify": true, "timeout": 3}},
		"jetstream":      object{"store_dir": config.StoreDirectory, "max_mem": 512 << 20, "max_file": int64(5) << 30},
		"system_account": "UEM_SYSTEM",
		"authorization": object{"timeout": 2, "auth_callout": object{
			"issuer": config.Issuer, "account": "UEM_AUTH",
			// Static trusted services authenticate with their configured NKey and
			// keep only their own account permissions. Device keys never bypass
			// the registry callout. The config-mode auth_users list is a bypass
			// list, not a grant of access to the isolated authorization account.
			"auth_users":       []string{config.AuthorizationUser, config.RevocationUser, config.WorkerUser, config.ConsoleUser, config.ProvisionerUser},
			"allowed_accounts": []string{"UEM_DEVICES"},
		}},
		"accounts": object{
			"UEM_AUTH":   object{"users": []object{user(config.AuthorizationUser, nil, []string{AuthorizationSubject}, 1)}},
			"UEM_SYSTEM": object{"users": []object{user(config.RevocationUser, []string{"$SYS.REQ.SERVER.*.KICK"}, []string{"_INBOX.>"}, 0)}},
			"UEM_DEVICES": object{"jetstream": "enabled", "users": []object{
				user(config.WorkerUser, nil, requests, 900),
				user(config.ConsoleUser, consolePublish, []string{"_INBOX.>"}, 0),
				user(config.ProvisionerUser, provisionPublish, []string{"_INBOX.>"}, 0),
			}},
		},
	})
	return output.Bytes(), err
}

func unsafeConfigString(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' })
}
