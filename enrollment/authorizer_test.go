package enrollment

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestBrokerAuthorizationBindsProofConnectionAndDevice(t *testing.T) {
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	broker, _ := nkeys.CreateServer()
	serverID, _ := broker.PublicKey()
	device, _ := nkeys.CreateUser()
	deviceKey, _ := device.PublicKey()
	connection, _ := nkeys.CreateUser()
	connectionKey, _ := connection.PublicKey()
	const id = "12345678-1234-4234-8234-123456789abc"
	calls := 0
	denied := false
	a, err := NewBrokerAuthorizer(signer, "UEM_DEVICES", func(ctx context.Context, key string, session BrokerSession) (*BrokerIdentity, error) {
		calls++
		if key != deviceKey || session.ServerID != serverID || session.ClientID != 42 || time.Until(session.ExpiresAt) > BrokerLease || ctx.Err() != nil {
			t.Error("identity/session binding was lost")
		}
		if denied {
			return nil, errors.New("private database details must not enter authorization responses")
		}
		return &BrokerIdentity{DeviceID: id, CertificateExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := jwt.NewAuthorizationRequestClaims(issuer)
	request.Audience = "nats-authorization-request"
	request.UserNkey = connectionKey
	request.Server.ID = serverID
	request.Expires = time.Now().Add(10 * time.Second).Unix()
	request.ClientInformation.ID = 42
	request.ClientInformation.Nonce = testToken(t)[:15]
	request.ConnectOptions.Nkey = deviceKey
	signature, _ := device.Sign([]byte(request.ClientInformation.Nonce))
	request.ConnectOptions.SignedNonce = base64.RawURLEncoding.EncodeToString(signature)
	run := func(r *jwt.AuthorizationRequestClaims) *jwt.AuthorizationResponseClaims {
		t.Helper()
		token, err := r.Encode(broker)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := a.Authorize(context.Background(), []byte(token))
		if err != nil {
			t.Fatal(err)
		}
		response, err := jwt.DecodeAuthorizationResponseClaims(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if response.Subject != connectionKey || response.Audience != serverID || response.Issuer != issuer {
			t.Fatal("authorization response can be used for a different connection")
		}
		return response
	}
	response := run(request)
	if response.Error != "" || calls != 1 {
		t.Fatal("valid device proof denied", response.Error)
	}
	user, err := jwt.DecodeUserClaims(response.Jwt)
	if err != nil {
		t.Fatal(err)
	}
	if user.Subject != connectionKey || user.Audience != "UEM_DEVICES" || user.Name != "openuem-agent:"+id || user.Expires > time.Now().Add(time.Minute).Unix() || user.BearerToken {
		t.Fatal("unbound or excessive broker grant")
	}
	denied = true
	response = run(request)
	if response.Error != "device authorization denied" || response.Jwt != "" || strings.Contains(response.String(), "database") {
		t.Fatal("revoked/unknown identity authorized or error leaked")
	}
	denied = false
	before := calls
	request.ClientInformation.Nonce = testToken(t)[:15]
	response = run(request)
	if response.Error == "" || calls != before {
		t.Fatal("captured nonce signature was replayed")
	}
	request.Expires = time.Now().Add(-time.Second).Unix()
	token, err := request.Encode(broker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authorize(context.Background(), []byte(token)); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatal("expired broker request accepted", err)
	}
}
