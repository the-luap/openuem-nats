package enrollment

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const AuthorizationSubject = "$SYS.REQ.USER.AUTH"
const BrokerLease = 5 * time.Minute

var ErrInvalidAuthorization = errors.New("invalid broker authorization request")
var accountName = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,63}$`)

type BrokerSession struct {
	ServerID  string
	ClientID  uint64
	ExpiresAt time.Time
}

type BrokerIdentity struct {
	DeviceID             string
	CertificateExpiresAt time.Time
}

// AuthorizeDevice must check active enrollment and record the proposed session
// atomically. The session allows revocation to disconnect an existing client;
// the bounded broker lease remains a fallback if the disconnect path fails.
type AuthorizeDevice func(context.Context, string, BrokerSession) (*BrokerIdentity, error)

type BrokerAuthorizer struct {
	signer          nkeys.KeyPair
	issuer, account string
	authorize       AuthorizeDevice
}

func NewBrokerAuthorizer(signer nkeys.KeyPair, account string, authorize AuthorizeDevice) (*BrokerAuthorizer, error) {
	if signer == nil || authorize == nil || !accountName.MatchString(account) {
		return nil, ErrInvalidAuthorization
	}
	public, err := signer.PublicKey()
	if err != nil || !nkeys.IsValidPublicAccountKey(public) {
		return nil, ErrInvalidAuthorization
	}
	if _, err = signer.Sign([]byte("openuem/agent/authorization-key-check/v1")); err != nil {
		return nil, ErrInvalidAuthorization
	}
	return &BrokerAuthorizer{signer: signer, issuer: public, account: account, authorize: authorize}, nil
}

// Authorize implements NATS config-mode auth callout for individual agents.
// Call it only from the isolated auth account's protected subscription, never a
// public HTTP endpoint or an ordinary agent's account. Server JWT signatures are
// self-consistent identities, not a substitute for that transport/account trust.
func (a *BrokerAuthorizer) Authorize(ctx context.Context, encoded []byte) ([]byte, error) {
	if a == nil || a.signer == nil || len(encoded) == 0 || len(encoded) > 64<<10 {
		return nil, ErrInvalidAuthorization
	}
	request, err := jwt.DecodeAuthorizationRequestClaims(string(encoded))
	if err != nil {
		return nil, ErrInvalidAuthorization
	}
	now := time.Now()
	validation := jwt.CreateValidationResults()
	request.Validate(validation)
	if validation.IsBlocking(true) || request.Audience != "nats-authorization-request" || request.Subject != a.issuer || request.Issuer != request.Server.ID || !nkeys.IsValidPublicServerKey(request.Server.ID) || request.ClientInformation.ID == 0 || request.Expires <= now.Unix() || request.Expires > now.Add(30*time.Second).Unix() || request.IssuedAt > now.Add(5*time.Second).Unix() || request.IssuedAt < now.Add(-30*time.Second).Unix() {
		return nil, ErrInvalidAuthorization
	}
	response := jwt.NewAuthorizationResponseClaims(request.UserNkey)
	response.Audience = request.Server.ID
	response.Expires = request.Expires
	response.Error = "device authorization denied"
	if verifyBrokerNonce(request) {
		deadline, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		lease := now.Add(BrokerLease)
		identity, lookupErr := a.authorize(deadline, request.ConnectOptions.Nkey, BrokerSession{ServerID: request.Server.ID, ClientID: request.ClientInformation.ID, ExpiresAt: lease})
		if lookupErr == nil && deadline.Err() == nil && identity != nil && ValidDeviceID(identity.DeviceID) && identity.CertificateExpiresAt.After(time.Now()) {
			if identity.CertificateExpiresAt.Before(lease) {
				lease = identity.CertificateExpiresAt
			}
			policy, _ := DeviceSubjects(identity.DeviceID)
			user := jwt.NewUserClaims(request.UserNkey)
			user.Name = "openuem-agent:" + identity.DeviceID
			user.Audience = a.account
			user.Expires = lease.Unix()
			user.Pub.Allow = policy.Publish
			user.Sub.Allow = policy.Subscribe
			user.Resp = &jwt.ResponsePermission{MaxMsgs: policy.ReplyMaxMessages, Expires: time.Duration(policy.ReplyMaxSeconds) * time.Second}
			user.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeStandard, jwt.ConnectionTypeWebsocket}
			user.Subs = 128
			user.NatsLimits.Payload = 8 << 20
			response.Jwt, err = user.Encode(a.signer)
			if err != nil {
				return nil, ErrInvalidAuthorization
			}
			response.Error = ""
		}
	}
	result, err := response.Encode(a.signer)
	if err != nil {
		return nil, ErrInvalidAuthorization
	}
	return []byte(result), nil
}

func verifyBrokerNonce(request *jwt.AuthorizationRequestClaims) bool {
	options := request.ConnectOptions
	nonce := request.ClientInformation.Nonce
	if !nkeys.IsValidPublicUserKey(options.Nkey) || options.JWT != "" || options.Token != "" || options.Username != "" || options.Password != "" || len(nonce) < 15 || len(nonce) > 512 || len(options.SignedNonce) != 86 {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(options.SignedNonce)
	if err != nil || len(signature) != 64 {
		return false
	}
	key, err := nkeys.FromPublicKey(options.Nkey)
	return err == nil && key.Verify([]byte(nonce), signature) == nil
}
