package registry

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

type InvitationOptions struct {
	Scope
	Platform     string    `json:"platform"`
	Architecture string    `json:"architecture"`
	MaxUses      int       `json:"max_uses"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Invitation struct {
	InvitationOptions
	ID  string `json:"id"`
	URL string `json:"url"`
}

func (s *Store) Invite(ctx context.Context, options InvitationOptions, actor string) (*Invitation, error) {
	now := time.Now()
	if !options.Scope.valid() || options.SiteID == 0 || (options.Platform != "windows" && options.Platform != "macos") || (options.Architecture != "amd64" && options.Architecture != "arm64") || options.MaxUses < 1 || options.MaxUses > 1000 || !options.ExpiresAt.After(now) || options.ExpiresAt.After(now.Add(7*24*time.Hour)) {
		return nil, ErrInvalid
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var origin string
	var siteID int
	err = tx.QueryRowContext(ctx, `SELECT a.public_origin,s.id FROM uem_agent_authorities a JOIN sites s ON s.tenant_sites=a.tenant_id WHERE a.tenant_id=$1 AND s.id=$2 AND a.expires_at>clock_timestamp()+INTERVAL '24 hours' FOR SHARE OF a,s`, options.TenantID, options.SiteID).Scan(&origin, &siteID)
	if err != nil {
		return nil, notFound(err)
	}
	id := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_invitations(id,tenant_id,site_id,token_hash,platform,architecture,max_uses,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, options.TenantID, siteID, digest([]byte(token)), options.Platform, options.Architecture, options.MaxUses, options.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, options.Scope, actor, "agent.invitation.create", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &Invitation{InvitationOptions: options, ID: id, URL: origin + "/enroll/desktop/" + token}, nil
}

// Claim atomically consumes one authorized use after both endpoint key proofs.
// A repeated proof with the same keys recovers the same public certificate and
// device ID while the invitation and identity remain active. No private device
// key is generated, accepted or persisted by this service.
func (s *Store) Claim(ctx context.Context, request enrollment.Request) (*enrollment.Response, error) {
	identity, err := enrollment.Validate(request)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var invitationID, platform, architecture string
	var scope Scope
	var maxUses, uses int
	var expires time.Time
	var revoked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT i.id,i.tenant_id,i.site_id,i.platform,i.architecture,i.max_uses,i.uses,i.expires_at,i.revoked_at FROM uem_agent_invitations i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id WHERE i.token_hash=$1 FOR UPDATE OF i FOR SHARE OF s`, digest([]byte(request.Invitation))).Scan(&invitationID, &scope.TenantID, &scope.SiteID, &platform, &architecture, &maxUses, &uses, &expires, &revoked)
	if err != nil {
		return nil, notFound(err)
	}
	if revoked.Valid || !expires.After(time.Now()) || platform != request.Platform || architecture != request.Architecture {
		return nil, ErrNotFound
	}
	response, err := claimedResponse(ctx, tx, invitationID, identity.KeyBinding)
	if err == nil {
		return response, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if uses >= maxUses {
		return nil, ErrNotFound
	}
	var caPEM, encrypted []byte
	var origin string
	err = tx.QueryRowContext(ctx, `SELECT public_origin,certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=$1 FOR SHARE`, scope.TenantID).Scan(&origin, &caPEM, &encrypted)
	if err != nil {
		return nil, notFound(err)
	}
	private, err := s.open(encrypted, fmt.Sprintf("%d/authority/key", scope.TenantID))
	if err != nil {
		return nil, err
	}
	defer clear(private)
	ca, signer, err := parseAuthority(caPEM, private)
	if err != nil {
		return nil, ErrUnavailable
	}
	id := uuid.NewString()
	certificate, certificateExpires, err := issueCertificate(ca, signer, id, identity.CertificateKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	publicDER, err := x509.MarshalPKIXPublicKey(identity.CertificateKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_identities(id,tenant_id,site_id,invitation_id,key_binding,certificate_key_hash,broker_key,platform,architecture,display_name,public_origin,certificate,authority_certificate,certificate_hash,certificate_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, id, scope.TenantID, scope.SiteID, invitationID, identity.KeyBinding, digest(publicDER), identity.BrokerKey, platform, architecture, request.DeviceName, origin, certificate, caPEM, digest(certificate), certificateExpires)
	if err != nil {
		// A previously registered key cannot create an identity in another scope.
		// Do not reveal which public key/constraint or existing device collided.
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrDenied
		}
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_agent_invitations SET uses=uses+1 WHERE id=$1`, invitationID); err != nil {
		return nil, err
	}
	if err = audit(ctx, tx, scope, "enrollment", "agent.identity.issue", id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return publicResponse(id, scope, origin, certificate, caPEM, certificateExpires), nil
}

func claimedResponse(ctx context.Context, tx *sql.Tx, invitationID, binding string) (*enrollment.Response, error) {
	var id, origin string
	var scope Scope
	var certificate, ca []byte
	var expires time.Time
	var revoked sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT id,tenant_id,site_id,public_origin,certificate,authority_certificate,certificate_expires_at,revoked_at FROM uem_agent_identities WHERE invitation_id=$1 AND key_binding=$2 FOR UPDATE`, invitationID, binding).Scan(&id, &scope.TenantID, &scope.SiteID, &origin, &certificate, &ca, &expires, &revoked)
	if err != nil {
		return nil, err
	}
	if revoked.Valid || !expires.After(time.Now()) {
		return nil, ErrDenied
	}
	return publicResponse(id, scope, origin, certificate, ca, expires), nil
}

func publicResponse(id string, scope Scope, origin string, certificate, ca []byte, expires time.Time) *enrollment.Response {
	return &enrollment.Response{Version: enrollment.Version, DeviceID: id, TenantID: scope.TenantID, SiteID: scope.SiteID, Endpoint: "wss://" + strings.TrimPrefix(origin, "https://") + "/agent-channel", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})), Authority: string(ca), ExpiresAt: expires}
}
