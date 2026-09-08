package registry

import (
	"context"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// HardwareReady lets a rolling deployment omit new RPCs until their schema exists.
// The legacy inventory report remains unchanged and works with older workers.
func (s *AccessStore) HardwareReady(ctx context.Context) bool {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_hardware') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}

// RecordHardware is for the worker that already proved the request subject's NKey
// identity. It rechecks that identity under the same row lock as revocation, with
// no CA/master key and no plaintext association token in the database.
func (s *AccessStore) RecordHardware(ctx context.Context, identity Identity, input enrollment.HardwareInventory) error {
	h, err := enrollment.NormalizeHardware(input)
	if err != nil || h.AgentID != identity.ID || identity.Platform != "macos" {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT i.id FROM uem_agent_identities i JOIN sites s ON s.id=i.site_id AND s.tenant_sites=i.tenant_id
 WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 AND i.platform='macos' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() FOR UPDATE OF i FOR SHARE OF s`, identity.ID, identity.TenantID, identity.SiteID).Scan(&id)
	if err != nil {
		return ErrDenied
	}
	var changed bool
	err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM uem_agent_hardware WHERE device_id=$1 AND model=$2 AND serial=$3 AND platform_uuid=$4 AND provisioning_udid=$5)`, id, h.Model, h.Serial, h.PlatformUUID, h.ProvisioningUDID).Scan(&changed)
	if err != nil {
		return err
	}
	var challenge, device, hash any
	if h.Binding != nil {
		challenge, device, hash = h.Binding.ChallengeID, h.Binding.DeviceID, digest([]byte(h.Binding.Token))
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_hardware(device_id,tenant_id,site_id,model,serial,platform_uuid,provisioning_udid,binding_challenge_id,binding_device_id,binding_token_hash)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(device_id) DO UPDATE SET model=EXCLUDED.model,serial=EXCLUDED.serial,platform_uuid=EXCLUDED.platform_uuid,provisioning_udid=EXCLUDED.provisioning_udid,binding_challenge_id=EXCLUDED.binding_challenge_id,binding_device_id=EXCLUDED.binding_device_id,binding_token_hash=EXCLUDED.binding_token_hash,observed_at=clock_timestamp()`, id, identity.TenantID, identity.SiteID, h.Model, h.Serial, h.PlatformUUID, h.ProvisioningUDID, challenge, device, hash)
	if err != nil {
		return err
	}
	if changed {
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_agent_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'hardware.recorded',$4)`, identity.TenantID, identity.SiteID, "device:"+id, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
