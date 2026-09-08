package bootstrap

import (
	"context"
	"io"
	"time"

	"github.com/open-uem/nats/enrollment"
)

// DownloadPackage uses only this configuration's exact origin/release/target.
// The native client must have independently authorized that origin. Destination
// is private staging; failures may leave untrusted bytes and must not be installed.
// Native signatures and the latest durable checkpoint remain caller checks.
func (v *Verified) DownloadPackage(ctx context.Context, client *enrollment.HTTPClient, destination io.Writer) error {
	if v == nil || v.release == nil || client == nil {
		return ErrInvalid
	}
	if client.Origin() != v.config.Origin {
		return ErrTarget
	}
	checkpoint := v.release.Checkpoint()
	if err := v.ValidAt(time.Now(), checkpoint); err != nil {
		return err
	}
	if err := client.DownloadPackage(ctx, v.release, v.config.Platform, v.config.Architecture, destination); err != nil {
		return err
	}
	return v.ValidAt(time.Now(), checkpoint)
}
