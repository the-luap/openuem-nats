package enrollment

import (
	"context"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/open-uem/nats/enrollment/artifacts"
)

const packageDownloadTimeout = 15 * time.Minute

// DownloadPackage streams one independently verified release target through the
// exact same-origin download route. It verifies size/hash and release lifetime;
// callers must separately authorize release pins and the persisted checkpoint.
// The destination must be private staging, never an executable installation path.
// A failure may leave partial/untrusted bytes (at most signed size plus one); the
// caller must discard them. Native OS signature verification is still required.
// Writers must return promptly; a context cannot interrupt an arbitrary io.Writer.
func (c *HTTPClient) DownloadPackage(ctx context.Context, release *artifacts.Verified, platform, architecture string, destination io.Writer) error {
	if ctx == nil || release == nil || destination == nil {
		return artifacts.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checkpoint := release.Checkpoint()
	if err := release.ValidAt(time.Now(), checkpoint); err != nil {
		return err
	}
	artifact, err := release.Select(platform, architecture)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, packageDownloadTimeout)
	defer cancel()
	path := "/enroll/desktop/releases/" + release.Digest() + "/" + platform + "/" + architecture
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return ErrEnrollmentTransport
	}
	request.Header.Set("Accept", "application/octet-stream")
	// Reuse the owned TLS transport, redirect policy and connection budget while
	// giving this bounded stream its own timeout; do not mutate the shared client.
	client := *c.client
	client.Timeout = packageDownloadTimeout
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrEnrollmentTransport
	}
	defer response.Body.Close()
	if err := responseStatusError(response.StatusCode); err != nil {
		return err
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" || len(params) != 0 || len(response.Header.Values("Content-Type")) != 1 || len(response.Header.Values("Content-Encoding")) != 0 || (response.ContentLength >= 0 && response.ContentLength != artifact.Size) {
		return artifacts.ErrPackage
	}
	if err := release.VerifyPackage(platform, architecture, io.TeeReader(response.Body, destination)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return artifacts.ErrPackage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return release.ValidAt(time.Now(), checkpoint)
}
