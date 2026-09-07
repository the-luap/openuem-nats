package enrollment

import "time"

// Response contains public certificates and the identity selected by the server.
// The endpoint retains both private keys locally and verifies this certificate
// matches its key before installing the individual connection configuration.
type Response struct {
	Version     int       `json:"version"`
	DeviceID    string    `json:"device_id"`
	TenantID    int       `json:"tenant_id"`
	SiteID      int       `json:"site_id"`
	Endpoint    string    `json:"endpoint"`
	Certificate string    `json:"certificate"`
	Authority   string    `json:"authority"`
	ExpiresAt   time.Time `json:"expires_at"`
}
