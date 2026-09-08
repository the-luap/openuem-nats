package enrollment

// CommandConsumerWork is leased private-service work. Device-supplied data must
// never determine a consumer name, command filter, revision or lease token.
type CommandConsumerWork struct {
	DeviceID string
	Active   bool
	Revision int64
	LeaseID  string
}
