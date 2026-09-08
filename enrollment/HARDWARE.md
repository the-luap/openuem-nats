# Mac hardware evidence protocol

An individually enrolled Mac can send version 1 `HardwareInventory` on its own
`uem.v1.agent.<device-id>.request.hardware` subject. The broker binds that subject
to the enrollment's NKey. The worker validates the JSON, rejects a different body
identity, and calls `AccessStore.RecordHardware` without holding the CA master
key. The store rechecks the active Mac identity, certificate expiry and current
site ownership while locking the identity against concurrent revocation.

This is a separate RPC. The ordinary `AgentReport` JSON has no additional fields,
so older workers can continue decoding it strictly. An agent sends the new RPC
only after receiving `hardware_inventory_version: 1` in its individual remote
configuration. Older configurations omit the field. Deploy registry migration
003 and the updated broker authorization service before the updated worker;
deploy the agent last. Reconnect devices after updating broker permissions.
Workers must omit the capability when the hardware schema is unavailable.

The report distinguishes the installation UUID, hardware platform UUID and
optional provisioning UDID. A serial number alone is not proof that an agent and
an MDM enrollment control the same endpoint. `MacBindingProof` is a random,
256-bit challenge delivered through MDM in the system managed-preferences domain
`eu.openuem.device-binding`. Only the separately authenticated hardware RPC may
return it. Never log the proof, expose it in inventory views, or include it in
the ordinary report. The registry stores only the SHA-256 hash of the canonical
base64url token, together with the challenge and native device IDs.

An accepted observation produces `HardwareReceipt {version: 1, ok: true}` only
after commit. The worker must not return this receipt for an error. Repeated
observations refresh `observed_at`; hardware changes produce an audit receipt in
the same transaction. Omitting a binding proof clears the previous proof. A
consumer must verify both current management identities, organization/site,
fresh hardware, the MDM challenge lifecycle and hardware consistency before
creating an association. This table does not create an association or confer
any device-action permission by itself.
