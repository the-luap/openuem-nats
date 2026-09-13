# NetBird profile state

`Netbird.ProfileDetails` adds optional ID, display name and active state to the
legacy `Profiles` handle projection. Existing decoders can keep using `Profiles`.
An empty ID means the client identifies profiles by their legacy unique names.
Current IDs and duplicate display names stay separate, and labels never become
command arguments.

`netbirdstate` validates at most 256 entries, 256-byte UTF-8 display names and
128-byte ASCII IDs. Duplicate handles, multiple active profiles, control
characters and malformed data fail closed. `Encode` retains structured profiles
in the existing text column using a versioned JSON prefix; commas in names are
data. `Decode` also reads existing comma-separated rows. Old comma-containing
names cannot be reconstructed from those legacy rows; a new report replaces
them. The older collector's single empty name is normalized to an empty list.
The stored representation is limited to one MiB, including JSON expansion.

Profile metadata is agent-reported inventory. Neither IDs nor active state prove
provider-peer ownership or authorize a device command. Durable command review,
source binding and provider association remain separate requirements.
