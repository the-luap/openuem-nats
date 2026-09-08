# Authenticated desktop installer manifests

This package defines the shared installer-release integrity boundary for the
console and endpoint bootstrap. It does not download files, sign native binaries,
prove Windows Authenticode trust or perform Apple notarization. Release pipelines
must complete and verify those platform steps before approving package bytes.

A schema-1 manifest describes one version and up to four Windows/Mac targets:
`windows` or `macos`, each with `amd64` or `arm64`. Windows supports `exe`/`msi`;
Mac supports `pkg`. No target is inferred or substituted. The exact filename is
`openuem-agent-<version>-<platform>-<architecture>.<format>`. Paths, URLs, encoded
separators and alternative filenames are rejected. Versions use three numeric
components, optionally followed by `-alpha.N`, `-beta.N` or `-rc.N`; numeric
components have no leading zeroes and are bounded to nine digits.

Each target binds a positive byte size of at most 512 MiB and a lowercase SHA-256
digest. The manifest also binds a positive sequence number that fits a PostgreSQL
bigint, publication time and expiry. Validity is at most thirty days, expiry is
exclusive, and future publication allows at most five minutes of clock skew.

Targets can additionally bind the installed agent executable with `agent_size`
and `agent_sha256`. Both must be present together, with a positive size of at most
512 MiB and a canonical lowercase SHA-256 digest. Hash the final native-signed
agent executable first, include those unchanged bytes in the installer, complete
installer signing/notarization, then hash and approve the final installer. The
manifest remains separate from the package, so no self-referential hash is needed.
`Verified.VerifyAgent` checks this distinct executable binding; it never uses the
installer's hash as a substitute. The native bootstrap must check the actual
installed executable before issuing/activating its individual identity.

Earlier preview manifests may omit both executable fields and remain readable
without changing their canonical encoding. They fail `VerifyAgent` and cannot
authorize installed-agent bytes through that API. Older clients that do not know
these optional fields reject manifests that include them; update those consumers
before approving such a release. Partial bindings, nulls, duplicates, case aliases
and malformed hashes are rejected even when the envelope signature is valid.

`Sign` authenticates the exact JSON payload using Ed25519 with the domain prefix
`openuem/desktop-installer-manifest/v1` followed by a NUL byte. The envelope carries
the raw payload and signature as canonical unpadded standard base64, and the
lowercase SHA-256 fingerprint of the public signing key. The envelope is limited
to 32 KiB and its decoded payload to 16 KiB. Both reject duplicate/case-aliased or
unknown fields, trailing JSON values, excessive nesting and invalid UTF-8.

`Verify` accepts only an explicit ring of one to eight pinned Ed25519 public keys.
It never trusts a key supplied by the envelope, an organization authority or a TLS
certificate as a release-signing key. Release private keys belong in the protected
release pipeline, not the console, endpoint, environment logs or downloads.

Persist `Verified.Checkpoint()` atomically with acceptance. Reject a lower sequence
and a different payload at an already accepted sequence; permit an identical
retry. An emergency return to older binaries requires a newly approved sequence.
Serialize concurrent acceptance so an older request cannot overwrite a newer
checkpoint. Restoring a database/checkpoint backup is also a trust-state operation;
these helpers do not provide storage or authorize resetting that state.

The verified object keeps its authenticated metadata private and returns copies.
Select an exact platform/architecture, recheck `ValidAt` against current time and
the latest persisted checkpoint before use, then call `VerifyPackage` on the
actual installer bytes. Package reads stop at the signed size plus one byte.
Serve/install that verified file without reopening a replaceable path. Callers
must provide a bounded reader or a transport with cancellation and deadlines.
After changing the trusted key ring, reverify saved envelopes under the new ring;
an old in-memory verified object does not observe configuration changes.

The console and native client now use the release catalog, approved download routes
and per-invitation target binding. Installed-executable admission, native packaging
and the release-signing workflow still require integration. Most test package and
agent bytes are non-executable fixtures; passing protocol tests is not native
signing or physical installation acceptance.
