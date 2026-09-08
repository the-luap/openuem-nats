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

The release-signing workflow, persisted console catalog, approved public download
routes, per-invitation artifact selection and endpoint consumption are subsequent
integration steps. Test installer bytes are deliberately non-executable fixtures;
passing these tests is not native signing or physical installation acceptance.
