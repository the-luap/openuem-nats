# Signed desktop installation configuration

This package authenticates the configuration accompanying an unchanged signed
Windows/Mac installer. It complements `enrollment/artifacts`; it does not establish
trust in a downloaded key, authorize a server origin, install a package or issue
an identity by itself. The enrollment service and native bootstrap command must
integrate it with their existing invitation, catalog and protected-state checks.

A schema-1 configuration binds the expected HTTPS origin, organization/site
labels and numeric scope, limited invitation, exact platform/architecture,
issuance/expiry and original signed release envelope/digest. It is valid for at
most seven days, with five minutes of future-clock tolerance, and cannot outlive
the selected release. Expiry is exclusive. No endpoint key, CA private key or
release private key is included. The invitation remains a short-lived credential
and must not be logged or placed in a long-lived public configuration file.

The enrollment service signs the exact payload using a dedicated Ed25519
configuration key and the domain `openuem/desktop-bootstrap-configuration/v1`
followed by NUL. The envelope contains a key fingerprint, canonical unpadded
standard-base64 payload and signature. It has no public-key field. Its maximum
size is 96 KiB; the decoded payload is bounded to 48 KiB and the embedded release
envelope to 32 KiB. Both documents reject duplicate/case-aliased and unknown JSON
fields, trailing values, excessive nesting and invalid UTF-8. Signing also checks
that the supplied private key's seed and public half agree.

`Verify` requires an explicit `Trust` containing:

- An independently authorized expected server origin and actual endpoint target.
- One to eight configuration public keys independently bound to that origin, for
  example through verified HTTPS to an already authorized origin, or pins supplied
  by the trusted installer. An origin read solely from the configuration is not
  independent authorization; the native UI/operator must make that decision.
- One to eight separately pinned release public keys from the release pipeline.
  A configuration signer cannot approve installer bytes by signing its own release.
- The current persisted release checkpoint, or the zero checkpoint only for a
  genuinely new installation.

The two key rings must be distinct and contain no duplicate fingerprints.
Verification authenticates the configuration, checks origin/target, independently
verifies the embedded release under release keys and the checkpoint, and matches
its digest, expiry and supported artifact. It derives the exact download URL from
the authorized origin and selected release; no alternative download URL is trusted.
CA keys and HTTPS certificate keys are not substitutes for either signing role.

`Verified` keeps authenticated values private and returns copies. Before use,
recheck `ValidAt` against current time and the latest durable checkpoint. Verify
actual package bytes through `VerifyPackage` without reopening a replaceable path;
verify Authenticode or Developer ID/notarization separately. Persist the checkpoint
atomically with installation acceptance. Key-ring changes require re-verification;
an old verified object does not observe later trust changes.

The native enrollment flow must copy the verified invitation, target, release and
expected scope into protected pending state before its claim. Validate returned
scope against that expectation before publishing a ready identity. A signature
does not bypass server-side expiry, revocation, use limits or current-release
selection. Scanners may download a configuration without consuming an invitation.

Tests use independent configuration/release keys and non-executable package bytes.
They cover signature-role separation, independently selected origin/target, scope,
expiry, release mismatch/rollback, malformed envelopes, package changes and immutable
verified values. These are protocol tests, not signed-installer acceptance.
