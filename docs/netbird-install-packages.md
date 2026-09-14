# Exact NetBird Unix package descriptors

`netbirdinstall.Package` binds one immutable organization approval to its exact
Unix platform, CPU architecture, package format, package identity/version, HTTPS
source, byte length and SHA-256. Linux descriptors accept DEB/RPM client packages
named `netbird` for amd64, arm64 or 386. macOS descriptors accept PKG installers
with receipt identity `io.netbird.client` for amd64 or arm64. Windows continues to
use the existing authenticated Windows software protocol.

The package version is the exact native package/receipt version, not inferred
from an inventory name or a CLI version string. The format, CPU and package
identity cannot be substituted at download time. All fields, including the
approval UUID, organization and private source URL, enter the canonical digest.
Unknown fields, aliases, duplicates, null values, missing fields, noncanonical
integers, invalid UTF-8 and oversized JSON are rejected. Package bytes have a
512 MiB upper bound. Sources require HTTPS and the exact format suffix, with no
userinfo or fragment. Display formatting and incidental JSON marshaling conceal
the URL; `Encode` is the explicit wire/storage API.

The descriptor is a preparation contract, not execution authority or an
independent publisher signature. Callers must authenticate the immutable approval
and current recipient, encrypt private source data when stored, enforce current
scope and validity, retain a durable attempt before mutation and verify native
package identity and requested state. A digest match alone does not establish
those facts. Existing NetBird command versions do not accept installer commands;
the console's [organization approval storage](https://github.com/the-luap/openuem-console/blob/fc5a2ae12c5cb47b47e1ff453e2d84b8ee09f895/docs/netbird-package-approvals.md)
and the agent's native preflight exist, but authenticated installer delivery,
durable admission, native execution and lifecycle recovery still need integration
before installation can be enabled. This documentation update does not change the
descriptor or require consumers to replace their existing immutable module pin.

The official [macOS installation documentation](https://docs.netbird.io/get-started/install/macos)
distinguishes signed official PKG installers from unsigned GitHub binary tarballs
and identifies the `io.netbird.client` receipt. Preparation must preserve native
signature checks; unsigned binary extraction is not a supported replacement.

Tests cover the target matrix, immutable approval/scope digests, private formatting,
invalid sources, exact field grammars and seeded fuzz round trips. They use inert
descriptors and do not download or execute a NetBird package.
