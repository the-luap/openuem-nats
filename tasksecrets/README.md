# Task secret storage contract

The console and worker must use the same immutable version of this package.
Upgrade every worker before enabling console SSH-secret writes or migration;
older workers pass stored SSH passphrases directly to Ansible and cannot read the
new format. Stop old workers during the transition. Agents receive the existing
plaintext configuration fields over the existing authenticated transport, so this
format does not require an agent protocol change. Generated configurations must
never be logged or retained as migration evidence.

SSH passphrases use AES-256-GCM with a random 12-byte nonce and a 16-byte tag.
The 32-byte raw master key is expanded with HKDF-SHA256 (empty salt, info equal to
`openuem:task-secret:ssh:v1:`). That prefix is also the authenticated additional
data. Storage is the prefix followed by canonical, unpadded URL-safe base64 of
nonce plus ciphertext and tag. Binding is to this field and version, deliberately
not to task/profile IDs: authorized task and profile clones can copy ciphertext.
It does not prevent a database writer from moving ciphertext between tasks.

The whole `openuem:task-secret:` namespace is reserved. Unknown versions, damaged
encoding, wrong keys and authentication failures are errors, never plaintext
fallbacks. An old literal passphrase beginning with that reserved prefix must be
explicitly replaced through the editor before migration. New writes always seal
literal input, including input that resembles an envelope.

Local account passwords retain the historical unmarked hexadecimal AES-GCM
format for compatibility. A hexadecimal value of at least 28 decoded bytes must
authenticate. Short hex values are safe legacy plaintext. The historical format
cannot distinguish a long hex plaintext password from damaged ciphertext;
explicitly replace ambiguous values instead of automatically double-encrypting
them. Legacy AES key sizes remain readable; SSH encryption requires 32 bytes.

Plaintext is bounded to 16 KiB, valid UTF-8, without NUL. Stored-size limits include
encryption overhead. Empty values remain empty, and verified encrypted values
are unchanged by repeated migrations. Errors contain no values or key material.
Temporary plaintext byte slices are cleared; Go string lifetimes cannot provide
a reliable memory-erasure guarantee. The package provides neither key rotation
nor a key backup/recovery mechanism.
