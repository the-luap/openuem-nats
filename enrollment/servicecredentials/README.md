# Protected private-service inputs

`DatabaseURL(raw, path)` selects exactly one database credential source. Raw input
retains the existing driver's connection-string grammar. File input must be a
network `postgres://` or `postgresql://` URL with a host and database, at most
8192 printable non-space ASCII bytes. A single LF or CRLF terminator is allowed;
other whitespace, extra lines, fragments and malformed URL/query escaping fail.
The deployment remains responsible for selecting verified TLS and the intended
CA; this reader does not replace or weaken a configured TLS mode.

`EncryptionKey(raw, path)` returns the actual 32-byte AES input without base64/hex
decoding. File input is exactly 32 printable non-space ASCII bytes, plus an
optional single LF/CRLF. A raw key, when selected, must be 32 bytes. Both omitted
returns an empty value for services that do not process encrypted tasks; callers
that need encryption must require it in their deployment configuration.

Both functions reject competing raw/file sources and never fall back from a
missing or invalid file. Errors do not echo paths, URL values, passwords or keys.
File reads use `keyfile.Open`, requiring a bounded private regular file, rejecting
final symbolic links and checking the opened object's identity. Unix ownership
and permissions or native Windows ACL checks apply. Keep ancestor directories
trusted against replacement. Read-only inputs need no directory creation, writes,
permission changes or synchronization of their mount.

These APIs read existing credentials. They do not generate, rotate, publish or
change them, and do not connect to PostgreSQL or NATS. Tests cover exact output,
line endings, bounds, Unicode/control characters, source ambiguity, rejected
files, parser-error privacy and native protected-file creation.
