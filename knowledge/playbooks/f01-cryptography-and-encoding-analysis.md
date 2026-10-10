# F01 (extension) — Cryptography & Encoding Analysis

A utility playbook, not a vulnerability category of its own — this
supports every other playbook whenever a finding involves obfuscated,
encoded, or encrypted data. `crypto_toolkit` is pure local computation
on text you already have: no network, no target, no approval needed.

## What it's for
Data found during an engagement is often not immediately readable:
Base64-encoded tokens in headers, hex-encoded payloads in a captured
request, Morse/Caesar-style obfuscation in a CTF-style challenge, an
XOR-obfuscated string in a binary (cross-reference with
`binary_analysis`/C02), or a hash whose algorithm needs identifying
before deciding whether `hash_crack` (E01, approval-gated) is even
worth proposing.

## Basic — recognize and decode
- Base64: look for strings ending in `=`/`==` padding, or a character
  set limited to `[A-Za-z0-9+/=]` — `crypto_toolkit(operation=
  'base64_decode', text=...)`.
- Hex: an even-length string of only `0-9a-fA-F` — `crypto_toolkit
  (operation='hex_decode', text=...)`.
- Binary: space-separated 8-bit groups of `0`/`1` —
  `crypto_toolkit(operation='binary_decode', text=...)`.
- ROT13/Caesar: readable-looking text that isn't quite readable, common
  in CTF-style challenges — try `rot13` first (it's the fixed-shift-13
  special case), then `caesar_decode` across a few shift values if that
  doesn't work.
- Morse: a sequence of only `.`, `-`, and spaces — `crypto_toolkit
  (operation='morse_decode', text=...)`.

## Intermediate — identify before acting
- `identify_hash` on any hex string that looks like a hash (fixed
  length, no other pattern) before proposing `hash_crack` (E01) — this
  tells you which `-m` mode Hashcat needs and whether cracking is even
  plausible for that algorithm (e.g. a correctly-salted bcrypt hash
  won't show up as a clean fixed-length hex string this tool
  recognizes at all — note that explicitly rather than guessing a mode).
- XOR-obfuscated data (common in simple malware/CTF payloads): if you
  have a hypothesis about the key (a short string, often visible
  elsewhere in the same binary/file), `crypto_toolkit(operation='xor',
  text=<hex>, key=<hypothesis>)` and check whether the result becomes
  readable. If not, it's either a different key or layered with
  another encoding — decode in whatever order the data was likely
  encoded, not randomly.

## Advanced
There is no exploitation tier here — this playbook only decodes/
analyzes data you already have. If decoding reveals something
actionable (a credential, a hash worth cracking, an embedded URL),
route it to the category that actually applies (A02 for credentials,
E01 for hash cracking, A10 for an embedded internal URL) rather than
treating "I decoded something" as a finding in itself.

## Tools
`crypto_toolkit` (base64/hex/binary/Caesar/ROT13/Morse/XOR/hash
identification, all local).

## Reporting notes (b01 cross-reference)
Decoding/analysis steps are rarely the finding themselves — they're
how you got to one. Report whatever the decoded content actually
reveals, mapped to its own category, and mention the decoding step
only as part of the evidence trail (e.g. "the token observed in the
Authorization header decodes via base64 to a JSON object containing
the session's internal user ID in cleartext").
