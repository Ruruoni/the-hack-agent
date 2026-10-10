# A07:2021 — Identification and Authentication Failures

## What it is
Weaknesses in login, session management, or credential handling —
formerly "Broken Authentication".

## Basic
- Check login form for: missing rate limiting / account lockout, whether
  error messages distinguish "no such user" from "wrong password" (user
  enumeration), and whether the form is served over HTTPS.
- Check session cookies: `Secure`, `HttpOnly`, `SameSite` attributes via
  `http_probe`/`http_request` response headers.
- Check for session token predictability — if tokens aren't obviously
  random (sequential, timestamp-based), note it; don't try to actually
  predict and hijack one without approval.

## Intermediate
- Session fixation: does the session ID stay the same across
  login/logout, or does a fresh one get issued on login? (Capture the
  cookie before and after authenticating with a throwaway test account.)
- Logout effectiveness: does the session token still work on a protected
  endpoint after logout? (Use only your own test session.)
- `jwt_analyze` on any JWT used for auth: check `alg` (flag `none` or
  weak HMAC), check for sensitive data in the unencrypted payload
  (base64 is not encryption), check expiry (`exp`) is set and enforced.
- Password policy: does the app reject common/weak passwords
  (`password123`) at signup? Check this by attempting signup with one
  throwaway test account, not a brute-force loop.
- MFA: if present, does it have a bypass (e.g. the pre-MFA session token
  alone still grants access to protected endpoints)?

## Advanced (approval-gated)
- Credential testing (brute force, password spraying, credential
  stuffing) is in `scope.yaml: require_human_approval_for` —
  `guardrails.py` blocks it without explicit approval. Even when
  approved, keep it to a small, clearly-bounded test (a short
  common-password list against one test account you control), never
  a real user's account, and respect `max_requests_per_second`.
- JWT forgery PoC (e.g. `alg: none` or a cracked HMAC secret from
  `jwt_analyze`): demonstrate with one forged token used once, not
  repeated use beyond the proof.

## Tools
`http_probe`, `http_request`, `jwt_analyze`.

## Remediation to report
Rate-limit and lock out after failed attempts, generic error messages
that don't reveal user existence, rotate session IDs on privilege
change, `HttpOnly`/`Secure`/`SameSite` cookies, strong `alg` enforcement
and signature verification on JWTs, and a real password policy.
