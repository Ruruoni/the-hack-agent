# A04:2021 — Insecure Design

## What it is
Missing or ineffective security controls by design — not a bug in an
implementation, but a gap in the threat model itself (e.g. no rate
limiting on password reset, business logic that can be abused).

This category is mostly found by *thinking*, not scanning — use the
other categories' tool output as raw material and reason about abuse
cases.

## Basic
- Read the app's flows (signup, checkout, password reset, referral/
  coupon systems) and ask: "what happens if a user does this out of
  order, twice, or with a negative/zero value?"
- Check for missing rate limiting on sensitive actions: password reset
  requests, OTP verification, login attempts (`http_request` sending a
  handful of repeated requests — a handful, not a flood; this is
  confirmation, not load testing, and `max_requests_per_second` in
  `scope.yaml` still applies).

## Intermediate
- Business-logic abuse: can a coupon be applied multiple times, can
  negative quantities reduce a price, can a "free trial" be restarted by
  re-registering with a plus-addressed email (`user+1@example.com`)?
- Workflow bypass: can a later step in a multi-step process (e.g.
  checkout confirmation) be called directly, skipping payment or
  verification steps?
- Client-side trust: does the server re-validate price/quantity/role sent
  from the client, or does it trust whatever the client last posted?

## Advanced (approval-gated)
- Demonstrating a business-logic flaw with real impact (e.g. completing
  one checkout at an altered price) requires explicit approval since it
  writes state on the target — propose the exact single transaction you'd
  run and why it proves the flaw, don't chain it into repeated abuse.

## Tools
Mostly manual reasoning over `http_request` traces; cross-reference
findings from A01 (access control) and A03 (injection) since insecure
design often shows up as "the other categories had no control to catch
this in the first place."

## Remediation to report
Threat-model the abuse case explicitly, add server-side validation for
every business rule (never trust client-sent price/quantity/role), rate
limit sensitive flows, and make multi-step workflows enforce step order
server-side.
