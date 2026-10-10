# C04 (extension) — API Security & Schema-Based Fuzzing

Overlaps with A03 (injection) and A01 (access control) in root cause,
but the testing *method* here is distinct enough to warrant its own
playbook: generating many schema-conformant requests automatically
rather than hand-crafting each probe, per the OWASP API Security Top 10.

## What it is
Modern APIs (REST with OpenAPI, GraphQL) publish a machine-readable
schema of every endpoint, parameter, and type. That schema can drive
automated test generation far beyond what manual probing covers in the
same time, surfacing edge cases (boundary values, unexpected types,
missing-required-field handling) a human wouldn't think to try.

## Basic
- Locate the schema: `/openapi.json`, `/swagger.json`, `/graphql`
  (introspection query), or check for a developer-docs page linking one.
  A schema that's supposed to be internal-only but is still publicly
  fetchable is itself an A05 (security misconfiguration) finding worth
  noting separately.
- `api_fuzz_test(schema_url='<schema URL>', max_examples=20)` -- starts
  conservative. This checks for schema-conformance violations and
  unhandled 5xx server errors, which often indicate unvalidated input
  reaching something fragile (a database call, a type coercion) --
  exactly the kind of thing that, followed up manually, turns into an
  A03 injection or A04 insecure-design finding.

## Intermediate
- Read the fuzzer's output for the *shape* of each failure, not just
  "it failed": a 500 error on a specific malformed field often points
  directly at which parameter and which endpoint to manually probe next
  with `http_request`, following A03's injection playbook from there.
- Authorization-by-endpoint-ID testing (A01's IDOR pattern) doesn't come
  for free from schema fuzzing alone -- schema fuzzing finds "what makes
  the server error," not "what makes the server leak someone else's
  data." Pair api_fuzz_test's structural findings with manual IDOR
  testing per a01-broken-access-control.md for full coverage.
- GraphQL-specific: check whether introspection is enabled in
  production (it often shouldn't be -- it hands an attacker the entire
  schema including unused/internal fields) and whether query depth/
  complexity limiting exists (its absence enables a cheap
  resource-exhaustion vector via deeply nested queries -- report the
  absence as a finding, never actually send a resource-exhaustion query
  yourself, since that risks denial of service, which is never
  permitted by this agent regardless of scope.yaml).

## Advanced (approval-gated)
- If fuzzing surfaces a parameter that looks injectable, confirming it
  follows A03's playbook exactly (sql_injection_test, detect-only
  first, dump only with approval) -- api_fuzz_test itself never
  attempts injection payloads beyond what the schema defines as a valid
  request shape.

## Tools
`api_fuzz_test` (Schemathesis). Remember its documented limitation:
guardrails' rate limiting is checked once per tool call, not once per
individual generated request -- keep `max_examples` low and prefer
running it against targets whose rules_of_engagement comfortably
tolerate a short automated burst.

## Reporting notes (b01 cross-reference)
Map findings to whichever downstream category they actually represent
(A01, A03, A04, A05) rather than inventing a separate framework mapping
for "API findings" generically -- an IDOR found via an API is still an
A01 finding with A01's NIST/ISO/CIS/PCI mapping, the API was just how
you found it.
