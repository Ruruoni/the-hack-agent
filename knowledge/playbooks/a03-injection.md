# A03:2021 — Injection (SQL, NoSQL, OS command, LDAP, XSS)

## What it is
Untrusted input reaches an interpreter (SQL engine, shell, template
engine, browser DOM) and changes its intended behavior.

## Basic
- Enumerate every input: URL params, form fields, JSON body fields,
  headers (`User-Agent`, `X-Forwarded-For`, `Referer` are frequently
  unvalidated), and cookies.
- Send a single harmless probe per input and diff the response: a quote
  (`'`), a `{{7*7}}` template-injection probe, and an HTML tag
  (`<b>probe</b>`) — look for SQL errors, template evaluation (`49`
  appearing), or unescaped reflection.
- `web_vuln_scan` (nuclei tags: `sqli`, `xss`, `rce`, `injection`) across
  all mapped endpoints first — it's cheap and catches the obvious cases
  before manual probing.

## Intermediate — SQL injection
- `sql_injection_test` (sqlmap) in **detect-only** mode
  (`--batch --level=1 --risk=1`, no `--dump`, no `--os-shell`) against
  each parameter that returned a DB-flavored error or behaved differently
  under the quote probe.
- Boolean-based blind: compare `id=1 AND 1=1` vs `id=1 AND 1=2` response
  length/content.
- Time-based blind only as a last resort and only briefly — `SLEEP()`
  payloads are easy to turn into an accidental DoS if looped; a single
  comparison (5s vs 0s) is enough to confirm, don't automate a full
  extraction this way.

## Intermediate — XSS
- Reflected: does the quote/tag probe above come back unescaped in the
  HTML response? Confirm with a non-executing marker
  (`"><svg onload=alert(1)>`) rendered but not auto-run in your own
  probe — do not rely on an actual alert firing against anyone but your
  own test browser/session.
- Stored: submit a unique, inert marker string into every input that
  persists (profile fields, comments) and check if it reflects
  *unescaped* elsewhere in the app (admin view, another user's view).
- DOM-based: check client-side JS sinks (`innerHTML`, `document.write`,
  `eval`) fed by `location.hash`/`location.search` — `sast_scan` with a
  JS-focused ruleset catches many of these statically if source is
  available.

## Intermediate — Command/OS injection
- Any parameter that plausibly reaches a shell (filenames, "ping this
  host" diagnostic tools, export/convert features): probe with command
  separators (`; id`, `| id`, `` `id` ``) using a harmless, observable
  command (`id`, `whoami`, `sleep 1`) — never a destructive one — and
  check response timing/content for evidence of execution.

## Advanced (approval-gated)
- SQLi data extraction: `sql_injection_test(dump=True)` is flagged
  `exploitation` and blocked on human approval regardless of this
  playbook — propose extracting the minimum needed (e.g. one row, or just
  `SELECT version()`), never a full table.
- Command injection PoC: execute one harmless, non-persistent command
  (`id`) to confirm, never a reverse shell or persistence mechanism.

## Tools
`web_vuln_scan`, `sql_injection_test`, `http_request` (manual probes),
`sast_scan` (for source-available DOM-XSS/taint review).

## Remediation to report
Parameterized queries/prepared statements (never string-concatenated
SQL), context-aware output encoding for XSS, strict input allow-lists,
and avoiding shell invocation with user input entirely (use library
calls, not `system()`/`exec()`).
