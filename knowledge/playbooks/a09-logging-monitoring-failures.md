# A09:2021 — Security Logging and Monitoring Failures

## What it is
Attacks that succeed (or nearly succeed) with no trace — missing logs,
logs that aren't monitored/alerted on, or logs that don't capture enough
to reconstruct an incident.

This category can't be fully assessed from outside the target's network
— most of it is a design/process review, not a scan. The agent reports
what's observable from the outside and flags the rest as "needs a
process review with the target's team."

## Basic (externally observable signals)
- After a handful of deliberately failed logins, is there any visible
  behavior change (lockout, CAPTCHA, delay)? Its absence doesn't prove
  there's no logging, but its absence *and* no lockout together suggest
  monitoring may not be acted on in real time.
- Check whether error responses leak whether an event was logged (some
  apps echo a "reference ID" useful for support — note this as
  informational, not a vulnerability itself).

## What to ask the target's team (report as a recommendation, not a
finding you can confirm remotely)
- Are authentication failures, access-control failures, and
  input-validation failures logged with enough context (who, what,
  when, from where) to investigate later?
- Are logs centralized and alerted on, or do they just sit on disk?
- Is there a tested incident-response process, or would a breach only be
  discovered when a customer notices?

## Tools
Mostly observation of behavior under the other categories' testing
(A03/A07 in particular) rather than a dedicated tool.

## Remediation to report
Log authentication events, access-control denials, and server-side input
validation failures with sufficient context; centralize and alert on
them; and test the incident-response process at least annually.
