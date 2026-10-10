# D01 (extension) — OSINT Reconnaissance

Passive, public-information lookup -- but with a scope model that
differs from a01-a11's domain/CIDR checking, so read this carefully
before using these tools.

## The scope distinction that matters here
`email_harvest` maps cleanly onto scope.yaml: its target is a domain,
checked the normal way. `username_osint`, by contrast, queries hundreds
of third-party sites (github.com, twitter.com/x.com, instagram.com, and
so on) that will never individually appear in `allowed_domains` -- that
is expected and correct, this is public-information lookup akin to a
search engine, not an attack against those sites.

What actually needs authorization for `username_osint` is the
**subject**: the specific username/person being investigated must be
in scope for this engagement (an employee as part of an authorized
social-engineering-readiness assessment, or the organization's own
public-facing accounts). It is never run against an arbitrary third
party picked on a whim, a public figure out of curiosity, or anyone not
explicitly named in the engagement's authorization. `guardrails.py`
enforces this the same way it enforces everything else -- via
`authorize_local_action` keyed on the username -- but the plan itself
should never propose a lookup against a subject who hasn't been
explicitly named as in-scope.

## Basic
- `email_harvest(domain='example-lab.local', sources='crtsh,bing')` --
  key-free sources first; finds employee email address patterns and
  subdomains from certificate transparency logs and search engines,
  entirely passive (no direct contact with the domain's own
  infrastructure).
- `username_osint(username='<in-scope subject>')` -- only once the
  subject has been explicitly confirmed as part of the engagement (see
  above). Finds which platforms an account exists on, useful for
  mapping an organization's social-engineering attack surface (e.g. "do
  employees reuse the same username pattern across platforms in a way
  that makes spear-phishing easier").

## Intermediate
- Cross-reference `email_harvest` results against `secret_scan`/
  `deep_secret_scan` findings: a harvested email pattern plus a leaked
  credential dump elsewhere is a much stronger finding (credential-
  stuffing risk) than either alone.
- Cross-reference discovered subdomains from `email_harvest` back into
  the normal recon phase (`http_probe`, `tls_scan`) -- OSINT frequently
  surfaces forgotten/unlisted subdomains that the organization's own
  inventory missed, which is itself a finding (asset inventory gap,
  NIST CSF 2.0 ID.AM).

## Advanced
There is no exploitation tier for OSINT itself -- by definition it
only surfaces public information. If OSINT findings suggest a follow-up
(e.g. a harvested email used in a phishing-susceptibility test, or a
discovered subdomain probed further), that follow-up belongs to
whichever category playbook it actually falls under (A01-A11), with
that category's own approval gating, not this one.

## Tools
`email_harvest` (theHarvester), `username_osint` (Sherlock).

## Reporting notes (b01 cross-reference)
Breach pattern: Social Engineering (enabling condition) or
Miscellaneous Errors (unlisted asset discovery). ATT&CK: T1589 Gather
Victim Identity Information, T1594 Search Victim-Owned Websites, T1593
Search Open Websites/Domains. NIST CSF 2.0: ID.AM (asset management) for
discovered-but-unlisted assets, GV.RM for social-engineering risk
generally. PCI DSS v4.0: not applicable to OSINT findings themselves.
