# C01 (extension) — Cloud Security (AWS/Azure/GCP/Kubernetes)

Not part of OWASP's Top 10, and not a network-target category like
a01-a11 -- this playbook covers auditing an organization's **own** cloud
account configuration, which requires credentials for that account (you
cannot and must not try to audit a cloud account you don't hold
credentials for; there's no scanning-your-way-in here).

## What it is
Cloud misconfiguration (overly permissive IAM, public storage, disabled
logging, unencrypted resources) is one of the most common real-world
breach causes, and is detectable almost entirely through the provider's
own configuration APIs -- no exploitation needed, just reading config
and comparing against known-safe baselines (CIS Benchmarks for AWS/
Azure/GCP).

## Basic
- Confirm which account/profile is being audited and that it belongs to
  the organization requesting the engagement -- `cloud_posture_scan`
  requires a local credential profile already configured in the
  environment; it is never pointed at a profile you don't recognize.
- Run `cloud_posture_scan(provider='aws', profile_or_account='<profile>')`
  (or azure/gcp/kubernetes) for a broad baseline sweep against CIS
  Benchmark-aligned checks: public S3/storage buckets, overly permissive
  security groups (0.0.0.0/0 on sensitive ports), root/account-owner
  access keys still active, MFA not enforced on privileged accounts,
  logging (CloudTrail/Activity Log/Audit Log) disabled or not centralized.

## Intermediate
- IAM review: look specifically for wildcard actions (`"Action": "*"`)
  or wildcard resources (`"Resource": "*"`) on roles/policies attached
  to anything internet-facing or third-party-integrated.
- Encryption review: unencrypted storage volumes/buckets/databases,
  especially any holding customer or payment data.
- Network review: security groups/NSGs allowing unrestricted inbound
  on management ports (22, 3389, database ports) from 0.0.0.0/0.
- Narrow a follow-up run with `checks=` to drill into one finding
  category once the broad sweep identifies where the real risk is.

## Advanced (approval-gated)
- Confirming that an overly permissive IAM role is *actually*
  assumable/exploitable from outside the account (e.g. via a trust
  policy that allows an external account) is itself still within
  passive_recon (reading policy documents), but actually assuming that
  role or using resulting credentials to access data is exploitation --
  propose it, don't do it without separate approval.

## Tools
`cloud_posture_scan` (Prowler).

## Reporting notes (b01 cross-reference)
Cloud misconfiguration findings map unusually cleanly onto CIS Controls
v8 (Control 3 Data Protection, Control 4 Secure Configuration, Control 6
Access Control, Control 12 Network Infrastructure) and onto PCI DSS v4.0
directly if the account hosts any part of a CDE (Requirements 1, 3, 7,
8, 10 all have cloud-native equivalents). NIST CSF 2.0's PR.PS and
PR.AA functions, and ISO 27001:2022's A.8.9 (Configuration Management),
also apply almost every time. Breach pattern is usually Security
Misconfiguration or Miscellaneous Errors; ATT&CK's cloud-specific
techniques (T1580 Cloud Infrastructure Discovery, T1526 Cloud Service
Discovery, T1619 Cloud Storage Object Discovery) are the right family to
cite rather than forcing a traditional network-intrusion technique.
