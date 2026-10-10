# C02 (extension) — Container & Kubernetes Security

Two distinct sub-cases with two different tools and two different
scope models: scanning a container image/IaC file (local, no network
target) versus probing a live cluster (a real network target that must
be in `scope.yaml`).

## Basic -- image and IaC scanning (local, no network target)
- `container_image_scan(target='<image>:<tag>')` against any image the
  organization builds or deploys -- finds known-CVE vulnerable OS
  packages and language dependencies baked into the image.
- `container_image_scan(target='<path>', scan_type='config')` against a
  Dockerfile, Kubernetes manifests, Helm chart, or Terraform directory
  -- finds misconfigurations before they're ever deployed: containers
  running as root, missing resource limits, privileged mode enabled,
  secrets baked into image layers, overly permissive RBAC in manifests.
- Treat secrets found in image layers the same as a `secret_scan` hit --
  they must be treated as already exposed and rotated, not just noted.

## Intermediate -- live cluster probing (network target, scope-checked)
- `k8s_live_scan(target='<cluster API endpoint or CIDR>')` -- only
  against a cluster explicitly in `scope.yaml`'s allowed_domains/
  allowed_cidrs, same as any other active_scanning tool. Finds exposed
  Kubernetes API servers, exposed kubelet read-only ports, anonymous
  authentication enabled, exposed etcd, and known CVEs in the cluster's
  own components.
- A cluster that allows anonymous/unauthenticated API access at all is
  a Critical finding on its own, independent of anything else found --
  report it immediately rather than continuing to explore with that
  access.

## Advanced (approval-gated)
- If kube-hunter or manual follow-up identifies a path to actually
  execute code inside a pod or escalate to node access (e.g. via an
  exposed, unauthenticated kubelet API), confirming it is the same
  discipline as A03's command-injection PoC: one harmless, observable
  action, not a persistence mechanism, and only with explicit approval.
- A container escape finding (breaking out of a container to the host
  node) is especially high-impact -- treat confirming it the same as
  A08's insecure-deserialization RCE: report the structural finding
  first, propose confirmation separately.

## Tools
`container_image_scan` (Trivy, local), `k8s_live_scan` (kube-hunter,
network target).

## Reporting notes (b01 cross-reference)
CIS Controls v8 Control 16 (Application Security) and Control 4 (Secure
Configuration) cover most findings here; there is also a dedicated CIS
Kubernetes Benchmark worth citing by name if the organization already
references it. NIST CSF 2.0 PR.PS and PR.IR (network segmentation --
cluster network policy gaps belong here). ISO 27001:2022 A.8.9 and
A.8.20/A.8.22 for network segregation. PCI DSS v4.0 Requirement 1/2/6 if
the cluster is CDE-adjacent. Breach pattern is typically Security
Misconfiguration or, for a confirmed escape/exposed API, System
Intrusion. ATT&CK has a growing container-specific technique set:
T1610 Deploy Container, T1611 Escape to Host, T1613 Container and
Resource Discovery.
