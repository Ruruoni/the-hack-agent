"""
security_agent — an authorization-gated, self-reporting recon/scan agent.

This package is deliberately separate from `backend/app/agents`, which is
CyberFactory's internal swarm for testing apps CyberFactory itself generates
inside isolated Docker containers. `security_agent` is the general-purpose,
model-driven agent discussed for testing *external, explicitly authorized*
targets listed in `scope.yaml` at the repo root.

Every capability here is guarded by `security_agent.guardrails`, which reads
`scope.yaml` and refuses anything outside it — in code, not by trusting the
model's judgment.
"""
