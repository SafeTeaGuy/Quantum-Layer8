# Quantum-Layer8

Minimal prototype of an authority-and-evidence substrate.

**Flow:** request → policy decision → Ed25519 delegation signature → execute → signed execution receipt → evidence package → independent verification.

## Primary verification API

`verify_authorized_execution` is the path for consequential actions. It requires:

- principal public key (delegation signature)
- verification_time (expiry)
- expected executor public key (pinned)
- original request (request hash binding)
- replay store
- a valid signed execution receipt

A package that fails any of these is rejected. This authenticates both the authorization and the execution result.

`verify_package` remains available for lower-level or policy-only checks. A success there does **not** authenticate the result unless an execution receipt was present and all receipt checks passed.

## Verification checks (strong path)

- Package self-hash
- Policy decision hash match
- Delegation signature (domain-separated over the decision hash)
- Decision hash excludes `decision_hash` and `delegation_proof`
- Expiry (explicit verification_time; production trusted time unresolved)
- Policy bounds
- Agent public key well-formedness
- Execution receipt signature
- Receipt binds decision_hash, request_hash, result_hash, execution_id, timestamp, executor key
- action_hash == receipt request_hash
- Executor key pinned
- Replay store required; execution_id recorded after all other checks

## Non-goals (this prototype)

- Authoritative Layer8 identity format
- Production key management or hardware attestation
- Durable replay prevention
- Trusted time source
- Executor hardware identity

Quantum adapters remain optional extensions that emit under the same evidence path.

## Quantum branch (experimental)

`quantum_l8/` tests whether Layer8's authority and evidence model can govern
quantum (and other) compute **without performing it**. It covers who
authorized a job, which exact workload and backend, under which
cryptographic policy, and what evidence binds the returned result to that
authorization. It does not claim that Layer8 "has quantum", proves quantum
execution, or is quantum-safe.

- Findings, threat model and limits: [docs/quantum/](docs/quantum/), starting
  with [ROADMAP.md](docs/quantum/ROADMAP.md)
- Demo: `pip install -r requirements.txt -r requirements-quantum.txt`, then
  `python -m examples.quantum_end_to_end`
- Tests: `pytest tests/quantum -q`

## Status

Local software-key prototype. **Not production-ready.**
