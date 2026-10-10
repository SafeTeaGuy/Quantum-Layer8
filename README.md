# Quantum-Layer8

Minimal prototype of an authority-and-evidence substrate.

**Flow:** request → policy decision → Ed25519 delegation signature → execute → signed execution receipt → evidence package → independent verification.

## Verification checks

- Package self-hash
- Policy decision hash match
- Delegation signature (domain-separated over decision hash)
- Expiry (explicit verification_time required; production trusted time unresolved)
- Policy bounds (action type, provider, target, cost)
- Agent public key well-formedness (raw Ed25519 base64)
- Execution receipt signature (domain-separated canonical payload)
- Receipt binds decision_hash, request_hash, result_hash, execution_id, timestamp, executor key
- Optional local replay store on execution_id

## Non-goals (this prototype)

- Authoritative Layer8 identity format
- Production key management or hardware attestation
- Durable replay prevention
- Trusted time source
- Executor hardware identity

Quantum adapters remain optional extensions that emit under the same evidence path.

## Status

Local software-key prototype. **Not production-ready.**
