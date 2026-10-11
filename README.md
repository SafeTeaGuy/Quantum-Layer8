# Quantum-Layer8

Minimal prototype of an authority-and-evidence substrate.

**Flow:** request → policy decision → Ed25519 delegation signature → execute → signed execution receipt → evidence package → independent verification.

## Verification checks

- Package self-hash
- Policy decision hash match
- Delegation signature (domain-separated over the decision hash)
- Decision hash is SHA-256 of the canonical decision **excluding** `decision_hash` and `delegation_proof` (the signature is not inside the digest it signs)
- Expiry (explicit verification_time required; production trusted time unresolved)
- Policy bounds (action type, provider, target, cost)
- Agent public key well-formedness (raw Ed25519 base64)
- Execution receipt signature (domain-separated canonical payload)
- Receipt binds decision_hash, request_hash, result_hash, execution_id, timestamp, executor key
- When a receipt is present, `action_hash` must equal the receipt `request_hash`
- Replay: a package with a receipt is accepted only when a replay store is passed. The execution id is recorded after every other check, and a reuse fails closed. The included store is in-memory only.
- `require_execution_receipt=True` rejects a package with no receipt. The default is off, so a policy-only check can still pass. That pass does not authenticate the result.

- A receipt is accepted only when `expected_executor_public_key_b64` is passed and matches the receipt. An unpinned receipt fails closed.

## Non-goals (this prototype)

- Authoritative Layer8 identity format
- Production key management or hardware attestation
- Durable replay prevention
- Trusted time source
- Executor hardware identity

Quantum adapters remain optional extensions that emit under the same evidence path.

## Status

Local software-key prototype. **Not production-ready.**
