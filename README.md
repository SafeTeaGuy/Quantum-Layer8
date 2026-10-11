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
- Optional local replay store on execution_id (recorded only after every other check passes)
- `require_execution_receipt=True` rejects a package with no receipt. The default is off, so a policy-only check can still pass. That pass does not authenticate the result.

The executor key is trusted only when the verifier passes the expected key. Without that pin, a packager can sign a receipt with their own key.

## Non-goals (this prototype)

- Authoritative Layer8 identity format
- Production key management or hardware attestation
- Durable replay prevention
- Trusted time source
- Executor hardware identity

Quantum adapters remain optional extensions that emit under the same evidence path.

## Status

Local software-key prototype. **Not production-ready.**
