# Post-quantum migration: crypto agility, hybrid signatures, historical evidence

> **Nothing here makes Layer8, Bitcoin, or any integrated system
> "quantum-proof".**
>
> The prototype shows that one design property can be enforced in code: a
> *required* post-quantum component cannot be removed or downgraded without
> detection. Whether ML-DSA-65 is the right choice for Layer8 is an **open
> owner decision** (core OD-Q1/OD-Q2). The prototype uses it under an
> experimental suite id and selects nothing for core.

## 1. Inventory of cryptographic dependencies

### 1.1 Quantum-Layer8 (this repository)

| Component | Primitive | Shor-breakable? | Notes |
|---|---|---|---|
| `src/delegation.py`: policy delegation signature | Ed25519 (pyca/cryptography) | **yes** | Wedge prototype. Domain `quantum-layer8-proto-v1:policy-delegation:` |
| `src/execution_receipt.py`: executor receipt | Ed25519 | **yes** | |
| `src/evidence.py`: package and decision hashes | SHA-256 | no (Grover: ~2^128 preimage) | |
| `quantum_l8/suites.py`: every quantum-branch signature | Ed25519, ML-DSA-65 (FIPS 204), or both | Ed25519 component: yes; ML-DSA-65: no known quantum attack | Selected per key; a policy can require both |
| `quantum_l8` ids, digests, log chain | SHA-256, full 256-bit ids | no | Ids are not truncated |

### 1.2 Layer8 core (summarised from core `docs/QUANTUM_READINESS_AUDIT.md`)

Every core signed artifact is Ed25519, through one domain-separated
construction. That includes:

- identity issuance;
- delegation credentials;
- principal credentials;
- signed action requests;
- ActionReceipts;
- execution authorization, attempt, receipt and release records;
- usage reservations and revocation events;
- key-registry records and checkpoints;
- node registration and attestations;
- capture manifests, settlement records and release statements.

| Area | Exposure to a CRQC | Why it matters |
|---|---|---|
| Identity (`agent_id`, `node_id` derived from the Ed25519 key) | Key recovery from the published public key | Total impersonation. A PQ key means a new id (no rotation for external identities) |
| Delegation and principal credentials | Forged authority | Root of every authorization |
| ActionReceipts and execution receipts | Forged evidence | Evidence of past decisions |
| Node identity and attestations | Forged nodes and observations | |
| Key registry and checkpoints | Forged key history, signed by the admin key | **Highest value:** decides which key was valid when |
| Append-only stores and Merkle | SHA-256 only | Survive, but are only as good as whatever signs or anchors their heads |
| Historical signatures | Retroactive forgery (§5) | Cannot be fixed by re-signing alone |
| External anchoring | Specified, not implemented | The precondition for historical survivability |
| Key rotation | Registry rotation exists for operator purposes; external identities cannot rotate | The migration route for agents and principals is undefined (core OD-Q7) |
| x402 (secp256k1) | External protocol | Outside Layer8's control |

Symmetric primitives (seed encryption, IPC HMAC) and SHA-256 are not
materially affected.

## 2. Design principle: agility, not replacement

Ed25519 is not removed. Each v1 artifact keeps its meaning forever: "a v1
format means Ed25519". New formats name their suite. The design is the core
audit's §4–§6. The prototype implements it as follows:

| Rule | Implementation (`quantum_l8/suites.py`) |
|---|---|
| Closed suite table | `SUITES`: `l8.sig.ed25519.v1`, `l8x.sig.ml-dsa-65.exp0`, `l8x.sig.hybrid-ed25519-ml-dsa-65.exp0`. Component order is part of the suite |
| Suite bound to the **key** | `verify()` takes the suite from the pinned `public_identity`; the artifact cannot choose it |
| Suite inside the signed bytes | Every body has `signature_suite`, which must equal the key's suite |
| Suite in the identity id | `identity_id = SHA-256(canonical({domain: L8X_IDENTITY_ID_V0, identity: {suite, public_keys}}))` |
| AND composition | Every component must verify, in fixed order, with exact lengths and strict lowercase hex. There is no partial validity |
| No fallback | No code path verifies "PQ, else Ed25519" |
| ML-DSA context string | ML-DSA signs with the message domain as its FIPS 204 context. The Ed25519 component uses the core length-prefixed domain construction |
| Unknown suite | `SIGNATURE_SUITE_UNSUPPORTED`, never valid |

## 3. Downgrade resistance: the required policy is inside the authority

The attacker's goal is to get an operation accepted under classical policy
when the principal required post-quantum. Each layer blocks it:

1. **The requirement is signed by the principal.** `crypto_policy` sits in
   every delegation body, under the principal's own hybrid signature.
   Removing or lowering it invalidates the delegation.
2. **The operator floor is pinned.** `gate_policy.crypto_floor` is part of
   `gate_policy_digest`. Every authorization binds that digest, and the
   verifier pins it.
3. **The effective level is computed, never declared.** It is
   `effective = union(floor, every link's crypto_policy)`. The request can
   only restate or raise it (`CRYPTO_POLICY_DOWNGRADE`).
4. **Every signature must satisfy it.** That covers the request, every
   delegation, the gate decision and authorization, the receipt and the log
   checkpoints (`*_SUITE_BELOW_POLICY`).
5. **The verifier does not trust the gate's statement.** It recomputes
   `effective` from the pinned policy and the signed chain. It then compares
   that with the authorization's `crypto_policy` and every suite in the
   bundle. A key-holding gate that issued a classical-level authorization is
   caught (`AUTHORIZATION_POLICY_NOT_EFFECTIVE_POLICY`).

The CRQC scenario is tested in
`test_forged_classical_signature_for_hybrid_agent_refused`. The attacker
recovers the agent's Ed25519 private key, re-labels the request as
Ed25519-only and signs it. The request is refused with `SIGNATURE_SUITE_MISMATCH`,
because the agent's registered identity is hybrid. A brand-new classical
identity does not help the attacker either: it is not the delegate, and it
is below policy (`test_classical_agent_key_refused_under_hybrid_policy`).

The design depends on one thing: **identities are registered claim-once with
their suite**. Whoever controls identity registration can register a new
classical identity, though it still cannot become a delegate without a
principal's hybrid signature. Core has no designated identity registrar yet.

## 4. Measured cost of hybrid (prototype, this machine)

| | Ed25519 | Hybrid Ed25519 + ML-DSA-65 |
|---|---|---|
| Public key | 32 B | 32 + 1952 B |
| Signature | 64 B | 64 + 3309 B |
| Signed request (JSON) | 1.5 KB | 8.2 KB |
| Authorization (JSON) | 1.8 KB | 8.5 KB |
| Receipt (JSON) | 3.5 KB | 10.2 KB |
| Full verification bundle | 13.8 KB | 62 KB |
| Sign (mean of 200) | 0.04 ms | 0.9 ms |
| Verify (mean of 200) | 0.13 ms | 0.6 ms |

Hex encoding doubles the on-wire size of keys and signatures. Core's fixed
64/128-hex regexes, store line sizes and request-body limits must be
re-measured before any core adoption (core audit R1/R2).

## 5. Harvest now, forge later

An Ed25519 signature proves only that the holder of key K signed some bytes.
Its timestamp is self-asserted. After a CRQC recovers K from its public key,
the attacker can produce new artifacts with any timestamp, including dates
before the break. Those are indistinguishable from genuine history. That is
the "forge later" half; "harvest now" is the public keys already published
in identity stores, passports and vectors.

What survives:

- **SHA-256 commitments.** Log heads, Merkle roots and content digests.
- **A commitment made before the break, to something the attacker cannot
  rewrite.** That means an external anchor that an independent party holds,
  or a PQ-signed checkpoint that a verifier already holds.

### 5.1 Re-attestation without rewriting history (prototyped)

`EvidenceLog.reattest(new_signer)` works in two steps:

1. It appends a `REATTESTATION` entry citing the previous checkpoint digest,
   its head hash and its suite.
2. It signs a **new** checkpoint with the newer-suite key. That checkpoint
   chains to the old one through `prev_checkpoint_digest`.

The old entries and old signatures are untouched
(`test_reattestation_under_new_suite_keeps_history`). A rewrite under the
old key is still caught (`test_reattestation_does_not_hide_rewrites`).

What a re-attestation means is narrow. It says: "PQ key K′ saw history with
head h at its own claimed time." It does **not** make K's old signatures
PQ-secure. It protects history against a later break of K **only if** the
re-attestation is shown to exist *before* that break. Showing that needs
an external anchor, or trusted time, and the prototype has neither.

### 5.2 Proposed classification of historical evidence (not implemented; depends on anchoring)

| Artifact | Anchored PQ/hybrid checkpoint covers it, made before the Ed25519 sunset | Not covered |
|---|---|---|
| Ed25519-only, dated before the sunset | **AUTHENTICATED_HISTORICAL** | **INSUFFICIENT_EVIDENCE** |
| Ed25519-only, dated after the sunset | **REFUSED** | **REFUSED** |
| Hybrid / PQ | normal verification | normal verification |

### 5.3 Re-attestation schedule (recommendation)

- Re-attest the evidence-log head and the key-registry head under the newest
  approved suite:
  - at every suite change;
  - periodically, for example daily;
  - and immediately on any credible CRQC-progress signal.
- Publish each re-attestation to at least one external anchor that an
  independent party can verify. Core's anchor contract is specified but has
  no suite field (core OD-Q6).
- Never re-sign individual historical artifacts. Re-attest heads.

## 6. Stop conditions hit (not resolved here)

| Decision | Why it blocks core adoption |
|---|---|
| OD-Q1: PQ standard, parameter set and library | The prototype uses ML-DSA-65 from pyca/cryptography (OpenSSL). It is experimental, not a recommendation. SLH-DSA (FIPS 205) is a hash-based alternative with different size and time costs; it was not prototyped |
| OD-Q2: hybrid as the transition mode; whether PQ-only is ever allowed | The level algebra supports all three. Which one each purpose requires is policy |
| OD-Q3: new id derivation | The prototype uses a full 256-bit id with the suite in the preimage |
| OD-Q4/Q5: where the floor lives; chain-wide vs root-only | The prototype is chain-wide, the stricter choice |
| OD-Q7: identity migration route | The prototype treats a new suite as a new identity. That requires re-delegation |
| Trusted time and external anchor | Without them, §5 cannot be completed |

## 7. What not to claim

- Not "quantum-proof", "quantum-safe" or "post-quantum secure". Hybrid
  artifacts are as strong as their strongest unbroken component *for new
  artifacts*. Old Ed25519 artifacts gain nothing.
- Not "Bitcoin is quantum-safe" because Layer8 anchors to it. Anchoring
  inherits the anchor chain's own signature exposure (ECDSA/Schnorr over
  secp256k1).
- Not "ML-DSA is unbreakable". It is a NIST standard with no known quantum
  attack. Implementations are new and side-channel posture varies.
