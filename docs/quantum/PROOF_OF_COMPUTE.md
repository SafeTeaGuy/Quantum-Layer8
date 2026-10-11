# Proof of execution: what a Layer8 QuantumExecutionReceipt proves

> **Layer8 does not prove quantum mechanics, and it does not prove that a
> quantum computer ran anything.**
>
> It provides cryptographically bound evidence of four things:
>
> 1. what was authorized;
> 2. which execution environment was selected;
> 3. what the provider reported executing and returning;
> 4. whether any of those records was altered afterwards.

## 1. The claim, stated precisely

When `verify_bundle` returns `chain_established = True` against trust roots
the verifier pinned out of band, a third party can rely on the following.
Each item assumes the signer's key was uncompromised at signing time.

1. Root principal **P** (pinned) signed a delegation chain that ends at agent
   **A**. Each link narrowed scope, and each link required crypto level
   **L**.
2. **A** signed a request for:
   - exactly these program bytes;
   - these parameters, shots and qubit count;
   - backend descriptor **B**;
   - cost limit **C**;
   - destination **D**;
   - level ≥ **L**.
3. Gate **G** (pinned) signed an `AUTHORIZED` decision and a single-use
   authorization for exactly that request. The authorization is under policy
   digest **Π** (pinned). The verifier independently re-derived that the
   request is within scope and that **L** is the effective level.
4. Executor **E** (pinned, and the one named in the authorization) signed a
   receipt that binds:
   - the authorization digest, **B**'s descriptor digest and the adapter id;
   - the provider's reported job id, backend name, status and metadata;
   - the executor's observed submit and complete times;
   - the result and its digest;
   - the classical consistency check;
   - the outcome.
5. The decision, authorization, consumption and receipt appear once each, in
   that order, in an evidence log. That log's chain and signed checkpoints
   verify, and the receipt is covered by a checkpoint.
6. Every signature in items 1–5 satisfies level **L**.
7. *(Optional, `--reexecute`)* For a reproducible run (a seeded simulator or
   the classical sampler), re-running gives the identical counts.
8. *(Optional)* For ≤16-qubit circuits whose measurements map qubit *i* to
   clbit *i*: the result's total variation distance from the ideal
   distribution is within the sampling tolerance.

## 2. Receipt fields and their basis

| Field group | Basis | Meaning |
|---|---|---|
| `authorization_*`, `request_*`, `workload_digest`, `program_digest`, `parameters`, `delegation_chain`, `principal_id`, `agent_id`, `tenant_id`, `crypto_policy` | GATE_SIGNED (copied, checked equal) | what was authorized |
| `backend_id`, `backend_descriptor_digest`, `backend_class`, `provider` | OPERATOR_REGISTERED | the execution environment selected |
| `adapter.{adapter_id, adapter_version}` | EXECUTOR_OBSERVED | which code talked to the provider |
| `execution.provider_job_id`, `provider_reported_backend`, `provider_reported_status`, `shots_reported` | **PROVIDER_REPORTED** | what the provider says it did |
| `provider_metadata` (+ digest): backend version, SDK version, `submitted_circuit_digest` (post-transpilation), timing | **PROVIDER_REPORTED** / adapter-computed | |
| `execution.submitted_at_ms`, `completed_at_ms` | EXECUTOR_OBSERVED, executor clock | not trusted time |
| `execution.reproducibility` | adapter | how to re-run, if possible |
| `result`, `result_digest` | **PROVIDER_REPORTED** | what came back |
| `classical_verification` | EXECUTOR_COMPUTED; the verifier can recompute it | consistency, not provenance |
| `cost.{reserved, reported, overrun}` | reserved: GATE_SIGNED; reported: PROVIDER_REPORTED | |
| `outcome` | `SUCCEEDED / FAILED / UNKNOWN / PROVIDER_MISMATCH` | an adapter exception is `UNKNOWN`, never success |
| `evidence_log_head_before` | EXECUTOR_OBSERVED | the log position at execution |

## 3. Verifier dimensions

The verifier reports one status per dimension and no single "valid" verdict.

| Dimension | Possible statuses |
|---|---|
| gate_policy | ESTABLISHED / FAILED |
| identities | ESTABLISHED / FAILED |
| delegation_chain | ESTABLISHED / FAILED |
| request | ESTABLISHED / FAILED |
| crypto_policy | ESTABLISHED / FAILED |
| decision | ESTABLISHED / FAILED |
| authorization | ESTABLISHED / FAILED |
| authorization_scope | ESTABLISHED / FAILED |
| receipt | ESTABLISHED / FAILED |
| result_binding | ESTABLISHED / FAILED |
| evidence_log | ESTABLISHED / FAILED |
| log_binding | ESTABLISHED / FAILED |
| **provider_execution** | **CLAIMED** / FAILED, never ESTABLISHED |
| classical_consistency | ESTABLISHED / FAILED / CLAIMED / NOT_CHECKED / INSUFFICIENT_EVIDENCE |
| reexecution | ESTABLISHED / FAILED / NOT_CHECKED / INSUFFICIENT_EVIDENCE |
| **revocation** | FAILED / **INSUFFICIENT_EVIDENCE**, never ESTABLISHED |

`chain_established` requires the first twelve dimensions and requires that
`revocation` is not FAILED. A revocation visible in the log that predates
execution defeats the chain; its absence proves nothing. Provider execution
and revocation completeness can never establish it.

## 4. Limits, and the stop condition this work hit

1. **No provider signs its results.** Here "provider" means the QPU vendor.
   IBM Quantum returns job ids, backend names, result objects and usage
   metadata over an authenticated API session (TLS plus an account token).
   That authenticates the *channel to Layer8's executor*. It does not give a
   third party a signed statement it can verify later. No vendor we know of
   offers hardware or TEE attestation of a QPU job. A "Proof of Quantum
   Execution" that requires provider-signed evidence **cannot be built
   today**. This is a mission stop condition, so the proof model was scoped
   down instead of inventing evidence: provider facts are attributed claims.
2. **The verification paradox.** A third party can only check a result
   classically if the circuit can be simulated classically. Those are
   exactly the circuits that do not need a QPU. Beyond that size, a result
   can be checked only:
   - for problems whose *output* is efficiently checkable, such as a
     factoring witness, an optimisation solution's objective value, or an
     NP certificate. The check then shows the answer is good. It does not
     show where the answer came from.
   - statistically, using protocols such as cross-entropy benchmarking
     against classically computed amplitudes. Those also need classical
     simulation at scale.
   - with interactive proofs of quantumness, or verifiable blind quantum
     computation. These are research protocols that need provider
     cooperation, and no production provider offers them.
3. **Transpilation.** The circuit that runs is not the circuit that was
   authorized: transpilation rewrites it to the backend's native gates and
   qubit layout. The receipt binds both:
   - the authorized program digest;
   - the adapter-computed `submitted_circuit_digest`.

   Equivalence between the two is the transpiler's claim. It is not proven.
4. **Time.** Every timestamp comes from a signer's own clock. Layer8 has no
   trusted time.
5. **Keys.** All statements are "the holder of key K signed". A compromised
   key forges its own statements. A CRQC compromises every Ed25519-only
   key.
6. **Tail and revocation completeness.** See THREAT_MODEL.md §4.

## 5. What is novel here, and what is not

| Element | Status |
|---|---|
| Signed receipts binding request, authorization, result digest | **Exists elsewhere**: Sigstore/in-toto attestations, SLSA provenance, Layer8 core receipts (minus the result digest), cloud audit logs |
| Hash-chained logs with signed checkpoints | **Exists**: Certificate Transparency, Trillian, Rekor |
| Hybrid classical+PQ signatures with downgrade protection | **Exists** as a pattern (IETF composite signatures, X.509 hybrid drafts). The binding into authority here is integration |
| Re-executing seeded simulations | **Trivial** |
| Delegated, attenuated, budgeted authority for agents (capabilities) | **Exists** as a pattern: macaroons, Biscuit, UCAN, SPIFFE, OAuth RAR, cloud IAM |
| **One authority object** binding delegator → agent → *exact quantum workload* → *registered backend class and descriptor* → *budget* → *required crypto level*, single-use, with an independently re-derivable decision and a receipt that labels every provider fact by basis | **The integration is new, as far as this audit found**. Each part has precedent; the combination applied to QPU jobs does not appear in provider IAM. IBM/AWS/Azure IAM authorize *accounts and resources*, not exact circuits, shot caps, per-delegation budgets or crypto levels |
| A cryptographic proof that a QPU executed a circuit | **Not achieved. Not achievable with current provider evidence** |
