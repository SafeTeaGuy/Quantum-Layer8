# Architecture audit for the quantum-computing branch

> **Experimental. Not production-ready.** This audit and the prototype in
> `quantum_l8/` do not change Layer8 core. Nothing in this document is an
> owner decision.

## 0. Scope and method

**Thesis under test.** Layer8 should not perform quantum computation. It
should govern who authorized a computation, what workload was authorized,
which backend may run it, which cryptographic policy applied, what was
executed, and what evidence binds the result to that execution.

**Sources audited (read-only):**

| Source | Revision | How used |
|---|---|---|
| `SafeTeaGuy/Layer8` (private core), integration branch `claude/layer8-cleanup-integration-kg8xf2` | `ed9f591` (2026-10-11) | Read only. No branch was modified. `integration/reviewer-ready-v1` and every other validated branch were not touched. |
| Core `docs/QUANTUM_READINESS_AUDIT.md` (same revision) | | Existing crypto-agility and compute-boundary audit. This work builds on it and does not repeat it. |
| `SafeTeaGuy/Quantum-Layer8` `main` | `133c5ae` | The earlier wedge prototype (`src/`, `adapters/`, `schema/`). Left unchanged. |

**Visibility note.** Quantum-Layer8 is public and core Layer8 is private. This
document names core primitives and their classification only. It deliberately
leaves out exploit-level detail of open core gaps; those stay in the core
gap register.

**Classifications:**

| Class | Meaning |
|---|---|
| **REUSE** | The primitive's semantics fit unchanged. |
| **EXTEND** | It fits, but needs a new versioned format or field. That is an owner decision in core. |
| **NEW_PRIMITIVE_REQUIRED** | Nothing in core expresses it. |
| **NOT_APPLICABLE** | It is irrelevant to governed compute. |

## 1. Primitive map

| Capability | Core primitive (module) | Class | Why | Prototype counterpart (`quantum_l8/`) |
|---|---|---|---|---|
| Canonical encoding | `layer8_core.canonical`: sorted-key JSON, floats rejected | **REUSE** | Floats are already refused. Workload parameters become decimal strings; costs become integer micro-USD. | `canonical.py` (same rules) |
| Domain-separated signing | `layer8_core.signing`: `len(domain)‖domain‖canonical(body)`, domain regex | **REUSE** construction, **EXTEND** primitive | The construction does not depend on the algorithm. The primitive is Ed25519 only. | `canonical.domain_separated`, `suites.py` |
| Agent identity | `layer8_trust.identity`: `agent_id` derived from an `ed25519:` key | **EXTEND** | Ids hash bare Ed25519 key hex, with no suite in the preimage (core OD-Q3). | `suites.identity_id`: full SHA-256 over `{suite, public_keys}` under its own domain |
| Principal identity and credential | `principal_credential.py` (operator-signed) | **REUSE** for semantics | Its scope containment (subset checks, depth) is the model to follow. The prototype pins root principals in the gate policy instead. | `gate_policy.root_principal_ids` |
| Delegation | `delegation.py`, `delegation_chain.py`, `delegation_store.py` | **EXTEND** | Attenuation, root re-check and canonical ids fit exactly. But `DelegationConstraints` holds only `{max_value, max_actions_per_day}`, and the strict v1 store parser refuses new fields. Shots, backend class, provider, lifetime execution count, result destination and crypto floor cannot be delegation-level constraints without a v2 format and a migration. Core lists that migration as blocked. | `contracts.build_delegation` (scope with no implicit wildcards), `scope_is_attenuation` |
| Authorization decision | `verification.verify_action()`, `TrustGate` | **REUSE** pattern, **NEW_PRIMITIVE_REQUIRED** for compute scope | The single-decision rule and the state vocabulary (`AUTHORIZED / DENIED / REVOKED / INSUFFICIENT_EVIDENCE`) carry over. Core policy can evaluate `action`, `resource`, `proposed_value` and flat `context`. It cannot evaluate a workload, a backend descriptor or a cost estimate. | `gate.QuantumTrustGate.decide` |
| Signed action request | `SignedActionRequest` (`LAYER8_AGENT_ACTION_V1`) | **REUSE as carrier**, **EXTEND** for semantics | The workload digest can travel today, with no format change, in the signed `context` as the broker-instruction digest. Core policy sees only an opaque digest. | `contracts.build_request` (`QuantumExecutionRequest`) |
| Generic parameters digest | Broker instruction `layer8-broker-instruction-v1`, bound through `context["layer8_broker_instruction_digest"]` | **REUSE** | This is the core-native binding for a workload today (§3). | `workload_digest` |
| Execution authorization (single use) | `ExecutionAuthorization`, `consume_execution_authorization()` → `try_consume` | **REUSE** semantics, **EXTEND** fields | It has single use, an intended executor, expiry capped by authority, and a re-check at consumption. It has no backend descriptor, workload digest field or crypto policy. | `gate._issue`, `gate.consume` |
| Execution receipt | `ExecutionReceipt` (`SUCCEEDED/FAILED/PARTIAL`), `ActionReceipt` | **EXTEND** | Core OD-Q8: there is **no result digest** and no `UNKNOWN` outcome. A compute receipt needs both, plus provider facts with a basis. | `executor.py` `QuantumExecutionReceipt` |
| Broker / execution boundary | `layer8_broker`: consume before credential, adapter `validate_parameters` / `check_binding` / `invoke`, at-most-once journal, `UNKNOWN` | **REUSE** | This is the provider-adapter boundary. The quantum adapter is a broker adapter. | `executor.Executor`, `adapters/base.py` |
| External adapters | Broker adapters; the vertical adapter contract (`layer8-vertical-adapter-v1`) | **REUSE** | Adapters only translate and may only refuse. `outcome_basis = EXECUTOR_REPORTED`. | `adapters/qiskit_adapter.py` |
| Replay protection | Signed `request_id`; `issue_once`; usage-ledger keyed by request; `MAX_CLOCK_SKEW_MS = 300000` | **REUSE** | Same semantics. The prototype adds a per-agent nonce set. | `gate._replay_and_budget` |
| Spending limits | Usage ledger (one unitless int, trailing windows) | **EXTEND** | Cost works as `proposed_value` in micro-USD. "At most N executions until T" is a lifetime count, which core can express only as a daily window. Shots and QPU-seconds need typed, multi-dimensional budgets. | per-delegation reservations (executions, cost) charged on every chain link |
| Revocation | `revocation.py`, `revocation_intake.py`, authority closure at consumption | **REUSE** semantics | Re-checking at consumption and `effective_at` scheduling carry over. Operator-issued revocation intake is blocked in core (OD-R2-02). | `gate.record_revocation`, consumption re-check |
| Trust Gate | `trust_gate.py` | **REUSE** pattern | Fixed vocabulary, fail closed. | `gate.py` |
| Append-only records | `layer8_core.append_only_store` (hash chain, `transact()`) | **REUSE** | Same construction. Core's own register records that the chain is unauthenticated at its tail. | `evidence_log.py` |
| Checkpoints | Key-registry checkpoint, `registry_commitment` (`TRUNCATED/FORK`) | **REUSE** pattern | Signed head checkpoints. There is no external anchor (§5). | `EvidenceLog.checkpoint`, `verify_log` |
| Proof plane | `layer8-proof-bundle-v1`, families, profiles, verdict vocabulary | **EXTEND** | A `compute.*` family and profile would be new profile versions (core audit §12.2). | `verify.verify_bundle` (per-dimension findings, no single verdict) |
| Independent verifier | `layer8_verifier` (standalone, pinned trust roots, per-dimension statuses) | **REUSE** pattern | Same status vocabulary (`ESTABLISHED / FAILED / INSUFFICIENT_EVIDENCE`), plus `CLAIMED`. | `verify.py` (not yet standalone; see ROADMAP) |
| Node identity | `node_identity.py`: roles `OBSERVER`, `GATE`, `EXECUTOR` | **EXTEND** | `GATE` and `EXECUTOR` are reserved and authorize no domain yet. The quantum gate and executor keys need those roles granted, with their domains, by key administration. | gate and executor `KeyBundle`s pinned in the gate policy and trust roots |
| Provenance attestation / `FactBasis` | `attestation.py`; `CLAIMED / OBSERVED / VERIFIED` | **REUSE** | Provider facts (backend name, calibration, job id) are `CLAIMED`, exactly as provenance mechanisms are labels and not verifications. | receipt `bases`, verifier `CLAIMED` |
| Workload authorization | none (closest: broker instruction plus the `DeterministicComputationContract` template in `layer8_research`) | **NEW_PRIMITIVE_REQUIRED** | No core object binds algorithm, program digest, parameters, shots, qubits, backend and cost. | `QuantumExecutionRequest`, `QuantumExecutionAuthorization` |
| Backend descriptor / class | proposed `l8.compute.backend-class.v1` (core audit §7, not implemented) | **NEW_PRIMITIVE_REQUIRED** | | `contracts.backend_descriptor` (operator-registered, pinned by digest) |
| Crypto policy bound into authority | none; every artifact is implicitly Ed25519 | **NEW_PRIMITIVE_REQUIRED** | Core OD-Q1/Q2/Q4/Q5 are open. | `suites.py` levels; `crypto_policy` in the delegation, request, authorization and receipt |
| Classical verification of results | none | **NEW_PRIMITIVE_REQUIRED** (application layer) | Core records commitments, never correctness. | `classical_verification` (TVD) and re-execution |
| Routing evidence | none | **NEW_PRIMITIVE_REQUIRED** | | `router.py` `RoutingDecision` |
| MCP | `layer8_service.mcp_adapter`: thin wrappers over the same dispatch | **REUSE** | A quantum tool would be one more wrapper with no decision logic. Not prototyped. | n/a |
| AuthZEN | `layer8_service/authzen` | **REUSE** | Same single decision. | n/a |
| Challenge / human approval | `challenge.py` (`HUMAN_CONFIRMATION` is a type only; M0 characterization) | **NOT_APPLICABLE now** | Useful later for high-cost QPU jobs. Human approval is not implemented in core. | n/a |
| Passports | `passport.py` | **NOT_APPLICABLE** | A passport is evidence, never authority. | n/a |
| Markets `merkle-v1` | `layer8_storage.merkle` | **NOT_APPLICABLE** | It has no leaf/node domain separation and is Markets-specific. Do not reuse it for evidence logs. | n/a |
| Stablecoin / x402 | `layer8_stablecoin`, `layer8_gateway/billing/x402` | **NOT_APPLICABLE** | Settlement of QPU spend is out of scope. | n/a |

## 2. Findings on the existing Quantum-Layer8 wedge (`src/`, `adapters/`)

Recorded, not fixed. They are outside this branch's scope and do not affect
`quantum_l8/`:

1. **The adapters are broken.** `adapters/ibm.py`, `adapters/braket.py` and
   `adapters/model_call.py` call `build_package(authorization=...)`, a keyword
   that `src/evidence.py` no longer accepts. `examples/minimal_example.py` and
   `examples/model_call_example.py` fail with `TypeError`. No test covers the
   adapters.
2. **The wedge's authorization does not name the agent.** `PolicyDecision`
   binds the principal and action classes but no agent id. Any holder of the
   signed decision can use it.
   `examples/live_execution_path.py` also uses the principal's key as the
   agent's key.
3. **The wedge does not bind the workload into the authorization.** The
   decision allows action types, providers and targets. The executor receipt
   binds `request_hash`, but only after execution. "Was the workload changed
   after authorization?" therefore cannot be answered before execution.
4. `schema/quantum_job_evidence.schema.json` already lists
   `key_type: ml-dsa | hybrid`, but no code supports either.

These are why `quantum_l8/` is a new package rather than an extension of `src/`.

## 3. How a quantum job maps onto core *today* (no format change)

| Quantum element | Core carrier today | Can core *evaluate* it? |
|---|---|---|
| principal, agent, delegation chain | `SignedActionRequest.agent_id`, `delegation_id`, chain walk | yes |
| backend | `resource`, e.g. `compute:quantum_simulator:qiskit.basic_simulator`; exact match only | yes, as an opaque string |
| cost ceiling | `proposed_value` in micro-USD, checked against `max_value` and `LimitRule` | yes |
| workload: program digest, parameters, shots, qubits | broker-instruction `parameters`, digest in signed `context` | **no**: digest only; adapter `validate_parameters` can refuse |
| crypto policy | a signed `context` key plus a policy `ContextConstraint eq` | declaration only; nothing verifies a PQ signature |
| result digest | none (`ExecutionReceipt` v1) | **no** |
| lifetime execution count N | `max_actions_per_day` (a daily window) | approximately |

**Conclusion.** Core can carry a quantum job end to end today. The carrier
is `request → verify_action → ExecutionAuthorization → Broker → receipt`.
But core can authorize only the job's *class* (resource string and value).
It cannot authorize the exact workload, backend descriptor, shots or crypto
policy, and it cannot bind the result. That gap is what `quantum_l8/`
prototypes.

## 4. Stop-condition review

| Stop condition | Status |
|---|---|
| Ambiguous core authority rule | Encountered, **not resolved here**. The prototype chooses locally and labels each choice: <br>• chain-wide crypto floor (core OD-Q5); <br>• delegation-issuer-or-operator revocation; <br>• one tenant per delegation (core tenant ownership is undefined). <br>None is proposed as core semantics. |
| Weakening an existing invariant | None. Core is untouched. The prototype has its own single decision function and its own single consumption path. |
| A provider cannot supply evidence the proof model needs | **Yes, for hardware execution.** IBM (and every QPU provider we know of) returns no signed result and no hardware attestation. The proof model therefore does **not** require provider proof. Provider facts are `CLAIMED`. Any stronger "proof of quantum execution" stops here (PROOF_OF_COMPUTE.md §4). |
| A PQ primitive needs an undecided architectural choice | **Yes.** Core OD-Q1 (standard and library) and OD-Q2 (hybrid mode) are open. The prototype uses ML-DSA-65 from pyca/cryptography under an **experimental** suite id (`l8x.…exp0`). It tests the downgrade-resistance *design* and selects nothing for core (PQ_MIGRATION.md §6). |
| Modifying validated Layer8 branches | Not done. Core was cloned read-only into a separate worktree. |
| The feature does not beat or complement a classical approach | **Partly triggered.** The arena found no quantum advantage on any problem run (WORKLOAD_ROUTER.md §5). The governance layer is backend-neutral, so its value does not depend on quantum winning. |
