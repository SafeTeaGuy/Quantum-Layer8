# Quantum execution contract (provider-neutral)

> **Experimental, version `v0`.** Implemented in `quantum_l8/contracts.py`
> and `quantum_l8/gate.py`. Every schema id is in the `l8x.` (experimental)
> namespace, not in core's `*-v1` namespace.

## 1. Design rules

1. **No provider in the contract.**
   - A provider appears only as an opaque `provider` string and a backend
     descriptor that the operator registers.
   - IBM and Qiskit appear only in an adapter (`adapters/qiskit_adapter.py`)
     and in a descriptor's `adapter_id`.
   - A new QPU vendor or research system needs a descriptor and an adapter.
     It needs no change to the delegation, request, authorization, receipt or
     verifier.
2. **Exact bytes.**
   - The circuit digest is SHA-256 of the exact program text (OpenQASM 3).
   - There is no normalisation. A whitespace change is a different circuit.
     Normalising would mean two parties could disagree about what was
     authorized.
3. **Canonical JSON with no floats.**
   - Workload parameters are decimal strings matching
     `^-?(0|[1-9][0-9]{0,15})(\.[0-9]{1,17})?$`.
   - Money is integer micro-USD.
   - Time is integer Unix milliseconds.
4. **No implicit wildcards.**
   - Every allow-list must be non-empty, sorted and unique.
   - Circuit freedom is an explicit mode: `PINNED` or `ANY_FOR_ALGORITHM`.
     An empty list never means "any".
5. **Every signed body names its suite.**
   - `signature_suite` is inside the signed bytes and must equal the suite
     of the signer's pinned key (PQ_MIGRATION.md §3).
6. **Ids derive from content.**
   - `delegation_id`, `revocation_id`, `authorization_id` and `receipt_id` are
     SHA-256 over the body without the id. An id cannot be re-pointed at
     other content.

## 2. Objects

### 2.1 Backend descriptor (`l8x.compute-backend-descriptor.v0`)

The operator registers each descriptor in the gate policy. Descriptors are
pinned by digest in every authorization and receipt, and are not signed on
their own.

| Field | Meaning |
|---|---|
| `backend_id` | Layer8's name for the execution target |
| `backend_class` | One of the closed set `CPU`, `GPU`, `TPU`, `QUANTUM_SIMULATOR`, `QUANTUM_HARDWARE` |
| `provider` | Opaque provider id, for example `qiskit-local` or `ibm-quantum` |
| `adapter_id` | The adapter allowed to execute on it |
| `provider_backend_names` | Names the provider may report back. Anything else is `PROVIDER_MISMATCH` |
| `max_qubits` | Upper bound on `num_qubits` |
| `pricing` | `per_job_micro_usd`, `per_shot_micro_usd`, used for the cost estimate |
| `allowed_tenants` | Tenants permitted on this backend |
| `region` | Geographic or policy label, used by the router |

`backend_class` is an operator registration, not a provider statement. The
claim "this ran on hardware" is a separate, `CLAIMED` provider fact.

### 2.2 Delegation (`l8x.quantum-delegation.v0`, domain `L8X_QUANTUM_DELEGATION_V0`)

Signed by the issuer (a root principal, or a delegate that was allowed to
re-delegate).

| Field | Meaning |
|---|---|
| `delegation_id` | Content id |
| `issuer_id`, `subject_id` | Issuer and delegate identity ids |
| `parent_delegation_id` | `null` at the root |
| `tenant_id` | One tenant per delegation |
| `scope.algorithm_ids` | Permitted algorithm identifiers |
| `scope.circuits` | `{mode: PINNED, digests: [...]}` or `{mode: ANY_FOR_ALGORITHM, digests: []}` |
| `scope.backend_ids`, `backend_classes`, `providers` | All three must match |
| `scope.max_shots_per_execution` | |
| `scope.max_executions` | Lifetime count, not a daily window |
| `scope.max_cost_micro_usd_per_execution`, `max_total_cost_micro_usd` | |
| `scope.result_destinations` | Where results may be delivered |
| `crypto_policy` | Minimum signature level for **every** signature in any chain through this link |
| `may_redelegate` | |
| `not_before_ms`, `expires_at_ms` | |
| `signature_suite` | |

**Attenuation.** A child must be a subset of its parent on every list. It
must be ≤ its parent on every number. It must be within its parent's
validity window, use the same tenant, and have at least its parent's crypto
policy. If the parent is `PINNED`, the child must also be `PINNED` with a
subset of the digests.

### 2.3 QuantumExecutionRequest (`l8x.quantum-execution-request.v0`, domain `L8X_QUANTUM_EXECUTION_REQUEST_V0`)

Signed by the agent. The program text travels next to the envelope and is
bound by digest.

| Field | Required by mission | Notes |
|---|---|---|
| `request_id` | request_id | 128-bit random hex; single use |
| `tenant_id` | | Must equal the caller's authenticated tenant |
| `principal_id` | principal | Must equal the chain's root issuer |
| `agent_id` | agent | Must equal the leaf delegation's subject |
| `delegation_id`, `delegation_chain_digest` | delegation | The digest pins the exact chain from root to leaf |
| `workload.algorithm_id` | algorithm | |
| `workload.program_format` | | `openqasm3` |
| `workload.program_digest` | circuit digest | SHA-256 of the exact program bytes |
| `workload.parameters` | parameters | Decimal strings |
| `workload.shots` | shots | |
| `workload.num_qubits` | resource | Declared. The adapter refuses before consumption if the program disagrees |
| `workload_digest` | workload digest | SHA-256 of canonical `workload` |
| `backend.{backend_id, backend_class, provider}` | backend, backend class, provider | All three must equal the registered descriptor |
| `resource_limits.{max_qubits, max_runtime_ms}` | resource limits | |
| `cost_limit_micro_usd` | cost limits | Reserved in full against every delegation in the chain |
| `execution_deadline_ms` | execution deadline | |
| `result_destination` | allowed result destination | |
| `crypto_policy` | cryptographic policy | Must restate at least the effective level (§3) |
| `signature_suite` | classical/PQ signing requirement | Must satisfy the effective level |
| `nonce` | nonce | Single use per agent |
| `created_at_ms` | timestamp | Must be no more than 300 s ahead of the gate's clock |

### 2.4 Gate decision and QuantumExecutionAuthorization

- **Decision.** Every decision, including refusals, is signed by the gate
  (`l8x.quantum-gate-decision.v0`) and logged. Its fields are `request_digest`,
  `state`, an ordered `reasons` list, `gate_policy_digest` and
  `authorization_id`.
- **Authorization.** Only `AUTHORIZED` issues an authorization
  (`l8x.quantum-execution-authorization.v0`, domain
  `L8X_QUANTUM_EXECUTION_AUTHORIZATION_V0`). It binds:
  - `request_digest` (the whole signed request, including its proof);
  - `workload_digest`, `program_digest`, `algorithm_id` and `shots`;
  - `backend_id`, `backend_descriptor_digest`, `backend_class` and `provider`;
  - `principal_id`, `agent_id`, `delegation_chain` and `tenant_id`;
  - `reserved_cost_micro_usd` and `result_destination`;
  - the **effective** `crypto_policy` (computed by the gate, not copied from
    the request);
  - `intended_executor_id`, with `permitted_execution_count = 1`;
  - `valid_until_ms = min(deadline, every delegation's expiry)`;
  - `gate_policy_digest`.

### 2.5 Revocation (`l8x.quantum-revocation.v0`)

- A delegation can be revoked by its issuer or by the operator. An agent
  identity can be revoked only by the operator.
- `effective_at_ms` may be immediate, scheduled or backdated.
- Revocation is checked at decision time and again at consumption time.

## 3. Effective crypto policy

The levels are sets of required component algorithms:

```
REQUIRE_ED25519                   = {ed25519}
REQUIRE_ML_DSA_65                 = {ml-dsa-65}
REQUIRE_HYBRID_ED25519_ML_DSA_65  = {ed25519, ml-dsa-65}
```

How the policy is computed and enforced:

```
effective = union( operator floor, crypto_policy of every delegation in the chain )
```

- The request must declare a level that is a superset of `effective`
  (otherwise `CRYPTO_POLICY_DOWNGRADE`).
- The suites of the request, every delegation, the gate, the executor, the
  receipt and the log checkpoints must each contain every component in
  `effective`.
- The level never comes from the request, the router, the adapter or the
  provider. The request can only restate it or raise it.

## 4. Reason codes (deterministic)

Checks run in this fixed order:

1. schema
2. well-formedness
3. agent identity
4. agent signature

Any failure in steps 1–4 stops evaluation. After that:

5. tenant
6. executor
7. agent revocation
8. chain resolution
9. per-link checks: signature, self-delegation, linkage, re-delegation,
   attenuation, validity window, revocation
10. root principal
11. principal
12. chain digest
13. chain tenant
14. crypto policy
15. workload digest and program bytes
16. backend descriptor
17. qubits and cost estimate
18. scope: algorithm, circuit, shots, backend, class, provider, per-execution
    cost, destination, qubits, backend tenant
19. clock
20. replay and budgets

**State precedence:** any `REVOKED_*` reason gives REVOKED. Otherwise, any
reason outside the evidence-missing set gives DENIED. Otherwise, any reason
gives INSUFFICIENT_EVIDENCE. No reasons gives AUTHORIZED.

Evidence-missing set: `REQUEST_SCHEMA_UNSUPPORTED`, `AGENT_IDENTITY_UNKNOWN`,
`DELEGATION_NOT_FOUND`, `ISSUER_IDENTITY_UNKNOWN`, `BACKEND_UNKNOWN`,
`PROGRAM_MISSING`.

A rejected request burns no request id, nonce or budget. Single use and
budgets are re-checked under the gate lock before issue.

The full list of codes is in `gate.py`. Every code is reachable from a test
in `tests/quantum/`.

## 5. Mapping onto core when it is ready

| Prototype | Core landing spot | Core decision needed |
|---|---|---|
| `QuantumExecutionRequest` | `SignedActionRequest` with `action = "compute.quantum.execute"`, `resource = backend_id`, `proposed_value = cost_limit_micro_usd`, and the workload as broker-instruction `parameters` | none to *carry* it; OD-Q8 to *evaluate* it |
| Delegation scope | `DelegationConstraints` v2 | v2 delegation format plus migration (blocked in core today) |
| Authorization | `ExecutionAuthorization` v2 with `workload_digest`, `backend_descriptor_digest`, `crypto_policy` | OD-Q8 |
| Receipt | `ExecutionReceipt` v2 with `result_digest`, `UNKNOWN`, provider facts with basis | OD-Q8 |
| Suites | core suite registry (core audit §4) | OD-Q1, Q2, Q4, Q5 |
