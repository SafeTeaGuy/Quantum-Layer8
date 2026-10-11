# Roadmap and findings: Layer8 quantum branch

> **Status:** an isolated experiment on branch
> `claude/layer8-quantum-architecture-6tgs7s` of Quantum-Layer8. Nothing was
> merged, and no Layer8 core branch was modified.

## 1. Result against the success criterion

> *Can we demonstrate an independently verifiable chain? A specific
> principal delegated narrowly scoped authority to an agent. The agent
> requested a specific quantum computation. Layer8 authorized the exact
> workload, backend and resources under an explicit cryptographic policy.
> The workload executed through a real or simulated quantum backend. And
> Layer8 produced tamper-evident evidence binding the authorization,
> execution and returned result.*

**Yes, for a simulated backend, with the limits below.**

`python -m examples.quantum_end_to_end` runs:

```
principal ──(hybrid-signed delegation)──► agent ──(hybrid-signed request)──►
Quantum Trust Gate ──(AUTHORIZED, single-use authorization)──► executor ──►
Qiskit BasicSimulator ──► counts ──► QuantumExecutionReceipt ──►
hash-chained, checkpointed evidence log ──► bundle.json + trust_roots.json
```

`python -m quantum_l8.verify bundle.json trust_roots.json --reexecute` then
establishes:

- 12 of 12 authority and evidence dimensions;
- classical consistency, with TVD within tolerance;
- bit-for-bit re-execution.

It reports `provider_execution: CLAIMED` and
`revocation: INSUFFICIENT_EVIDENCE`, which is by design.

The 98 tests in `tests/quantum/` cover:

- every gate question in Phase 3;
- the scoped-agent cases in Phase 8;
- every attack listed in Phase 9, plus extras;
- three pinned "cannot prove" limits;
- 8 regressions from an adversarial review: fail-open revocation, crash paths, and checks the verifier did not re-derive.

**Not demonstrated:** a real QPU. There are no IBM credentials here, and the
adapter design in IBM_QISKIT_ADAPTER.md §3 is unimplemented. Even with one,
the chain would establish that Layer8's executor *received* a result from
IBM. It would not establish that IBM's hardware *produced* it.

## 2. What is novel, what exists elsewhere, what is integration

| | Assessment |
|---|---|
| **Novel, as far as this audit found** | One authority object that binds, single-use: principal → attenuated delegation → agent → **the exact quantum workload** (program bytes, parameters, shots, qubits) → **a registered backend class and descriptor** → **per-delegation lifetime budgets** → **a required signature level that the agent cannot lower and the verifier re-derives**. That object comes with a receipt that labels every provider fact by its basis. QPU provider IAM authorizes accounts and resources, not circuits, shot caps, delegated budgets or crypto levels. |
| **Exists elsewhere** | Capability tokens and attenuated delegation (macaroons, Biscuit, UCAN); signed provenance and attestations (in-toto, SLSA, Sigstore); transparency logs with signed checkpoints (CT, Trillian, Rekor); composite and hybrid PQ signatures (IETF drafts); ML-DSA itself (FIPS 204); QAOA, MaxCut and benchmarking practice; workload schedulers and brokers. |
| **Merely integration** | Calling Qiskit; seeded simulator re-execution; the TVD consistency check; the router's weighted score; the arena harness; transcribing Layer8 core's existing patterns (single decision, single consumption, at-most-once broker, `CLAIMED` basis, per-dimension verifier) into a compute vertical. |

## 3. Claims we can defend

- Layer8 can govern quantum jobs *as a class of external execution* without
  performing them. Authority and evidence are backend-neutral: the same
  objects authorize CPU, simulator and QPU descriptors.
- An agent can be given narrowly scoped QPU authority that fails closed
  against each of the following (each tested):
  - replay;
  - a modified circuit or parameters;
  - backend or provider substitution;
  - cost and count bypass;
  - escalation through re-delegation;
  - cross-tenant use;
  - a stolen request;
  - result substitution;
  - revocation;
  - expiry.
- In this prototype, a required post-quantum signature component cannot be
  stripped or downgraded, by the agent or by a malicious gate, without
  detection.
- Evidence of what was authorized, selected, reported and returned is
  tamper-evident, within the checkpointed range, against pinned keys.
- On the problems run, classical methods won. The system records that.

## 4. Claims we absolutely cannot make

- "Layer8 has quantum", "Layer8 is a quantum platform", or that Layer8
  performs or accelerates quantum computation.
- "Layer8 proves a quantum computer executed this job", or proves which
  device did.
- "Layer8 proves the result is correct", for anything beyond the classically
  checkable cases.
- "Layer8 is quantum-proof", "quantum-safe" or "post-quantum secure". Core
  is Ed25519-only. The prototype's hybrid suite is experimental, and old
  Ed25519 evidence gains nothing.
- "Anchoring to Bitcoin (or any chain) makes Layer8 evidence quantum-safe."
- "Quantum beats classical" for any workload measured here.
- Any guarantee about time, log tail completeness or revocation completeness.
- That the prototype's choices are Layer8 semantics. They are explicitly
  local; see §6.

## 5. Phase 11: is Layer8 a "Machine Authority Network" for heterogeneous compute?

**Hypothesis.** Layer8 can become the boundary between INTELLIGENCE (agents),
AUTHORITY, COMPUTE (CPU/GPU/TPU/QPU) and EVIDENCE.

**What supports it in the existing architecture:**

- **Backend neutrality held in practice.** Nothing in the authority path
  needed to know the backend was quantum. Quantum-specific meaning lives in
  four places only:
  - the workload fields (program format, qubits, shots);
  - the backend-class vocabulary;
  - the adapter;
  - the optional classical check.

  The same gate authorized a CPU sampler and a quantum simulator for the
  same workload.
- **Core already has the shape.** It has one decision function, single-use
  authorizations consumed at one linearization point, a broker that consumes
  before it touches credentials, at-most-once adapters with `UNKNOWN`,
  `CLAIMED` provider facts, and a per-dimension independent verifier. A
  compute vertical is mostly a new set of typed fields on existing objects.
- **The router experiment confirms the AUTHORITY/OPTIMIZATION split is
  clean.** Authority is a filter; optimization is a ranking. The two do
  not interfere.

**What the existing architecture does NOT yet support** (each one blocks the
vision; none can be faked):

| Gap | Core status |
|---|---|
| Typed, multi-dimensional budgets (GPU-seconds, shots, QPU-seconds, money) and lifetime counts | Delegation constraints are frozen at v1 (`max_value`, `max_actions_per_day`). Needs a v2 format and migration; blocked |
| Policy evaluation over workload parameters | Core sees an opaque digest only (OD-Q8) |
| Result digest and `UNKNOWN` in receipts | Absent (OD-Q8) |
| GATE and EXECUTOR node roles | Reserved; they authorize nothing |
| Tenant ownership of principals | Undefined spec |
| Signature agility | Ed25519-only (OD-Q1 to Q7) |
| Trusted time, external anchor | Specified or partial, not implemented |
| Execution attestation for any accelerator | **External dependency.** GPUs have confidential-computing attestation (for example NVIDIA H100/Blackwell CC) that could make `provider_execution` `ESTABLISHED` for GPU jobs. QPUs have nothing comparable |

**Verdict.** The architecture *supports the authority half* of a Machine
Authority Network: who may cause which computation, where, at what cost,
under which crypto policy, recorded as evidence. It does **not yet** support
the *evidence-of-execution half* for any accelerator. Where hardware
attestation exists (GPU confidential computing), it is a clear extension.
Where it does not (QPU), it is a hard external limit. **Recommendation:**
pursue it as "governed compute authorization", not as "proof of compute".
Do not build the general network until the core v2 formats (OD-Q8) and the
suite decisions (OD-Q1–Q5) exist. Otherwise every vertical becomes another
opaque-digest workaround.

## 6. Prototype-local choices (not Layer8 semantics)

| Choice | Alternatives | Core decision it touches |
|---|---|---|
| Crypto floor applies chain-wide | root and request only | OD-Q5 |
| Effective level = union of component sets | ordered levels | OD-Q2/Q4 |
| ML-DSA-65 under `l8x.…exp0` | ML-DSA-44/87, SLH-DSA | OD-Q1 |
| Full 256-bit identity ids with the suite in the preimage | truncated ids | OD-Q3 |
| One tenant per delegation; the backend lists its tenants | per-resource ownership | tenant ownership spec |
| Revocation: issuer or operator for delegations; operator for agents | | OD-R2-02 |
| Budgets reserved at authorization, never released | release on failure | matches core usage ledger |
| `valid_until` bounds submission, not completion | bound completion | needs a decision before QPU use |
| The gate's log is signed by the gate key | separate log key | key separation (ROADMAP §7) |

## 7. Next steps, in order, each needing its own go-ahead

1. **A standalone second verifier.**
   - It must import nothing from `quantum_l8`.
   - Add conformance vectors for every suite and for each attack in
     THREAT_MODEL.md, as core does for `layer8_verifier`.
2. **Separate keys:**
   - gate decision and authorization key;
   - log checkpoint key;
   - executor key.

   Map them to core's `GATE` and `EXECUTOR` node roles.
3. **External anchor for log checkpoints** (core anchor contract plus a
   suite field, OD-Q6). Without it, tail truncation and post-break forgery
   stay undetectable.
4. **IBM Runtime adapter** (IBM_QISKIT_ADAPTER.md §3).
   - Needs operator-provided credentials, held behind a `capability_ref`.
   - Needs read-only reconcile.
   - Needs a decision on queue time versus `valid_until`.
   - Run it first against IBM's fake/noisy local backends, then against one
     open-plan device with a tiny shot budget.
5. **Propose to core (owner decisions, not code):**
   - OD-Q8: a v2 `ExecutionAuthorization` and `ExecutionReceipt` with
     workload and result digests and `UNKNOWN`;
   - a typed compute-scope v2 delegation;
   - the backend-class vocabulary.

   Graduate only general-purpose primitives. Quantum SDKs never enter core.
6. **GPU confidential-computing attestation.** This is the first accelerator
   where `provider_execution` could become `ESTABLISHED`. It is the
   strongest test of the Phase 11 thesis.
7. **Arena:**
   - add a GPU leg;
   - add problems with efficiently checkable outputs;
   - add a real-QPU leg once the adapter exists.

   Keep the pre-registered verdict rules unchanged.
8. **Legacy wedge cleanup** (`src/`, `adapters/`). Fix or remove the broken
   adapters and examples (ARCHITECTURE_AUDIT.md §2). This is separate from
   this branch.
