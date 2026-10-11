# IBM / Qiskit adapter

> **What runs today:** Qiskit 2.x locally, through the seeded
> `BasicSimulator` (`QUANTUM_SIMULATOR`), plus a classical exact sampler
> (`CPU`).
>
> **What does not run:** no IBM Quantum hardware job was submitted. This
> environment has no IBM credentials, and an adapter nobody can test is not
> shipped. §3 says exactly what an IBM Runtime adapter would capture.

## 1. Boundary

`quantum_l8/adapters/` is the only place an SDK is imported. The contracts,
gate, executor, receipt and verifier contain no IBM or Qiskit names, apart
from the optional re-execution helper the verifier calls for reproducible
runs.

```python
class ProviderAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    def preflight(program_text, workload, descriptor) -> str | None: ...  # refuse-only, BEFORE consumption
    def submit(program_text, workload, descriptor, idempotency_key) -> ProviderRun: ...  # exactly once, AFTER consumption
    def ideal_distribution(program_text, workload) -> dict | None: ...  # optional classical check
```

| Core broker method | Adapter method here |
|---|---|
| `validate_parameters` / `check_binding` | `preflight` |
| `invoke` | `submit` |

The adapter never sees the delegation, the request signature or the gate
key. It receives the authorization id only as an idempotency tag.

## 2. Implemented adapters

| | `QiskitBasicSimulatorAdapter` | `CPUExactSamplerAdapter` |
|---|---|---|
| adapter_id | `l8x.adapter.qiskit-basic-simulator.v0` | `l8x.adapter.cpu-exact-sampler.v0` |
| Input | OpenQASM 3 (`qiskit.qasm3.loads`, via `qiskit-qasm3-import`); `input float[64]` parameters bound from decimal strings | same |
| Preflight refusals | `PROGRAM_UNPARSEABLE`, `PARAMETER_SET_MISMATCH`, `DECLARED_QUBITS_MISMATCH`, `QUBITS_EXCEED_BACKEND`, `PROGRAM_HAS_NO_MEASUREMENT` | the same, plus `CLASSICAL_EXACT_UNSUPPORTED_FOR_PROGRAM` |
| Execution | `transpile(seed_transpiler)` then `BasicSimulator.run(shots, seed_simulator)` | exact statevector, then `numpy` multinomial (seeded) |
| Provider facts reported | `job_id`, `result.backend_name`, `backend_version`, Qiskit version, `time_taken`, digest of the **transpiled** circuit | `cpu_exact_statevector`, numpy version |
| Reproducible? | yes: the verifier re-runs and compares counts bit for bit | yes |
| Classical check | ideal statevector TVD for ≤ 16 qubits with identity measurement | same |

## 3. IBM Quantum Runtime adapter: design (not implemented)

**Descriptor** (already registered in `scenario.py` as an example):

```
backend_class           = QUANTUM_HARDWARE
provider                = ibm-quantum
adapter_id              = l8x.adapter.ibm-runtime.v0
provider_backend_names  = [<exact IBM backend name>]
pricing                 = operator-configured
```

**Credentials** stay outside Layer8 objects:

- Stored behind an operator-provisioned handle: core broker `capability_ref`,
  tenant-scoped.
- Never in a request, delegation, receipt or log.

**What the adapter would record**, with every item labelled
PROVIDER_REPORTED unless stated:

| Item | Source (qiskit-ibm-runtime) | Why it matters |
|---|---|---|
| Runtime job id | `job.job_id()` | Lets an auditor holding the account query IBM later |
| Backend name, as the job reports it | `job.backend().name` | Compared with `provider_backend_names` → `PROVIDER_MISMATCH` |
| Primitive and version, execution options (shots, error-mitigation settings) | `SamplerV2` options, job inputs | Mitigation changes the statistics; it must be bound |
| ISA circuit digest | adapter-computed over the transpiled circuit (preset pass manager, `seed_transpiler`) | Authorized ≠ executed circuit (PROOF_OF_COMPUTE.md §4.3) |
| Calibration snapshot reference | `backend.properties()` / target `last_update_date`, digest of the properties document | Lets results be read against device state. **Fetched, not attested** |
| Timestamps (created, running, finished) | job metrics | Provider clock |
| Usage (quantum seconds) | job usage / metrics | Compared with the reserved cost → `cost.overrun` |
| Status | `job.status()`; any non-terminal or error state → `UNKNOWN` | Never infer success |

**Required behaviour:**

- **Submit exactly once.**
  - A timeout, lost poll or SDK exception gives `UNKNOWN`.
  - A later read-only `reconcile`, keyed by the stored job id, may move
    `UNKNOWN` to a reported state.
  - It never re-submits and never re-consumes (the core broker's
    reconcile pattern).
- **Queue time can exceed the authorization window.** The authorization's
  `valid_until` bounds *submission*. A completion after it is recorded with
  the executor's observed time and is not an authorization failure. This
  is a prototype-local choice and must be decided explicitly before
  hardware use.
- **No correctness claim.** For circuits beyond about 16 qubits the
  classical check is `NOT_CHECKED`.

## 4. What IBM does not provide (the proof model's limit)

- A signature over job results that a third party can verify offline.
  Results come over an authenticated TLS session to the account holder.
- Hardware, firmware or TEE attestation that a specific QPU executed a
  specific circuit.
- A public, append-only job log.

Layer8 can therefore show that its executor *received* the result from the
IBM API under its account. It cannot show that IBM's hardware *produced*
it. That is why `provider_execution` is `CLAIMED` and never `ESTABLISHED`.

## 5. How to run

```
pip install -r requirements.txt -r requirements-quantum.txt
python -m examples.quantum_end_to_end ./quantum_demo_out    # writes bundle.json + trust_roots.json
python -m quantum_l8.verify ./quantum_demo_out/bundle.json ./quantum_demo_out/trust_roots.json --reexecute
python -m examples.quantum_arena
pytest tests/quantum -q
```
