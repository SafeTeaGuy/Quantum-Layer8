"""Qiskit adapters: the first concrete provider adapters (EXPERIMENTAL).

* ``QiskitBasicSimulatorAdapter``: OpenQASM 3 -> Qiskit circuit -> the local
  ``BasicSimulator`` with an explicit seed. The run is reproducible, so a third
  party can re-execute it and compare counts bit for bit.
* ``CPUExactSamplerAdapter``: a classical alternative for the same workload.
  It computes the exact output distribution as a statevector on the CPU and
  samples it with a seeded classical RNG. It is a CPU backend; it never
  claims to be quantum.

No IBM Quantum hardware adapter is implemented: this environment has no IBM
credentials and nothing would test it. See docs/quantum/IBM_QISKIT_ADAPTER.md
for what such an adapter would capture and what IBM does not provide.
"""

from __future__ import annotations

from decimal import Decimal

import numpy as np

ADAPTER_VERSION = "0.1.0"


def _qiskit():
    import qiskit
    from qiskit import qasm3, transpile
    from qiskit.providers.basic_provider import BasicSimulator
    from qiskit.quantum_info import Statevector

    return qiskit, qasm3, transpile, BasicSimulator, Statevector


def load_circuit(program_text: str, workload: dict):
    _, qasm3, _, _, _ = _qiskit()
    qc = qasm3.loads(program_text)
    names = {p.name: p for p in qc.parameters}
    if set(names) != set(workload["parameters"]):
        raise ValueError("PARAMETER_SET_MISMATCH")
    if names:
        qc = qc.assign_parameters({names[k]: float(Decimal(v)) for k, v in workload["parameters"].items()})
    return qc


def _identity_measured(qc) -> bool:
    """True iff every measurement maps qubit i -> clbit i and all qubits are measured."""
    measured = {}
    for inst in qc.data:
        if inst.operation.name == "measure":
            q = qc.find_bit(inst.qubits[0]).index
            c = qc.find_bit(inst.clbits[0]).index
            measured[q] = c
    return len(measured) == qc.num_qubits and all(q == c for q, c in measured.items()) and qc.num_clbits == qc.num_qubits


def _preflight(program_text: str, workload: dict, descriptor: dict) -> str | None:
    try:
        qc = load_circuit(program_text, workload)
    except ValueError as e:
        return str(e) if str(e).isupper() else "PROGRAM_UNPARSEABLE"
    except Exception:
        return "PROGRAM_UNPARSEABLE"
    if qc.num_qubits != workload["num_qubits"]:
        return "DECLARED_QUBITS_MISMATCH"
    if qc.num_qubits > descriptor["max_qubits"]:
        return "QUBITS_EXCEED_BACKEND"
    if qc.num_clbits == 0:
        return "PROGRAM_HAS_NO_MEASUREMENT"
    return None


def ideal_probabilities(program_text: str, workload: dict) -> dict[str, float] | None:
    """Exact output distribution, only for circuits with identity measurement
    mapping and at most 16 qubits. None means 'not classically checked'."""
    _, _, _, _, Statevector = _qiskit()
    qc = load_circuit(program_text, workload)
    if qc.num_qubits > 16 or not _identity_measured(qc):
        return None
    sv = Statevector.from_instruction(qc.remove_final_measurements(inplace=False))
    return {k: float(v) for k, v in sv.probabilities_dict().items() if v > 1e-12}


class QiskitBasicSimulatorAdapter:
    adapter_id = "l8x.adapter.qiskit-basic-simulator.v0"
    adapter_version = ADAPTER_VERSION

    def __init__(self, seed: int = 1234):
        self.seed = seed

    def preflight(self, program_text, workload, descriptor):
        return _preflight(program_text, workload, descriptor)

    def submit(self, program_text, workload, descriptor, idempotency_key):
        qiskit, _, transpile, BasicSimulator, _ = _qiskit()
        from hashlib import sha256
        from qiskit import qasm3
        qc = load_circuit(program_text, workload)
        backend = BasicSimulator()
        executed = transpile(qc, backend, seed_transpiler=self.seed)
        executed_digest = sha256(qasm3.dumps(executed).encode("utf-8")).hexdigest()
        job = backend.run(executed, shots=workload["shots"], seed_simulator=self.seed)
        result = job.result()
        counts = {str(k): int(v) for k, v in sorted(result.get_counts().items())}
        return {
            "provider_job_id": str(job.job_id()),
            "provider_reported_backend": str(result.backend_name),
            "provider_reported_status": "COMPLETED" if result.success else "FAILED",
            "shots_reported": sum(counts.values()),
            "counts": counts,
            "provider_metadata": {
                "backend_version": str(result.backend_version),
                "qiskit_version": str(qiskit.__version__),
                "time_taken_s": format(float(result.time_taken), ".6f"),
                # The circuit actually submitted after transpilation. It differs
                # from the authorized program; the authorized digest is the
                # program text, this one is what the provider was given.
                "submitted_circuit_digest": executed_digest,
                "idempotency_key": idempotency_key,
            },
            "reproducibility": {
                "method": "qiskit-basic-simulator-seeded",
                "seed_simulator": self.seed,
                "qiskit_version": str(qiskit.__version__),
            },
            "reported_cost_micro_usd": 0,
        }

    def ideal_distribution(self, program_text, workload):
        return ideal_probabilities(program_text, workload)


class CPUExactSamplerAdapter:
    adapter_id = "l8x.adapter.cpu-exact-sampler.v0"
    adapter_version = ADAPTER_VERSION

    def __init__(self, seed: int = 1234):
        self.seed = seed

    def preflight(self, program_text, workload, descriptor):
        reason = _preflight(program_text, workload, descriptor)
        if reason is None and ideal_probabilities(program_text, workload) is None:
            return "CLASSICAL_EXACT_UNSUPPORTED_FOR_PROGRAM"
        return reason

    def submit(self, program_text, workload, descriptor, idempotency_key):
        probs = ideal_probabilities(program_text, workload)
        keys = sorted(probs)
        p = np.array([probs[k] for k in keys])
        p = p / p.sum()
        rng = np.random.default_rng(self.seed)
        draws = rng.multinomial(workload["shots"], p)
        counts = {k: int(n) for k, n in zip(keys, draws) if n}
        return {
            "provider_job_id": f"cpu-{idempotency_key[:16]}",
            "provider_reported_backend": "cpu_exact_statevector",
            "provider_reported_status": "COMPLETED",
            "shots_reported": sum(counts.values()),
            "counts": counts,
            "provider_metadata": {"numpy_version": np.__version__, "idempotency_key": idempotency_key},
            "reproducibility": {"method": "numpy-multinomial-seeded", "seed": self.seed},
            "reported_cost_micro_usd": 0,
        }

    def ideal_distribution(self, program_text, workload):
        return ideal_probabilities(program_text, workload)


def reexecute(adapter_id: str, program_text: str, workload: dict, reproducibility: dict) -> dict | None:
    """Independent re-execution for reproducible (simulated/classical) runs.
    Returns counts, or None if the run is not reproducible here."""
    if adapter_id == QiskitBasicSimulatorAdapter.adapter_id and reproducibility.get("method") == "qiskit-basic-simulator-seeded":
        a = QiskitBasicSimulatorAdapter(seed=reproducibility["seed_simulator"])
    elif adapter_id == CPUExactSamplerAdapter.adapter_id and reproducibility.get("method") == "numpy-multinomial-seeded":
        a = CPUExactSamplerAdapter(seed=reproducibility["seed"])
    else:
        return None
    run = a.submit(program_text, workload, {"max_qubits": 10**6}, "reexecution")
    return run["counts"]
