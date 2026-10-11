"""A reproducible scenario: principal -> delegation -> agent -> gate -> executor.

Used by the end-to-end demo and the tests. The "agent" is a scripted
stand-in for an AI agent: it holds its own key and signs requests. No model
is involved; the authority model does not depend on what the agent is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from quantum_l8 import suites
from quantum_l8.canonical import digest
from quantum_l8.contracts import (
    backend_descriptor,
    build_delegation,
    build_request,
    build_workload,
)
from quantum_l8.evidence_log import EvidenceLog
from quantum_l8.gate import IdentityRegistry, QuantumTrustGate, build_gate_policy

T0 = 1_790_000_000_000  # fixed epoch ms for reproducible scenarios
HOUR = 3_600_000

TENANT = "tenant:acme-research"
ALG_BELL = "l8x.alg.bell-state-sampling.v0"
ALG_ROT = "l8x.alg.parametrized-bell-sampling.v0"
DEST = "dest:acme/results/quantum"

BELL_QASM = """OPENQASM 3.0;
include "stdgates.inc";
qubit[2] q;
bit[2] c;
h q[0];
cx q[0], q[1];
c = measure q;
"""

ROT_QASM = """OPENQASM 3.0;
include "stdgates.inc";
input float[64] theta;
qubit[2] q;
bit[2] c;
ry(theta) q[0];
cx q[0], q[1];
c = measure q;
"""

SIM_BACKEND = backend_descriptor(
    backend_id="qiskit.basic_simulator",
    backend_class="QUANTUM_SIMULATOR",
    provider="qiskit-local",
    adapter_id="l8x.adapter.qiskit-basic-simulator.v0",
    provider_backend_names=["basic_simulator"],
    max_qubits=24,
    per_job_micro_usd=0,
    per_shot_micro_usd=0,
    allowed_tenants=[TENANT],
    region="local",
)
CPU_BACKEND = backend_descriptor(
    backend_id="cpu.exact_sampler",
    backend_class="CPU",
    provider="local-cpu",
    adapter_id="l8x.adapter.cpu-exact-sampler.v0",
    provider_backend_names=["cpu_exact_statevector"],
    max_qubits=16,
    per_job_micro_usd=0,
    per_shot_micro_usd=0,
    allowed_tenants=[TENANT],
    region="local",
)
# Registered so authority can name it; no adapter exists in this environment.
QPU_BACKEND = backend_descriptor(
    backend_id="ibm.qpu.example_heron",
    backend_class="QUANTUM_HARDWARE",
    provider="ibm-quantum",
    adapter_id="l8x.adapter.ibm-runtime.v0",
    provider_backend_names=["ibm_example_heron"],
    max_qubits=133,
    per_job_micro_usd=0,
    per_shot_micro_usd=400,  # illustrative operator-configured price, not a quote
    allowed_tenants=[TENANT],
    region="us",
)


@dataclass
class World:
    suite: str
    principal: suites.KeyBundle
    agent: suites.KeyBundle
    operator: suites.KeyBundle
    gate_key: suites.KeyBundle
    executor_key: suites.KeyBundle
    identities: IdentityRegistry
    log: EvidenceLog
    gate: QuantumTrustGate
    policy: dict
    delegation: dict | None = None
    clock_ms: list = field(default_factory=lambda: [T0])

    def now(self) -> int:
        return self.clock_ms[0]

    def advance(self, ms: int) -> None:
        self.clock_ms[0] += ms


def make_world(suite: str = suites.SUITE_HYBRID, crypto_floor: str | None = None,
               backends: list[dict] | None = None) -> World:
    principal = suites.KeyBundle.generate(suite)
    agent = suites.KeyBundle.generate(suite)
    operator = suites.KeyBundle.generate(suite)
    gate_key = suites.KeyBundle.generate(suite)
    executor_key = suites.KeyBundle.generate(suite)
    reg = IdentityRegistry()
    for k in (principal, agent, operator, gate_key, executor_key):
        reg.register(k.public_identity())
    floor = crypto_floor or (suites.REQUIRE_HYBRID if suite == suites.SUITE_HYBRID else suites.REQUIRE_ED25519)
    policy = build_gate_policy(
        policy_id="policy:acme-quantum-exp",
        operator_id=operator.identity_id(),
        root_principal_ids=[principal.identity_id()],
        crypto_floor=floor,
        backends=backends or [SIM_BACKEND, CPU_BACKEND, QPU_BACKEND],
        executor_ids=[executor_key.identity_id()],
    )
    log = EvidenceLog("log:acme-quantum-exp", gate_key)
    gate = QuantumTrustGate(gate_key, policy, reg, log)
    return World(suite, principal, agent, operator, gate_key, executor_key, reg, log, gate, policy)


def delegate(w: World, **overrides) -> dict:
    args = dict(
        subject_id=w.agent.identity_id(),
        tenant_id=TENANT,
        algorithm_ids=[ALG_BELL, ALG_ROT],
        backend_ids=["qiskit.basic_simulator", "cpu.exact_sampler"],
        backend_classes=["CPU", "QUANTUM_SIMULATOR"],
        providers=["local-cpu", "qiskit-local"],
        max_shots_per_execution=4096,
        max_executions=3,
        max_cost_micro_usd_per_execution=50_000,
        max_total_cost_micro_usd=100_000,
        result_destinations=[DEST],
        crypto_policy=suites.REQUIRE_HYBRID if w.suite == suites.SUITE_HYBRID else suites.REQUIRE_ED25519,
        not_before_ms=w.now() - 1,
        expires_at_ms=w.now() + HOUR,
    )
    issuer = overrides.pop("issuer", w.principal)
    args.update(overrides)
    env = build_delegation(issuer, **args)
    w.gate.register_delegation(env)
    w.delegation = env
    return env


def request(w: World, delegation_ids: list[str] | None = None, program: str = BELL_QASM,
            algorithm_id: str = ALG_BELL, parameters: dict | None = None, shots: int = 1024,
            backend: dict = SIM_BACKEND, agent: suites.KeyBundle | None = None, **overrides) -> dict:
    agent = agent or w.agent
    workload = build_workload(algorithm_id, program, parameters or {}, shots, num_qubits=2)
    args = dict(
        principal_id=w.principal.identity_id(),
        tenant_id=TENANT,
        delegation_ids=delegation_ids or [w.delegation["body"]["delegation_id"]],
        workload=workload,
        backend=backend,
        max_qubits=4,
        max_runtime_ms=60_000,
        cost_limit_micro_usd=10_000,
        execution_deadline_ms=w.now() + 10 * 60_000,
        result_destination=DEST,
        crypto_policy=suites.REQUIRE_HYBRID if w.suite == suites.SUITE_HYBRID else suites.REQUIRE_ED25519,
        created_at_ms=w.now(),
    )
    args.update(overrides)
    return build_request(agent, **args)


def trust_roots(w: World) -> dict:
    """What an independent verifier pins out of band."""
    return {
        "schema_version": "l8x.quantum-verifier-trust-roots.v0",
        "root_principals": {w.principal.identity_id(): w.principal.public_identity()},
        "gate": w.gate_key.public_identity(),
        "executors": {w.executor_key.identity_id(): w.executor_key.public_identity()},
        "log_signers": {w.gate_key.identity_id(): w.gate_key.public_identity()},
        "gate_policy_digest": digest(w.policy),
    }
