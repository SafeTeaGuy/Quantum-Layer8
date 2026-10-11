"""Phases 6, 7, 10 and the historical-evidence part of Phase 5."""

import json

from quantum_l8 import suites
from quantum_l8.arena import decide_verdict, run_arena
from quantum_l8.contracts import build_workload
from quantum_l8.evidence_log import EvidenceLog, verify_log
from quantum_l8.router import WeightedOptimizer, route
from quantum_l8.scenario import (
    ALG_BELL, BELL_QASM, CPU_BACKEND, QPU_BACKEND, SIM_BACKEND, delegate, make_world, request, trust_roots,
)
from quantum_l8.verify import export_bundle, verify_bundle
from tests.quantum.conftest import decide, make_executor, reasons, state

BACKENDS = [SIM_BACKEND, CPU_BACKEND, QPU_BACKEND]
SIGNALS = {
    "qiskit.basic_simulator": {"available": True, "est_runtime_ms": 50, "est_cost_micro_usd": 0},
    "cpu.exact_sampler": {"available": True, "est_runtime_ms": 5, "est_cost_micro_usd": 0},
    "ibm.qpu.example_heron": {"available": True, "est_queue_ms": 3_600_000, "est_runtime_ms": 5000,
                              "est_cost_micro_usd": 409_600, "error_rate_ppm": 3000},
}


def _wl(n=2):
    return build_workload(ALG_BELL, BELL_QASM, {}, 1024, num_qubits=n)


# --- router ---

def test_router_only_ranks_permitted(world):
    d = route([world.delegation["body"]], _wl(), BACKENDS, SIGNALS, WeightedOptimizer(), log=world.log)
    assert d["status"] == "ROUTED"
    assert d["permitted"] == ["cpu.exact_sampler", "qiskit.basic_simulator"]
    assert "ibm.qpu.example_heron" in d["excluded"]
    assert d["chosen"] == "cpu.exact_sampler"  # cheapest/fastest permitted; classical wins here
    assert world.log.entries[-1]["kind"] == "ROUTING_DECISION"


def test_compromised_optimizer_cannot_route_outside_authority(world):
    d = route([world.delegation["body"]], _wl(), BACKENDS, SIGNALS, WeightedOptimizer(), proposed="ibm.qpu.example_heron")
    assert d["status"] == "ROUTE_NOT_PERMITTED" and d["chosen"] is None
    # And if the agent ignores the router, the gate still refuses.
    assert "BACKEND_NOT_AUTHORIZED" in reasons(decide(world, request(world, backend=QPU_BACKEND)))


def test_router_unavailable_and_region():
    w = make_world()
    delegate(w, backend_ids=["ibm.qpu.example_heron", "qiskit.basic_simulator"],
             backend_classes=["QUANTUM_HARDWARE", "QUANTUM_SIMULATOR"], providers=["ibm-quantum", "qiskit-local"])
    sig = dict(SIGNALS)
    sig["qiskit.basic_simulator"] = {"available": False}
    d = route([w.delegation["body"]], _wl(), BACKENDS, sig, WeightedOptimizer(), allowed_regions=["local"])
    assert d["status"] == "NO_PERMITTED_OPTION"
    assert d["excluded"]["ibm.qpu.example_heron"] == ["REGION_NOT_PERMITTED"]


def test_optimizer_preference_never_overrides_authority():
    w = make_world()
    delegate(w, backend_ids=["ibm.qpu.example_heron"], backend_classes=["QUANTUM_HARDWARE"], providers=["ibm-quantum"])
    sig = {"ibm.qpu.example_heron": {"available": True}}
    d = route([w.delegation["body"]], _wl(), BACKENDS, sig, WeightedOptimizer())
    # The optimizer penalises a QPU for an exactly simulable circuit, but the
    # only permitted option is the QPU, so it is still the one routed.
    assert d["chosen"] == "ibm.qpu.example_heron"


# --- evidence log and re-attestation ---

def test_reattestation_under_new_suite_keeps_history():
    old = suites.KeyBundle.generate(suites.SUITE_ED25519)
    new = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    log = EvidenceLog("log:t", old)
    for i in range(3):
        log.append("X", {"i": i})
    cp_old = log.checkpoint(1)
    before = json.loads(json.dumps(log.entries))
    cp_new = log.reattest(new, 2)
    assert log.entries[:3] == before  # nothing rewritten
    assert cp_new["body"]["prev_checkpoint_digest"] is not None
    assert cp_new["body"]["signature_suite"] == suites.SUITE_HYBRID
    signers = {old.identity_id(): old.public_identity(), new.identity_id(): new.public_identity()}
    assert verify_log(log.export(), signers) == (True, ["LOG_CONSISTENT"])
    # A verifier that trusts only the new key still checks old checkpoints: it must pin both.
    ok, codes = verify_log(log.export(), {new.identity_id(): new.public_identity()})
    assert not ok and codes == ["CHECKPOINT_SIGNER_NOT_PINNED"]
    assert cp_old["body"]["signature_suite"] == suites.SUITE_ED25519


def test_reattestation_does_not_hide_rewrites():
    from quantum_l8.evidence_log import entry_hash
    old = suites.KeyBundle.generate(suites.SUITE_ED25519)
    new = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    log = EvidenceLog("log:t", old)
    log.append("X", {"i": 0})
    log.checkpoint(1)
    log.reattest(new, 2)
    exp = log.export()
    exp["entries"][0]["body"]["i"] = 99
    exp["entries"][0]["entry_hash"] = entry_hash(exp["entries"][0])
    ok, _ = verify_log(exp, {old.identity_id(): old.public_identity(), new.identity_id(): new.public_identity()})
    assert not ok


# --- arena ---

def test_arena_negative_result_is_recorded(world):
    rep = run_arena(6, 0.5, 42, log=world.log)
    assert rep["verdict"] == "CLASSICAL_WINS"
    assert rep["legs"]["quantum_hardware"]["status"] == "NOT_RUN"
    assert world.log.entries[-1]["kind"] == "ARENA_RESULT"


def _leg(family, q, t, simulated=False, repeats=3):
    return {"family": family, "simulated": simulated, "status": "RUN", "repeats": repeats,
            "quality_median": q, "wall_time_s_median": t}


def test_verdict_rules():
    assert decide_verdict({"a": _leg("classical", 1.0, 1.0), "b": _leg("quantum", 1.0, 1.2)})[0] == "NO_MEANINGFUL_ADVANTAGE"
    assert decide_verdict({"a": _leg("classical", 0.9, 1.0), "b": _leg("quantum", 1.0, 9.0)})[0] == "QUANTUM_WINS"
    assert decide_verdict({"a": _leg("classical", 0.9, 1.0), "b": _leg("quantum", 1.0, 9.0, simulated=True)})[0] == \
        "INSUFFICIENT_EVIDENCE"
    assert decide_verdict({"a": _leg("classical", 0.9, 1.0), "h": _leg("hybrid", 1.0, 2.0)})[0] == "HYBRID_WINS"
    assert decide_verdict({"a": _leg("classical", 1.0, 1.0, repeats=2)})[0] == "INSUFFICIENT_EVIDENCE"
    assert decide_verdict({"a": _leg("classical", 1.0, 0.1), "b": _leg("quantum", 1.0, 1.0)})[0] == "CLASSICAL_WINS"


# --- end to end ---

def test_end_to_end_chain_verifies_with_reexecution():
    w = make_world()
    delegate(w)
    req = request(w)
    out = decide(w, req)
    res = make_executor(w).run(out["authorization"], req, BELL_QASM)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    rep = verify_bundle(bundle, json.loads(json.dumps(trust_roots(w))), reexecute=True)
    assert rep["chain_established"], rep["findings"]
    st = {f["dimension"]: f["status"] for f in rep["findings"]}
    assert st["provider_execution"] == "CLAIMED"
    assert st["reexecution"] == "ESTABLISHED"
    assert st["revocation"] == "INSUFFICIENT_EVIDENCE"


def test_end_to_end_cpu_backend_is_labelled_cpu():
    w = make_world()
    delegate(w)
    req = request(w, backend=CPU_BACKEND)
    out = decide(w, req)
    assert state(out) == "AUTHORIZED"
    res = make_executor(w).run(out["authorization"], req, BELL_QASM)
    assert res["receipt"]["body"]["backend_class"] == "CPU"
    assert res["receipt"]["body"]["execution"]["provider_reported_backend"] == "cpu_exact_statevector"


def test_demo_script_runs(tmp_path):
    from examples.quantum_end_to_end import main
    assert main(str(tmp_path)) == 0
    assert (tmp_path / "bundle.json").exists()
