"""Phase 9: adversarial lab. Each test is one row of the matrix in
docs/quantum/THREAT_MODEL.md. Tests named ``test_limit_*`` pin what Layer8
CANNOT prove: they assert the attack is NOT detected, so a future change that
claims otherwise must update the threat model.
"""

import copy
import json

import pytest

from quantum_l8 import suites
from quantum_l8.canonical import digest
from quantum_l8.contracts import REQUEST_DOMAIN, build_revocation
from quantum_l8.executor import RECEIPT_DOMAIN
from quantum_l8.gate import AUTHORIZATION_DOMAIN
from quantum_l8.adapters.qiskit_adapter import CPUExactSamplerAdapter, QiskitBasicSimulatorAdapter
from quantum_l8.scenario import (
    BELL_QASM, CPU_BACKEND, SIM_BACKEND, TENANT, delegate, make_world, request, trust_roots,
)
from quantum_l8.verify import export_bundle, verify_bundle
from tests.quantum.conftest import decide, make_executor, reasons, state


def _run(w, adapters=None, **req_kw):
    req = request(w, **req_kw)
    out = decide(w, req)
    assert state(out) == "AUTHORIZED", reasons(out)
    res = make_executor(w, adapters=adapters).run(out["authorization"], req, BELL_QASM)
    return req, out, res


@pytest.fixture
def evidence():
    w = make_world()
    delegate(w)
    req, out, res = _run(w)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    roots = json.loads(json.dumps(trust_roots(w)))
    assert verify_bundle(bundle, roots)["chain_established"]
    return w, bundle, roots


def _status(report, dim):
    return next(f for f in report["findings"] if f["dimension"] == dim)


def _failed(bundle, roots, dim, code_fragment=None):
    rep = verify_bundle(bundle, roots)
    f = _status(rep, dim)
    assert not rep["chain_established"]
    assert f["status"] == "FAILED", f
    if code_fragment:
        assert any(code_fragment in c for c in f["codes"]), f
    return rep


def _resign_receipt(bundle, key):
    b = bundle["receipt"]["body"]
    b["receipt_id"] = digest({k: v for k, v in b.items() if k != "receipt_id"})
    bundle["receipt"]["proof"] = key.sign(RECEIPT_DOMAIN, b)


# 1. signature downgrade
def test_signature_downgrade_in_bundle(evidence):
    w, bundle, roots = evidence
    body = dict(bundle["request"]["body"], signature_suite=suites.SUITE_ED25519)
    ed = suites.KeyBundle(suites.SUITE_ED25519, {"ed25519": w.agent.keys["ed25519"]})
    bundle["request"] = {"body": body, "proof": ed.sign(REQUEST_DOMAIN, body)}
    _failed(bundle, roots, "request", "SIGNATURE_SUITE_MISMATCH")


# 2. crypto-policy downgrade by a (malicious but key-holding) gate
def test_policy_downgrade_by_gate_detected_by_verifier(evidence):
    w, bundle, roots = evidence
    a = bundle["authorization"]["body"]
    a["crypto_policy"] = suites.REQUIRE_ED25519
    a["authorization_id"] = digest({k: v for k, v in a.items() if k != "authorization_id"})
    bundle["authorization"]["proof"] = w.gate_key.sign(AUTHORIZATION_DOMAIN, a)
    _failed(bundle, roots, "crypto_policy", "AUTHORIZATION_POLICY_NOT_EFFECTIVE_POLICY")


def test_policy_downgrade_by_editing_authorization(evidence):
    _, bundle, roots = evidence
    bundle["authorization"]["body"]["crypto_policy"] = suites.REQUIRE_ED25519
    _failed(bundle, roots, "authorization", "AUTHORIZATION_SIGNATURE")


# 3. backend substitution
def test_backend_substitution_at_request(evidence):
    w = make_world()
    delegate(w)
    lying = dict(SIM_BACKEND, backend_class="CPU")
    assert "BACKEND_CLASS_MISMATCH" in reasons(decide(w, request(w, backend=lying)))


def test_backend_substitution_in_receipt(evidence):
    w, bundle, roots = evidence
    rb = bundle["receipt"]["body"]
    rb["backend_id"], rb["backend_class"] = CPU_BACKEND["backend_id"], "CPU"
    rb["backend_descriptor_digest"] = digest(CPU_BACKEND)
    _resign_receipt(bundle, w.executor_key)  # even the real executor key cannot make this consistent
    _failed(bundle, roots, "receipt", "RECEIPT_BACKEND_ID_MISMATCH")


# 4. fake QPU identity
class _ClaimsHardware(QiskitBasicSimulatorAdapter):
    def submit(self, *a, **k):
        run = super().submit(*a, **k)
        run["provider_reported_backend"] = "ibm_example_heron"
        return run


def test_fake_qpu_identity_detected_when_name_differs():
    w = make_world()
    delegate(w)
    req, out, res = _run(w, adapters=[_ClaimsHardware()])
    rb = res["receipt"]["body"]
    assert rb["outcome"] == "PROVIDER_MISMATCH" and not res["delivered"]
    assert "PROVIDER_REPORTED_BACKEND_NOT_AUTHORIZED" in rb["findings"]


class _ClassicalPretendingToBeSimulator(CPUExactSamplerAdapter):
    adapter_id = QiskitBasicSimulatorAdapter.adapter_id

    def submit(self, *a, **k):
        run = super().submit(*a, **k)
        run["provider_reported_backend"] = "basic_simulator"
        run["reproducibility"] = None
        return run


def test_limit_consistent_provider_lie_is_not_detectable():
    """A provider or adapter that computes classically and reports the expected
    backend name passes every check. Provider execution stays CLAIMED."""
    w = make_world()
    delegate(w)
    req, out, res = _run(w, adapters=[_ClassicalPretendingToBeSimulator()])
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    rep = verify_bundle(bundle, trust_roots(w), reexecute=True)
    assert rep["chain_established"] is True
    assert _status(rep, "provider_execution")["status"] == "CLAIMED"
    assert _status(rep, "reexecution")["status"] == "NOT_CHECKED"


# 5. replayed job (gate) - see also test_gate_agent_control
def test_replayed_job_with_fresh_signature_refused():
    w = make_world()
    delegate(w)
    req = request(w)
    assert state(decide(w, req)) == "AUTHORIZED"
    again = request(w, request_id=req["body"]["request_id"])
    assert "REQUEST_REPLAYED" in reasons(decide(w, again))


# 6. modified circuit
def test_modified_circuit_after_authorization():
    w = make_world()
    delegate(w)
    req = request(w)
    out = decide(w, req)
    evil = BELL_QASM.replace("h q[0];", "x q[0];")
    assert make_executor(w).run(out["authorization"], req, evil) == {"executed": False, "reason": "WORKLOAD_MISMATCH"}
    assert "PROGRAM_DIGEST_MISMATCH" in reasons(decide(w, request(w), program=evil))


def test_modified_circuit_in_bundle(evidence):
    _, bundle, roots = evidence
    bundle["program"] = bundle["program"].replace("h q[0];", "x q[0];")
    _failed(bundle, roots, "request", "PROGRAM_BYTES_MISMATCH")


# 7. modified parameters / shots
def test_modified_parameters_or_shots(evidence):
    _, bundle, roots = evidence
    b1 = copy.deepcopy(bundle)
    b1["request"]["body"]["workload"]["shots"] = 1
    _failed(b1, roots, "request", "REQUEST_SIGNATURE")
    b2 = copy.deepcopy(bundle)
    b2["receipt"]["body"]["parameters"] = {"theta": "3.14"}
    _failed(b2, roots, "receipt", "RECEIPT_SIGNATURE")


# 8. forged result
def test_forged_result(evidence):
    _, bundle, roots = evidence
    bundle["receipt"]["body"]["result"]["counts"] = {"00": 1024}
    bundle["receipt"]["body"]["result_digest"] = digest(bundle["receipt"]["body"]["result"])
    _failed(bundle, roots, "receipt", "RECEIPT_SIGNATURE")


def test_limit_executor_key_holder_can_forge_result(evidence):
    """A compromised executor key can sign a false result. Detected only where
    re-execution or classical checking is possible."""
    w, bundle, roots = evidence
    bundle["receipt"]["body"]["result"]["counts"] = {"00": 600, "11": 424}
    bundle["receipt"]["body"]["result_digest"] = digest(bundle["receipt"]["body"]["result"])
    _resign_receipt(bundle, w.executor_key)
    # the forger also controls the log only if it holds the log key; here it does not,
    # so the log binding fails. With both keys, only re-execution would catch it:
    assert _status(verify_bundle(bundle, roots), "log_binding")["status"] == "FAILED"
    rep = verify_bundle(bundle, roots, reexecute=True)
    assert _status(rep, "reexecution")["status"] == "FAILED"
    assert _status(rep, "classical_consistency")["status"] == "FAILED"


# 9. receipt substitution
def test_receipt_substitution():
    w = make_world()
    delegate(w)
    req1, out1, res1 = _run(w)
    req2, out2, res2 = _run(w)
    bundle = json.loads(json.dumps(export_bundle(w, req1, BELL_QASM, out1, res2["receipt"])))
    _failed(bundle, json.loads(json.dumps(trust_roots(w))), "receipt", "RECEIPT_AUTHORIZATION_ID_MISMATCH")


# 10. cross-domain delegation
def test_cross_domain_delegation():
    home, foreign = make_world(), make_world()
    foreign_deleg = delegate(foreign)
    home.identities.register(foreign.principal.public_identity())
    home.identities.register(foreign.agent.public_identity())
    home.gate.register_delegation(foreign_deleg)
    home.delegation = foreign_deleg
    req = request(home, agent=foreign.agent, principal_id=foreign.principal.identity_id())
    out = decide(home, req)
    assert state(out) == "DENIED" and "ROOT_PRINCIPAL_NOT_PERMITTED" in reasons(out)


# 11/12. revoked and expired authority, seen by the verifier
def test_revocation_in_log_before_execution_fails_verification(evidence):
    w, bundle, roots = evidence
    # Fabricated: insert a revocation that predates execution. The log hash
    # chain breaks, which is what the verifier reports first.
    entries = bundle["evidence_log"]["entries"]
    entries.insert(1, {"seq": 1, "prev_hash": entries[0]["entry_hash"], "kind": "REVOCATION_RECORDED",
                       "body": {"target_id": w.delegation["body"]["delegation_id"], "effective_at_ms": 0},
                       "entry_hash": "00" * 32})
    _failed(bundle, roots, "evidence_log")


def test_expired_authorization_window_in_bundle(evidence):
    w, bundle, roots = evidence
    rb = bundle["receipt"]["body"]
    rb["execution"]["submitted_at_ms"] = bundle["authorization"]["body"]["valid_until_ms"] + 1
    _resign_receipt(bundle, w.executor_key)
    _failed(bundle, roots, "receipt", "SUBMITTED_OUTSIDE_AUTHORIZATION_WINDOW")


# 13. key substitution
def test_agent_key_substitution(evidence):
    _, bundle, roots = evidence
    attacker = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    aid = bundle["request"]["body"]["agent_id"]
    bundle["identities"][aid] = attacker.public_identity()
    _failed(bundle, roots, "identities", "IDENTITY_NOT_BOUND_TO_KEY")


def test_executor_key_substitution(evidence):
    _, bundle, roots = evidence
    attacker = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    bundle["receipt"]["body"]["executor_id"] = attacker.identity_id()
    _resign_receipt(bundle, attacker)
    _failed(bundle, roots, "receipt", "EXECUTOR_NOT_PINNED")


# 14/15. evidence deletion and reordering
def test_evidence_deletion(evidence):
    _, bundle, roots = evidence
    del bundle["evidence_log"]["entries"][2]
    _failed(bundle, roots, "evidence_log", "LOG_SEQ_GAP_OR_REORDER")


def test_evidence_reordering(evidence):
    _, bundle, roots = evidence
    e = bundle["evidence_log"]["entries"]
    e[1], e[2] = e[2], e[1]
    _failed(bundle, roots, "evidence_log")


def test_evidence_rewrite_with_recomputed_hashes(evidence):
    """Rewriting an entry and recomputing the chain is caught by the signed checkpoint."""
    from quantum_l8.evidence_log import entry_hash
    _, bundle, roots = evidence
    e = bundle["evidence_log"]["entries"]
    e[1]["body"]["state"] = "DENIED"
    prev = e[0]["entry_hash"]
    for x in e[1:]:
        x["prev_hash"] = prev
        x["entry_hash"] = entry_hash(x)
        prev = x["entry_hash"]
    _failed(bundle, roots, "evidence_log", "CHECKPOINT_HEAD_MISMATCH")


def test_limit_tail_truncation_after_last_checkpoint_undetected():
    """Entries appended after the newest checkpoint the verifier holds can be
    removed together with any later checkpoint. Needs an external anchor."""
    w = make_world()
    delegate(w)
    req, out, res = _run(w)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    w.gate.record_revocation(build_revocation(w.principal, "DELEGATION", w.delegation["body"]["delegation_id"], w.now()))
    w.log.checkpoint(w.now())
    full = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    truncated = copy.deepcopy(full)
    truncated["evidence_log"]["entries"] = truncated["evidence_log"]["entries"][:len(bundle["evidence_log"]["entries"])]
    truncated["evidence_log"]["checkpoints"] = truncated["evidence_log"]["checkpoints"][:len(bundle["evidence_log"]["checkpoints"])]
    assert verify_bundle(truncated, trust_roots(w))["chain_established"] is True


# 16. classical result represented as quantum
def test_classical_run_relabelled_as_quantum():
    w = make_world()
    delegate(w)
    req, out, res = _run(w, backend=CPU_BACKEND)
    assert res["receipt"]["body"]["backend_class"] == "CPU"
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    bundle["receipt"]["body"]["backend_class"] = "QUANTUM_SIMULATOR"
    _failed(bundle, trust_roots(w), "receipt", "RECEIPT_SIGNATURE")
    _resign_receipt(bundle, w.executor_key)
    _failed(bundle, trust_roots(w), "receipt", "RECEIPT_BACKEND_CLASS_MISMATCH")


# 17. quantum result presented as coming from another backend
def test_result_moved_to_other_backends_receipt():
    w = make_world()
    delegate(w)
    _, _, sim = _run(w)
    req, out, cpu = _run(w, backend=CPU_BACKEND)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, cpu["receipt"])))
    bundle["receipt"]["body"]["result"] = sim["receipt"]["body"]["result"]
    bundle["receipt"]["body"]["result_digest"] = sim["receipt"]["body"]["result_digest"]
    _failed(bundle, trust_roots(w), "receipt", "RECEIPT_SIGNATURE")


# stolen request
def test_stolen_request_gives_thief_nothing():
    """A thief who replays the victim's signed request cannot change the
    destination or tenant; at worst it pre-empts the victim (single use)."""
    w = make_world()
    delegate(w)
    req = request(w)
    assert "TENANT_MISMATCH" in reasons(decide(w, req, tenant="tenant:thief"))
    out = decide(w, req)  # same tenant: the thief submits first
    assert state(out) == "AUTHORIZED"
    assert out["authorization"]["body"]["result_destination"] == req["body"]["result_destination"]
    assert "REQUEST_REPLAYED" in reasons(decide(w, req))  # victim is pre-empted (availability, not authority)


def test_malformed_bundle_is_a_named_failure(evidence):
    _, bundle, roots = evidence
    del bundle["receipt"]["body"]["execution"]
    rep = verify_bundle(bundle, roots)
    assert rep["chain_established"] is False
    assert any(f["status"] == "FAILED" for f in rep["findings"])
