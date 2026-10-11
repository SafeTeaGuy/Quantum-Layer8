"""Regressions for defects found by an adversarial review of the prototype.

Each was reproduced before the fix. "Malicious gate" cases wrap the gate's
evaluation to drop one reason code: the gate key is genuine, the decision is
wrong, and the independent verifier must still catch it.
"""

import json

from quantum_l8 import suites
from quantum_l8.adapters.qiskit_adapter import QiskitBasicSimulatorAdapter
from quantum_l8.canonical import digest
from quantum_l8.contracts import REVOCATION_DOMAIN, REVOCATION_SCHEMA, backend_descriptor, build_revocation
from quantum_l8.scenario import BELL_QASM, SIM_BACKEND, TENANT, delegate, make_world, request, trust_roots
from quantum_l8.verify import export_bundle, verify_bundle
from tests.quantum.conftest import decide, make_executor, reasons, state


def _raw_revocation(issuer, target_kind, target_id, effective_at_ms):
    body = {"schema_version": REVOCATION_SCHEMA, "issuer_id": issuer.identity_id(), "target_kind": target_kind,
            "target_id": target_id, "effective_at_ms": effective_at_ms, "signature_suite": issuer.suite}
    body["revocation_id"] = digest(body)
    return {"body": body, "proof": issuer.sign(REVOCATION_DOMAIN, body)}


# 1, 2: revocation with a missing / wrong-typed effective time was "recorded" but not enforced, or crashed.
def test_revocation_effective_time_must_be_an_int(world):
    did = world.delegation["body"]["delegation_id"]
    for bad in (None, "0", True, -1, 1.5):
        rv = _raw_revocation(world.operator, "AGENT", world.agent.identity_id(), bad) if bad != 1.5 else \
            {"body": {"effective_at_ms": 1.5}, "proof": {}}
        assert world.gate.record_revocation(rv) == "REVOCATION_MALFORMED", bad
    assert world.gate.record_revocation(_raw_revocation(world.principal, "DELEGATION", did, "0")) == "REVOCATION_MALFORMED"
    assert world.gate.record_revocation(_raw_revocation(world.principal, "DELEGATION", "not-an-id", 0)) == \
        "REVOCATION_MALFORMED"
    assert state(decide(world, request(world))) == "AUTHORIZED"
    # A valid revocation afterwards still records and is enforced.
    assert world.gate.record_revocation(build_revocation(world.principal, "DELEGATION", did, world.now())) == \
        "REVOCATION_RECORDED"
    assert state(decide(world, request(world))) == "REVOKED"


# 3: unhashable crypto_policy crashed the shape check before authentication.
def test_unhashable_crypto_policy_is_malformed(world):
    for bad in (["REQUIRE_ED25519"], {}):
        r = request(world)
        r["body"]["crypto_policy"] = bad
        assert reasons(decide(world, r)) == ["REQUEST_MALFORMED"]


# 4: un-encodable program text crashed the gate and the executor.
def test_unencodable_program_text(world):
    out = world.gate.decide(request(world), "\ud800", TENANT, world.now(), world.executor_key.identity_id())
    assert "PROGRAM_MALFORMED" in reasons(out)
    req = request(world)
    ok = decide(world, req)
    assert make_executor(world).run(ok["authorization"], req, "\ud800")["reason"] == "AUTHORIZATION_OR_REQUEST_MALFORMED"
    assert make_executor(world).run({}, req, BELL_QASM)["reason"] == "AUTHORIZATION_OR_REQUEST_MALFORMED"


# 5: malformed provider output after consumption left no receipt.
class _FloatMeta(QiskitBasicSimulatorAdapter):
    def submit(self, *a, **k):
        r = super().submit(*a, **k)
        r["provider_metadata"]["time_taken_s"] = 0.0123
        return r


class _NoCounts(QiskitBasicSimulatorAdapter):
    def submit(self, *a, **k):
        r = super().submit(*a, **k)
        r["counts"] = None
        return r


def test_malformed_provider_output_yields_unknown_receipt(world):
    for adapter, code in ((_FloatMeta(), "PROVIDER_OUTPUT_MALFORMED:NOT_CANONICAL"),
                          (_NoCounts(), "PROVIDER_OUTPUT_MALFORMED:FIELD:counts")):
        req = request(world)
        out = decide(world, req)
        res = make_executor(world, adapters=[adapter]).run(out["authorization"], req, BELL_QASM)
        rb = res["receipt"]["body"]
        assert rb["outcome"] == "UNKNOWN" and code in rb["findings"] and rb["result"] is None
        assert res["delivered"] is False
        assert world.log.entries[-1]["kind"] == "EXECUTION_RECEIPT"


# 6: verifier did not re-derive tenant, cost-estimate and qubit-limit checks.
def _malicious_gate_bundle(drop: str, backend=SIM_BACKEND, w=None, **req_kw):
    w = w or make_world()
    delegate(w)
    honest = w.gate._evaluate

    def lenient(*a, **k):
        rs, chain, req = honest(*a, **k)
        return [x for x in rs if x != drop], chain, req
    w.gate._evaluate = lenient
    req = request(w, backend=backend, **req_kw)
    out = w.gate.decide(req, BELL_QASM, req["body"]["tenant_id"], w.now(), w.executor_key.identity_id())
    assert state(out) == "AUTHORIZED", reasons(out)
    res = make_executor(w).run(out["authorization"], req, BELL_QASM)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    return verify_bundle(bundle, json.loads(json.dumps(trust_roots(w))))


def _scope_codes(rep):
    return next(f for f in rep["findings"] if f["dimension"] == "authorization_scope")["codes"]


def test_verifier_rederives_tenant():
    rep = _malicious_gate_bundle("TENANT_MISMATCH", tenant_id="tenant:other-co")
    assert not rep["chain_established"] and "TENANT_MISMATCH" in _scope_codes(rep)


def test_verifier_rederives_qubit_limit():
    rep = _malicious_gate_bundle("QUBITS_EXCEED_REQUEST_LIMIT", max_qubits=1)
    assert not rep["chain_established"] and "QUBITS_EXCEED_REQUEST_LIMIT" in _scope_codes(rep)


def test_verifier_rederives_cost_estimate():
    pricey = backend_descriptor("qiskit.basic_simulator", "QUANTUM_SIMULATOR", "qiskit-local",
                                "l8x.adapter.qiskit-basic-simulator.v0", ["basic_simulator"], 24,
                                per_job_micro_usd=40_000, per_shot_micro_usd=0, allowed_tenants=[TENANT], region="local")
    w = make_world(backends=[pricey])
    rep = _malicious_gate_bundle("COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT", backend=pricey, w=w)
    assert not rep["chain_established"] and "COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT" in _scope_codes(rep)


# 7: verifier ignored issuer revocations; a logged revocation did not block the chain.
def _revoked_then_executed(target):
    w = make_world()
    delegate(w)
    tid = {"delegation": w.delegation["body"]["delegation_id"], "principal": w.principal.identity_id()}[target]
    kind, issuer = ("DELEGATION", w.principal) if target == "delegation" else ("AGENT", w.operator)
    assert w.gate.record_revocation(build_revocation(issuer, kind, tid, w.now())) == "REVOCATION_RECORDED"
    honest = w.gate._evaluate
    w.gate._evaluate = lambda *a, **k: ([], *honest(*a, **k)[1:])  # gate ignores revocation
    w.gate._is_revoked = lambda *a: False                            # and so does consumption
    req = request(w)
    out = w.gate.decide(req, BELL_QASM, TENANT, w.now(), w.executor_key.identity_id())
    res = make_executor(w).run(out["authorization"], req, BELL_QASM)
    bundle = json.loads(json.dumps(export_bundle(w, req, BELL_QASM, out, res["receipt"])))
    return verify_bundle(bundle, json.loads(json.dumps(trust_roots(w))))


def test_logged_revocation_blocks_chain():
    for target in ("delegation", "principal"):
        rep = _revoked_then_executed(target)
        rev = next(f for f in rep["findings"] if f["dimension"] == "revocation")
        assert rev["status"] == "FAILED", (target, rev)
        assert rep["chain_established"] is False
