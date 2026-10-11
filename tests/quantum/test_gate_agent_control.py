"""Phases 3 and 8: the Quantum Trust Gate's questions, and scoped agent authority.

Scoped grant under test (scenario.delegate defaults):
  agent may run algorithms {bell, parametrized-bell}
  on backends {qiskit.basic_simulator, cpu.exact_sampler} (classes CPU, QUANTUM_SIMULATOR)
  at most 3 executions, 4096 shots each, $0.05 per execution, $0.10 total
  until T0 + 1h, results only to DEST, hybrid signatures required.
"""

from quantum_l8 import suites
from quantum_l8.contracts import build_revocation
from quantum_l8.scenario import (
    ALG_BELL, ALG_ROT, BELL_QASM, DEST, HOUR, QPU_BACKEND, ROT_QASM, SIM_BACKEND, TENANT, delegate, make_world, request,
)
from tests.quantum.conftest import decide, make_executor, reasons, state


def test_happy_path_authorizes_and_binds(world):
    req = request(world)
    out = decide(world, req)
    assert state(out) == "AUTHORIZED" and reasons(out) == []
    a = out["authorization"]["body"]
    assert a["principal_id"] == world.principal.identity_id()
    assert a["agent_id"] == world.agent.identity_id()
    assert a["delegation_chain"] == [world.delegation["body"]["delegation_id"]]
    assert a["workload_digest"] == req["body"]["workload_digest"]
    assert a["backend_id"] == "qiskit.basic_simulator" and a["backend_class"] == "QUANTUM_SIMULATOR"
    assert a["crypto_policy"] == suites.REQUIRE_HYBRID
    assert a["permitted_execution_count"] == 1


def test_decisions_are_deterministic(world):
    req = request(world, shots=100_000, backend=QPU_BACKEND, result_destination="dest:elsewhere")
    r1 = reasons(decide(world, req))
    r2 = reasons(decide(world, req))
    assert r1 == r2
    assert r1 == ["COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT", "SHOTS_EXCEED_DELEGATION", "BACKEND_NOT_AUTHORIZED",
                  "BACKEND_CLASS_NOT_AUTHORIZED", "PROVIDER_NOT_AUTHORIZED", "RESULT_DESTINATION_NOT_AUTHORIZED"]


def test_rejection_burns_nothing(world):
    bad = request(world, backend=QPU_BACKEND)
    assert state(decide(world, bad)) == "DENIED"
    for _ in range(3):
        assert state(decide(world, request(world))) == "AUTHORIZED"


# --- who / delegation ---

def test_unknown_agent_is_insufficient_evidence(world):
    stranger = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    out = decide(world, request(world, agent=stranger))
    assert state(out) == "INSUFFICIENT_EVIDENCE" and reasons(out) == ["AGENT_IDENTITY_UNKNOWN"]


def test_delegation_missing(world):
    out = decide(world, request(world, delegation_ids=["ab" * 32]))
    assert state(out) == "INSUFFICIENT_EVIDENCE" and "DELEGATION_NOT_FOUND" in reasons(out)


def test_root_principal_must_be_permitted():
    w = make_world()
    rogue = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    w.identities.register(rogue.public_identity())
    delegate(w, issuer=rogue)
    out = decide(w, request(w, principal_id=rogue.identity_id()))
    assert state(out) == "DENIED" and "ROOT_PRINCIPAL_NOT_PERMITTED" in reasons(out)


def test_principal_mismatch(world):
    out = decide(world, request(world, principal_id=world.operator.identity_id()))
    assert "PRINCIPAL_MISMATCH" in reasons(out)


def test_expired_and_not_yet_valid_delegation(world):
    world.advance(HOUR + 1)
    out = decide(world, request(world, execution_deadline_ms=world.now() + 1000))
    assert state(out) == "DENIED" and "DELEGATION_EXPIRED" in reasons(out)
    w = make_world()
    delegate(w, not_before_ms=w.now() + 10_000, expires_at_ms=w.now() + HOUR)
    assert "DELEGATION_NOT_YET_VALID" in reasons(decide(w, request(w)))


# --- scope (Phase 8) ---

def test_algorithm_not_authorized(world):
    w = make_world()
    delegate(w, algorithm_ids=[ALG_BELL])
    out = decide(w, request(w, program=ROT_QASM, algorithm_id=ALG_ROT, parameters={"theta": "0.5"}), program=ROT_QASM)
    assert reasons(out) == ["ALGORITHM_NOT_AUTHORIZED"]


def test_pinned_circuit_only(world):
    from quantum_l8.contracts import CIRCUIT_PINNED, program_digest
    w = make_world()
    delegate(w, circuit_mode=CIRCUIT_PINNED, circuit_digests=[program_digest(BELL_QASM)])
    assert state(decide(w, request(w))) == "AUTHORIZED"
    other = BELL_QASM.replace("cx q[0], q[1];", "cx q[1], q[0];")
    out = decide(w, request(w, program=other), program=other)
    assert reasons(out) == ["CIRCUIT_NOT_AUTHORIZED"]


def test_backend_class_and_qpu_not_permitted(world):
    out = decide(world, request(world, backend=QPU_BACKEND))
    assert {"BACKEND_NOT_AUTHORIZED", "BACKEND_CLASS_NOT_AUTHORIZED", "PROVIDER_NOT_AUTHORIZED"} <= set(reasons(out))


def test_shots_and_qubit_limits(world):
    assert "SHOTS_EXCEED_DELEGATION" in reasons(decide(world, request(world, shots=5000)))
    assert "QUBITS_EXCEED_REQUEST_LIMIT" in reasons(decide(world, request(world, max_qubits=1)))


def test_max_executions(world):
    for _ in range(3):
        assert state(decide(world, request(world))) == "AUTHORIZED"
    out = decide(world, request(world))
    assert reasons(out) == ["EXECUTION_COUNT_EXHAUSTED"]


def test_cost_limits():
    w = make_world()
    delegate(w, backend_ids=["ibm.qpu.example_heron"], backend_classes=["QUANTUM_HARDWARE"],
             providers=["ibm-quantum"], max_cost_micro_usd_per_execution=500_000, max_total_cost_micro_usd=600_000)
    # estimate 1024 * 400 = 409_600 micro-USD
    assert "COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT" in reasons(
        decide(w, request(w, backend=QPU_BACKEND, cost_limit_micro_usd=100_000)))
    assert "COST_LIMIT_EXCEEDS_DELEGATION" in reasons(
        decide(w, request(w, backend=QPU_BACKEND, cost_limit_micro_usd=900_000)))
    assert state(decide(w, request(w, backend=QPU_BACKEND, cost_limit_micro_usd=450_000))) == "AUTHORIZED"
    # The second job would push reserved spend to 900_000 > 600_000.
    out = decide(w, request(w, backend=QPU_BACKEND, cost_limit_micro_usd=450_000))
    assert reasons(out) == ["COST_BUDGET_EXHAUSTED"]


def test_result_destination(world):
    assert reasons(decide(world, request(world, result_destination="dest:attacker"))) == \
        ["RESULT_DESTINATION_NOT_AUTHORIZED"]


def test_deadline_and_future_request(world):
    assert "EXECUTION_DEADLINE_PASSED" in reasons(decide(world, request(world, execution_deadline_ms=world.now())))
    assert "REQUEST_FROM_FUTURE" in reasons(decide(world, request(world, created_at_ms=world.now() + 600_000)))


def test_cross_tenant(world):
    out = decide(world, request(world), tenant="tenant:other")
    assert state(out) == "DENIED" and reasons(out) == ["TENANT_MISMATCH"]
    out = decide(world, request(world, tenant_id="tenant:other"), tenant="tenant:other")
    assert "TENANT_MISMATCH" in reasons(out)


def test_executor_must_be_registered(world):
    out = decide(world, request(world), executor_id="ff" * 32)
    assert reasons(out) == ["EXECUTOR_NOT_PERMITTED"]


# --- delegation escalation and re-delegation ---

def test_agent_cannot_escalate_by_redelegating(world):
    """Agent (not allowed to re-delegate) issues itself a wider sub-delegation."""
    sub_agent = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    world.identities.register(sub_agent.public_identity())
    parent_id = world.delegation["body"]["delegation_id"]
    child = delegate(world, issuer=world.agent, subject_id=sub_agent.identity_id(), parent_delegation_id=parent_id,
                     backend_ids=["ibm.qpu.example_heron", "qiskit.basic_simulator"], max_executions=100,
                     backend_classes=["QUANTUM_HARDWARE", "QUANTUM_SIMULATOR"],
                     providers=["ibm-quantum", "qiskit-local"])
    req = request(world, agent=sub_agent, delegation_ids=[parent_id, child["body"]["delegation_id"]])
    out = decide(world, req)
    assert state(out) == "DENIED"
    assert {"REDELEGATION_NOT_PERMITTED", "DELEGATION_ESCALATION"} <= set(reasons(out))


def test_attenuating_redelegation_is_allowed():
    w = make_world()
    root = delegate(w, may_redelegate=True)
    sub_agent = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    w.identities.register(sub_agent.public_identity())
    child = delegate(w, issuer=w.agent, subject_id=sub_agent.identity_id(),
                     parent_delegation_id=root["body"]["delegation_id"], algorithm_ids=[ALG_BELL],
                     backend_ids=["qiskit.basic_simulator"], backend_classes=["QUANTUM_SIMULATOR"],
                     providers=["qiskit-local"], max_executions=1, max_total_cost_micro_usd=10_000,
                     max_cost_micro_usd_per_execution=10_000)
    ids = [root["body"]["delegation_id"], child["body"]["delegation_id"]]
    out = decide(w, request(w, agent=sub_agent, delegation_ids=ids))
    assert state(out) == "AUTHORIZED", reasons(out)
    # The child's single execution is spent; the parent budget was charged too.
    assert reasons(decide(w, request(w, agent=sub_agent, delegation_ids=ids))) == \
        ["EXECUTION_COUNT_EXHAUSTED", "COST_BUDGET_EXHAUSTED"]
    # The parent was charged too: 1 of its 3 executions and 10_000 of its budget.
    assert w.gate._reserved[root["body"]["delegation_id"]] == {"executions": 1, "cost": 10_000}


def test_self_delegation_refused():
    w = make_world()
    delegate(w, subject_id=w.principal.identity_id())
    out = decide(w, request(w, agent=w.principal))
    assert "SELF_DELEGATION" in reasons(out)


# --- revocation ---

def test_revocation_before_decision(world):
    rv = build_revocation(world.principal, "DELEGATION", world.delegation["body"]["delegation_id"], world.now())
    assert world.gate.record_revocation(rv) == "REVOCATION_RECORDED"
    out = decide(world, request(world))
    assert state(out) == "REVOKED" and reasons(out) == ["REVOKED_DELEGATION"]


def test_revocation_between_authorization_and_execution(world):
    req = request(world)
    out = decide(world, req)
    assert state(out) == "AUTHORIZED"
    rv = build_revocation(world.principal, "DELEGATION", world.delegation["body"]["delegation_id"], world.now())
    world.gate.record_revocation(rv)
    res = make_executor(world).run(out["authorization"], req, BELL_QASM)
    assert res == {"executed": False, "reason": "REVOKED_DELEGATION"}


def test_agent_revocation_by_operator_only(world):
    by_agent = build_revocation(world.agent, "AGENT", world.agent.identity_id(), world.now())
    assert world.gate.record_revocation(by_agent) == "REVOCATION_UNAUTHORIZED_REVOKER"
    stranger = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    world.identities.register(stranger.public_identity())
    rv = build_revocation(stranger, "DELEGATION", world.delegation["body"]["delegation_id"], world.now())
    assert world.gate.record_revocation(rv) == "REVOCATION_UNAUTHORIZED_REVOKER"
    rv = build_revocation(world.operator, "AGENT", world.agent.identity_id(), world.now())
    assert world.gate.record_revocation(rv) == "REVOCATION_RECORDED"
    assert state(decide(world, request(world))) == "REVOKED"


def test_scheduled_revocation_takes_effect_later(world):
    rv = build_revocation(world.principal, "DELEGATION", world.delegation["body"]["delegation_id"], world.now() + 5000)
    world.gate.record_revocation(rv)
    assert state(decide(world, request(world))) == "AUTHORIZED"
    world.advance(5000)
    assert state(decide(world, request(world))) == "REVOKED"


# --- replay / single use ---

def test_replay_same_request(world):
    req = request(world)
    assert state(decide(world, req)) == "AUTHORIZED"
    assert set(reasons(decide(world, req))) >= {"REQUEST_REPLAYED", "NONCE_REPLAYED"}


def test_reused_nonce_new_request_id(world):
    r1 = request(world, nonce="aa" * 16)
    r2 = request(world, nonce="aa" * 16)
    assert state(decide(world, r1)) == "AUTHORIZED"
    assert reasons(decide(world, r2)) == ["NONCE_REPLAYED"]


def test_authorization_single_use(world):
    req = request(world)
    out = decide(world, req)
    ex = make_executor(world)
    assert ex.run(out["authorization"], req, BELL_QASM)["executed"] is True
    assert ex.run(out["authorization"], req, BELL_QASM) == {"executed": False, "reason": "AUTHORIZATION_ALREADY_CONSUMED"}


def test_authorization_expires(world):
    req = request(world, execution_deadline_ms=world.now() + 1000)
    out = decide(world, req)
    world.advance(1000)
    assert make_executor(world).run(out["authorization"], req, BELL_QASM)["reason"] == "AUTHORIZATION_EXPIRED"


def test_result_goes_only_to_authorized_destination(world):
    sinks = {}
    req = request(world)
    out = decide(world, req)
    res = make_executor(world, sinks).run(out["authorization"], req, BELL_QASM)
    assert res["delivered"] and list(sinks) == [DEST]
    assert sinks[DEST][0]["receipt_id"] == res["receipt"]["body"]["receipt_id"]


def test_parametrized_workload_end_to_end(world):
    req = request(world, program=ROT_QASM, algorithm_id=ALG_ROT, parameters={"theta": "0.25"})
    out = decide(world, req, program=ROT_QASM)
    res = make_executor(world).run(out["authorization"], req, ROT_QASM)
    assert res["receipt"]["body"]["outcome"] == "SUCCEEDED"
    assert res["receipt"]["body"]["classical_verification"]["verdict"] == "CONSISTENT"


def test_preflight_refuses_before_consumption(world):
    """Declared qubit count lies about the program: refused, authorization unspent."""
    from quantum_l8.contracts import build_request, build_workload
    wl = build_workload(ALG_BELL, BELL_QASM, {}, 1024, num_qubits=1)
    req = build_request(world.agent, world.principal.identity_id(), TENANT, [world.delegation["body"]["delegation_id"]],
                        wl, SIM_BACKEND, 4, 60_000, 10_000, world.now() + 60_000, DEST, suites.REQUIRE_HYBRID, world.now())
    out = decide(world, req)
    assert state(out) == "AUTHORIZED"
    res = make_executor(world).run(out["authorization"], req, BELL_QASM)
    assert res == {"executed": False, "reason": "PREFLIGHT_REFUSED:DECLARED_QUBITS_MISMATCH"}
    assert out["authorization"]["body"]["authorization_id"] not in world.gate._consumed


# --- remaining reason codes ---

def test_schema_malformed_missing_inputs(world):
    req = request(world)
    bad_schema = {"body": dict(req["body"], schema_version="l8x.quantum-execution-request.v9"), "proof": req["proof"]}
    assert reasons(decide(world, bad_schema)) == ["REQUEST_SCHEMA_UNSUPPORTED"]
    assert state(decide(world, bad_schema)) == "INSUFFICIENT_EVIDENCE"
    extra = {"body": dict(req["body"], surprise=1), "proof": req["proof"]}
    assert reasons(decide(world, extra)) == ["REQUEST_MALFORMED"]
    float_param = {"body": dict(req["body"], cost_limit_micro_usd=1.5), "proof": req["proof"]}
    assert reasons(decide(world, float_param)) == ["REQUEST_MALFORMED"]
    out = world.gate.decide(req, None, TENANT, world.now(), world.executor_key.identity_id())
    assert state(out) == "INSUFFICIENT_EVIDENCE" and reasons(out) == ["PROGRAM_MISSING"]


def test_backend_unknown_and_provider_mismatch(world):
    ghost = dict(SIM_BACKEND, backend_id="ghost.backend")
    assert "BACKEND_UNKNOWN" in reasons(decide(world, request(world, backend=ghost)))
    lying = dict(SIM_BACKEND, provider="ibm-quantum")
    assert "PROVIDER_MISMATCH" in reasons(decide(world, request(world, backend=lying)))


def test_chain_depth_limit():
    from quantum_l8.gate import MAX_CHAIN_DEPTH
    w = make_world()
    prev = delegate(w, may_redelegate=True)
    issuer, ids = w.agent, [prev["body"]["delegation_id"]]
    for _ in range(MAX_CHAIN_DEPTH):
        nxt = suites.KeyBundle.generate(suites.SUITE_HYBRID)
        w.identities.register(nxt.public_identity())
        prev = delegate(w, issuer=issuer, subject_id=nxt.identity_id(), parent_delegation_id=ids[-1],
                        may_redelegate=True)
        issuer = nxt
        ids.append(prev["body"]["delegation_id"])
    assert reasons(decide(w, request(w, agent=issuer, delegation_ids=ids))) == ["DELEGATION_DEPTH_EXCEEDED"]


def test_chain_digest_and_broken_chain(world):
    req = request(world, delegation_ids=["cd" * 32, world.delegation["body"]["delegation_id"]])
    assert "DELEGATION_CHAIN_DIGEST_MISMATCH" in reasons(decide(world, req))
    # A child whose issuer is not the parent's subject.
    w = make_world()
    root = delegate(w, may_redelegate=True)
    stranger = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    w.identities.register(stranger.public_identity())
    child = delegate(w, issuer=stranger, parent_delegation_id=root["body"]["delegation_id"])
    out = decide(w, request(w, delegation_ids=[root["body"]["delegation_id"], child["body"]["delegation_id"]]))
    assert "DELEGATION_CHAIN_BROKEN" in reasons(out)


def test_root_principal_identity_revoked_by_operator(world):
    req = request(world)
    out = decide(world, req)
    assert state(out) == "AUTHORIZED"
    rv = build_revocation(world.operator, "AGENT", world.principal.identity_id(), world.now())
    assert world.gate.record_revocation(rv) == "REVOCATION_RECORDED"
    assert make_executor(world).run(out["authorization"], req, BELL_QASM)["reason"] == "REVOKED_ISSUER"
    out = decide(world, request(world))
    assert state(out) == "REVOKED" and reasons(out) == ["REVOKED_ISSUER"]
