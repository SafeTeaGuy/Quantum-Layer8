"""Phase 5: crypto agility and downgrade resistance (matrix D1-D10 of the core audit)."""

import copy

from quantum_l8 import suites
from quantum_l8.contracts import REQUEST_DOMAIN
from quantum_l8.scenario import delegate, make_world, request
from tests.quantum.conftest import decide, reasons, state

DOM = "L8X_TEST_V0"


def _body(suite):
    return {"x": 1, "signature_suite": suite}


def test_each_suite_roundtrip():
    for s in (suites.SUITE_ED25519, suites.SUITE_MLDSA65, suites.SUITE_HYBRID):
        k = suites.KeyBundle.generate(s)
        b = _body(s)
        assert suites.verify(k.public_identity(), DOM, b, k.sign(DOM, b)) == (True, suites.OK)


def test_hybrid_sizes_measured():
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    proof = k.sign(DOM, _body(suites.SUITE_HYBRID))
    assert [len(s["sig"]) // 2 for s in proof["signatures"]] == [64, 3309]
    assert [len(v) // 2 for v in k.public_identity()["public_keys"].values()] == [32, 1952]


def test_d2_strip_pq_component_refused():
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    b = _body(suites.SUITE_HYBRID)
    p = k.sign(DOM, b)
    p["signatures"] = p["signatures"][:1]
    assert suites.verify(k.public_identity(), DOM, b, p) == (False, suites.MALFORMED_PROOF)


def test_d2_lifted_classical_component_not_a_standalone_proof():
    """The Ed25519 component of a hybrid proof, presented as a classical
    proof, fails: the signed bytes name the hybrid suite."""
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    b = _body(suites.SUITE_HYBRID)
    p = k.sign(DOM, b)
    classical_identity = {"suite": suites.SUITE_ED25519,
                          "public_keys": {"ed25519": k.public_identity()["public_keys"]["ed25519"]}}
    lifted = {"suite": suites.SUITE_ED25519, "signatures": p["signatures"][:1]}
    assert not suites.verify(classical_identity, DOM, b, lifted)[0]
    relabelled = dict(b, signature_suite=suites.SUITE_ED25519)
    assert suites.verify(classical_identity, DOM, relabelled, lifted) == (False, suites.SIGNATURE_INVALID)


def test_d1_d3_suite_comes_from_key_not_artifact():
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    ed = suites.KeyBundle.generate(suites.SUITE_ED25519)
    b = _body(suites.SUITE_ED25519)
    # A classical proof presented for a hybrid-registered identity.
    assert suites.verify(k.public_identity(), DOM, b, ed.sign(DOM, b))[1] == suites.SUITE_MISMATCH
    # Edited suite label inside the proof.
    hb = _body(suites.SUITE_HYBRID)
    p = k.sign(DOM, hb)
    p["suite"] = suites.SUITE_ED25519
    assert suites.verify(k.public_identity(), DOM, hb, p)[1] == suites.SUITE_MISMATCH


def test_d7_unknown_suite_fails_closed():
    k = suites.KeyBundle.generate(suites.SUITE_ED25519)
    pi = dict(k.public_identity(), suite="l8.sig.falcon-512.v1")
    b = _body("l8.sig.falcon-512.v1")
    assert suites.verify(pi, DOM, b, {"suite": "l8.sig.falcon-512.v1", "signatures": []}) == (False, suites.SUITE_UNSUPPORTED)


def test_d8_malformed_hybrid_variants():
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    b = _body(suites.SUITE_HYBRID)
    good = k.sign(DOM, b)
    variants = []
    v = copy.deepcopy(good); v["signatures"].reverse(); variants.append(v)
    v = copy.deepcopy(good); v["signatures"].append(v["signatures"][0]); variants.append(v)
    v = copy.deepcopy(good); v["signatures"][1]["sig"] = v["signatures"][1]["sig"].upper(); variants.append(v)
    v = copy.deepcopy(good); v["signatures"][0]["sig"] += "00"; variants.append(v)
    v = copy.deepcopy(good); v["extra"] = 1; variants.append(v)
    v = copy.deepcopy(good); v["signatures"][1]["sig"] = "00" * 3309; variants.append(v)
    for v in variants:
        assert suites.verify(k.public_identity(), DOM, b, v)[0] is False


def test_pq_component_alone_invalid_is_rejected_even_if_classical_valid():
    """AND composition: a forged PQ part fails the whole proof."""
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    other = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    b = _body(suites.SUITE_HYBRID)
    p = k.sign(DOM, b)
    p["signatures"][1] = other.sign(DOM, b)["signatures"][1]
    assert suites.verify(k.public_identity(), DOM, b, p) == (False, suites.SIGNATURE_INVALID)


def test_level_algebra():
    assert suites.satisfies(suites.SUITE_HYBRID, suites.REQUIRE_PQ)
    assert suites.satisfies(suites.SUITE_HYBRID, suites.REQUIRE_ED25519)
    assert not suites.satisfies(suites.SUITE_ED25519, suites.REQUIRE_HYBRID)
    assert not suites.satisfies(suites.SUITE_MLDSA65, suites.REQUIRE_ED25519)
    assert suites.combine_levels([suites.REQUIRE_ED25519, suites.REQUIRE_PQ]) == suites.REQUIRE_HYBRID
    assert suites.combine_levels(["REQUIRE_NOTHING"]) is None


def test_identity_id_binds_suite():
    k = suites.KeyBundle.generate(suites.SUITE_HYBRID)
    pi = k.public_identity()
    classical = {"suite": suites.SUITE_ED25519, "public_keys": {"ed25519": pi["public_keys"]["ed25519"]}}
    assert suites.identity_id(pi) != suites.identity_id(classical)


# --- gate-level downgrade ---

def test_d9_request_cannot_lower_policy(world):
    req = request(world, crypto_policy=suites.REQUIRE_ED25519)
    out = decide(world, req)
    assert state(out) == "DENIED" and "CRYPTO_POLICY_DOWNGRADE" in reasons(out)


def test_classical_agent_key_refused_under_hybrid_policy(world):
    """An attacker with a classical-only key for a new identity gets nothing:
    the identity is not the delegate, and its suite is below policy."""
    attacker = suites.KeyBundle.generate(suites.SUITE_ED25519)
    world.identities.register(attacker.public_identity())
    out = decide(world, request(world, agent=attacker))
    assert state(out) == "DENIED"
    assert {"DELEGATION_SUBJECT_MISMATCH", "REQUEST_SUITE_BELOW_POLICY"} <= set(reasons(out))


def test_forged_classical_signature_for_hybrid_agent_refused(world):
    """Models a CRQC that recovered the agent's Ed25519 key: it can produce a
    valid Ed25519 signature, but not the ML-DSA component."""
    req = request(world)
    body = dict(req["body"], signature_suite=suites.SUITE_ED25519)
    ed_only = suites.KeyBundle(suites.SUITE_ED25519, {"ed25519": world.agent.keys["ed25519"]})
    forged = {"body": body, "proof": ed_only.sign(REQUEST_DOMAIN, body)}
    out = decide(world, forged)
    assert state(out) == "DENIED"
    assert reasons(out) == ["AGENT_SIGNATURE_INVALID", suites.SUITE_MISMATCH]


def test_operator_floor_applies_even_if_delegation_is_classical():
    w = make_world(suites.SUITE_ED25519, crypto_floor=suites.REQUIRE_HYBRID)
    delegate(w, crypto_policy=suites.REQUIRE_ED25519)
    out = decide(w, request(w, crypto_policy=suites.REQUIRE_HYBRID))
    assert state(out) == "DENIED"
    assert {"REQUEST_SUITE_BELOW_POLICY", "DELEGATION_SUITE_BELOW_POLICY", "GATE_SUITE_BELOW_POLICY"} <= set(reasons(out))


def test_classical_world_still_works_under_classical_policy():
    w = make_world(suites.SUITE_ED25519)
    delegate(w)
    assert state(decide(w, request(w))) == "AUTHORIZED"
