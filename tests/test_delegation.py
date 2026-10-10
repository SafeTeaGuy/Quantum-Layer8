"""Focused tests for Ed25519 delegation binding."""

import pytest

from src.delegation import (
    generate_keypair,
    public_key_to_b64,
    sign_delegation,
    verify_delegation,
    public_key_from_b64,
    delegation_message,
)
from src.evidence import build_policy_decision, build_package, verify_package, decision_hash


def _make_signed_policy(private, public):
    principal = {"id": "user:alice", "type": "human"}
    unsigned = {
        "policy_id": "policy:test",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": ["xai"],
        "allowed_targets": ["grok-4"],
        "max_cost_usd": 0.1,
        "expires_at": "2026-12-31T00:00:00+00:00",
        "delegation_proof": "",
    }
    d_hash = decision_hash(unsigned)
    sig = sign_delegation(private, d_hash)
    return build_policy_decision(
        policy_id="policy:test",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=["xai"],
        allowed_targets=["grok-4"],
        max_cost_usd=0.1,
        expires_at="2026-12-31T00:00:00+00:00",
        delegation_proof=sig,
    ), public_key_to_b64(public)


def test_sign_and_verify_roundtrip():
    private, public = generate_keypair()
    policy, pub_b64 = _make_signed_policy(private, public)
    assert verify_delegation(public, policy["decision_hash"], policy["delegation_proof"])


def test_modified_decision_hash_fails():
    private, public = generate_keypair()
    policy, pub_b64 = _make_signed_policy(private, public)
    assert not verify_delegation(public, "a" * 64, policy["delegation_proof"])


def test_wrong_public_key_fails():
    private, public = generate_keypair()
    _, other_public = generate_keypair()
    policy, _ = _make_signed_policy(private, public)
    assert not verify_delegation(other_public, policy["decision_hash"], policy["delegation_proof"])


def test_malformed_signature_fails():
    private, public = generate_keypair()
    policy, _ = _make_signed_policy(private, public)
    assert not verify_delegation(public, policy["decision_hash"], "not-base64!!")
    assert not verify_delegation(public, policy["decision_hash"], "AA==")  # too short


def test_package_verification_with_signature():
    private, public = generate_keypair()
    policy, pub_b64 = _make_signed_policy(private, public)
    agent = {"id": "agent:1", "public_key": "ed25519:x", "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="b" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "model_response", "data": {}, "status": "ok"},
        settlement={"cost_usd": 0.01},
    )
    ok, reason = verify_package(package, policy_decision=policy, principal_public_key_b64=pub_b64)
    assert ok, reason


def test_swapped_signature_fails_package_verify():
    private1, public1 = generate_keypair()
    private2, public2 = generate_keypair()
    policy1, pub1 = _make_signed_policy(private1, public1)
    policy2, _ = _make_signed_policy(private2, public2)
    agent = {"id": "agent:1", "public_key": "x", "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy1,
        action_hash="c" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    # Replace signature with one from the other key
    package["authorization"]["delegation_proof"] = policy2["delegation_proof"]
    package["package_hash"] = None
    from src.evidence import package_hash
    package["package_hash"] = package_hash(package)
    ok, reason = verify_package(package, policy_decision=policy1, principal_public_key_b64=pub1)
    assert not ok
    assert "delegation signature" in reason
