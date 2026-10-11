"""Adversarial tests for execution-to-authorization binding."""

from datetime import datetime, timezone

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import build_policy_decision, build_package, verify_package, decision_hash, package_hash
from src.mock_executor import execute_model_call


def _signed_policy(private, public, max_cost=0.1, providers=None, targets=None):
    principal = {"id": "user:alice", "type": "human"}
    unsigned = {
        "policy_id": "p",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": providers or ["xai"],
        "allowed_targets": targets or ["grok-4"],
        "max_cost_usd": max_cost,
        "expires_at": "2026-12-31T00:00:00+00:00",
        "delegation_proof": "",
    }
    d_hash = decision_hash(unsigned)
    sig = sign_delegation(private, d_hash)
    return build_policy_decision(
        policy_id="p",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=providers or ["xai"],
        allowed_targets=targets or ["grok-4"],
        max_cost_usd=max_cost,
        expires_at="2026-12-31T00:00:00+00:00",
        delegation_proof=sig,
    ), public_key_to_b64(public)


_BEFORE_EXPIRY = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_decision_a_signature_b_fails():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    policy_a, pub_a_b64 = _signed_policy(priv_a, pub_a)
    policy_b, _ = _signed_policy(priv_b, pub_b)
    agent = {"id": "a", "public_key": pub_a_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy_a,
        action_hash="d" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    # Swap signature
    package["authorization"]["delegation_proof"] = policy_b["delegation_proof"]
    package["package_hash"] = package_hash(package)
    ok, reason = verify_package(package, policy_decision=policy_a, principal_public_key_b64=pub_a_b64)
    assert not ok
    assert "delegation signature" in reason


def test_package_a_decision_b_fails():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    policy_a, pub_a_b64 = _signed_policy(priv_a, pub_a)
    policy_b, pub_b_b64 = _signed_policy(priv_b, pub_b, max_cost=9.0)
    agent = {"id": "a", "public_key": pub_a_b64, "key_type": "ed25519"}
    package_a = build_package(
        agent_identity=agent,
        policy_decision=policy_a,
        action_hash="e" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    ok, reason = verify_package(package_a, policy_decision=policy_b, principal_public_key_b64=pub_a_b64)
    assert not ok
    assert "does not match" in reason


def test_cost_exceeds_after_authorization_fails():
    priv, pub = generate_keypair()
    policy, pub_b64 = _signed_policy(priv, pub, max_cost=0.01)
    agent = {"id": "a", "public_key": pub_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="f" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
        settlement={"cost_usd": 1.0},
    )
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=pub_b64,
        verification_time=_BEFORE_EXPIRY,
    )
    assert not ok
    assert "cost exceeds" in reason


def test_provider_not_allowed_fails():
    priv, pub = generate_keypair()
    policy, pub_b64 = _signed_policy(priv, pub, providers=["openai"])
    agent = {"id": "a", "public_key": pub_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="1" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=pub_b64,
        verification_time=_BEFORE_EXPIRY,
    )
    assert not ok
    assert "provider not allowed" in reason


def test_mock_executor_is_deterministic():
    req = {"model": "grok-4", "messages": [{"role": "user", "content": "hello"}]}
    r1 = execute_model_call(req)
    r2 = execute_model_call(req)
    assert r1 == r2
    assert "mock-response-for" in r1["data"]["content"]
