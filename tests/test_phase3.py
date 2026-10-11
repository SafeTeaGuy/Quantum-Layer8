"""Adversarial tests for Phase 3: expiry, agent key, execution receipt, replay."""

from datetime import datetime, timedelta, timezone
import uuid

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import build_policy_decision, build_package, verify_package, decision_hash, package_hash
from src.execution_receipt import create_signed_receipt, request_hash, result_hash
from src.mock_executor import execute_and_sign
from src.replay import InMemoryReplayStore


def _make_policy(private, expires_offset_hours=1):
    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=expires_offset_hours)).isoformat()
    unsigned = {
        "policy_id": "p",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": ["xai"],
        "allowed_targets": ["grok-4"],
        "max_cost_usd": 0.1,
        "expires_at": expires,
        "delegation_proof": "",
    }
    d_hash = decision_hash(unsigned)
    sig = sign_delegation(private, d_hash)
    return build_policy_decision(
        policy_id="p",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=["xai"],
        allowed_targets=["grok-4"],
        max_cost_usd=0.1,
        expires_at=expires,
        delegation_proof=sig,
    ), public_key_to_b64(private.public_key())


def test_expired_decision_fails():
    priv, pub = generate_keypair()
    policy, pub_b64 = _make_policy(priv, expires_offset_hours=-1)
    agent = {"id": "a", "public_key": public_key_to_b64(pub), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="a" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(package, policy_decision=policy, principal_public_key_b64=pub_b64, verification_time=now)
    assert not ok
    assert "expired" in reason


def test_malformed_expiry_fails():
    priv, pub = generate_keypair()
    principal = {"id": "user:alice", "type": "human"}
    expires = "not-a-date"
    unsigned = {
        "policy_id": "p",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": ["xai"],
        "allowed_targets": ["grok-4"],
        "max_cost_usd": 0.1,
        "expires_at": expires,
        "delegation_proof": "",
    }
    sig = sign_delegation(priv, decision_hash(unsigned))
    policy = build_policy_decision(
        policy_id="p",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=["xai"],
        allowed_targets=["grok-4"],
        max_cost_usd=0.1,
        expires_at=expires,
        delegation_proof=sig,
    )
    pub_b64 = public_key_to_b64(pub)
    agent = {"id": "a", "public_key": pub_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="b" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(package, policy_decision=policy, principal_public_key_b64=pub_b64, verification_time=now)
    assert not ok
    assert "malformed" in reason


def test_malformed_agent_key_fails():
    priv, pub = generate_keypair()
    policy, pub_b64 = _make_policy(priv)
    agent = {"id": "a", "public_key": "not-base64!!!", "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="c" * 64,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result={"type": "x", "data": {}},
    )
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(package, policy_decision=policy, principal_public_key_b64=pub_b64, verification_time=now)
    assert not ok
    assert "malformed agent" in reason


def test_result_substitution_fails_receipt():
    priv_exec, pub_exec = generate_keypair()
    priv_prin, pub_prin = generate_keypair()
    policy, prin_b64 = _make_policy(priv_prin)
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "hi"}]}
    result, receipt = execute_and_sign(priv_exec, policy["decision_hash"], request)
    agent = {"id": "a", "public_key": public_key_to_b64(pub_prin), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=request_hash(request),
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
    )
    # Tamper result after packaging
    package["result"]["data"]["content"] = "forged"
    package["package_hash"] = package_hash(package)
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=now,
        expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request,
    )
    assert not ok
    assert "result_hash" in reason


def test_replay_detected():
    priv_exec, pub_exec = generate_keypair()
    priv_prin, pub_prin = generate_keypair()
    policy, prin_b64 = _make_policy(priv_prin)
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "hi"}]}
    result, receipt = execute_and_sign(priv_exec, policy["decision_hash"], request, execution_id="fixed-id")
    agent = {"id": "a", "public_key": public_key_to_b64(pub_prin), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=request_hash(request),
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
    )
    store = InMemoryReplayStore()
    now = datetime.now(timezone.utc)
    ok1, _ = verify_package(
        package, policy_decision=policy, principal_public_key_b64=prin_b64,
        verification_time=now, expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request, replay_store=store,
    )
    assert ok1
    ok2, reason2 = verify_package(
        package, policy_decision=policy, principal_public_key_b64=prin_b64,
        verification_time=now, expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request, replay_store=store,
    )
    assert not ok2
    assert "replay" in reason2


def test_full_successful_path():
    priv_exec, pub_exec = generate_keypair()
    priv_prin, pub_prin = generate_keypair()
    policy, prin_b64 = _make_policy(priv_prin)
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "What is Layer8?"}]}
    result, receipt = execute_and_sign(priv_exec, policy["decision_hash"], request)
    agent = {"id": "agent:demo", "public_key": public_key_to_b64(pub_prin), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=request_hash(request),
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
        settlement={"cost_usd": 0.002},
    )
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=now,
        expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request,
    )
    assert ok, reason


def test_receipt_action_hash_mismatch_fails():
    priv_exec, pub_exec = generate_keypair()
    priv_prin, pub_prin = generate_keypair()
    policy, prin_b64 = _make_policy(priv_prin)
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "hi"}]}
    result, receipt = execute_and_sign(priv_exec, policy["decision_hash"], request)
    agent = {"id": "a", "public_key": public_key_to_b64(pub_prin), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash="ab" * 32,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
    )
    now = datetime.now(timezone.utc)
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=now,
        expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request,
    )
    assert not ok
    assert "action_hash" in reason


def test_failed_expiry_does_not_consume_replay_id():
    priv_exec, pub_exec = generate_keypair()
    priv_prin, pub_prin = generate_keypair()
    policy, prin_b64 = _make_policy(priv_prin, expires_offset_hours=-1)
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "hi"}]}
    result, receipt = execute_and_sign(
        priv_exec, policy["decision_hash"], request, execution_id="once"
    )
    agent = {"id": "a", "public_key": public_key_to_b64(pub_prin), "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=request_hash(request),
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
    )
    store = InMemoryReplayStore()
    now = datetime.now(timezone.utc)
    kwargs = dict(
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=now,
        expected_executor_public_key_b64=public_key_to_b64(pub_exec),
        request=request,
        replay_store=store,
    )
    ok1, reason1 = verify_package(package, **kwargs)
    ok2, reason2 = verify_package(package, **kwargs)
    assert not ok1 and "expired" in reason1
    assert not ok2 and "expired" in reason2
    assert not store.seen("once")
