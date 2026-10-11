"""Strong verification path is the primary API."""

from datetime import datetime, timedelta, timezone

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import (
    build_policy_decision,
    build_package,
    verify_authorized_execution,
    verify_package,
    decision_hash,
)
from src.execution_receipt import request_hash
from src.mock_executor import execute_and_sign
from src.replay import InMemoryReplayStore


def _setup():
    prin_priv, prin_pub = generate_keypair()
    exec_priv, exec_pub = generate_keypair()
    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
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
    sig = sign_delegation(prin_priv, d_hash)
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
    request = {"model": "grok-4", "messages": [{"role": "user", "content": "hi"}]}
    result, receipt = execute_and_sign(exec_priv, policy["decision_hash"], request)
    agent = {"id": "a", "public_key": public_key_to_b64(prin_pub), "key_type": "ed25519"}
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
    return policy, package, request, public_key_to_b64(prin_pub), public_key_to_b64(exec_pub)


def test_strong_path_succeeds():
    policy, package, request, prin_b64, exec_b64 = _setup()
    store = InMemoryReplayStore()
    ok, reason = verify_authorized_execution(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=datetime.now(timezone.utc),
        expected_executor_public_key_b64=exec_b64,
        request=request,
        replay_store=store,
    )
    assert ok, reason


def test_strong_path_rejects_missing_receipt():
    policy, package, request, prin_b64, exec_b64 = _setup()
    package.pop("execution_receipt")
    package["package_hash"] = None
    from src.evidence import package_hash
    package["package_hash"] = package_hash(package)
    store = InMemoryReplayStore()
    ok, reason = verify_authorized_execution(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=datetime.now(timezone.utc),
        expected_executor_public_key_b64=exec_b64,
        request=request,
        replay_store=store,
    )
    assert not ok
    assert "missing execution_receipt" in reason


def test_weak_path_is_explicit_opt_in():
    policy, package, request, prin_b64, exec_b64 = _setup()
    package.pop("execution_receipt")
    package["package_hash"] = None
    from src.evidence import package_hash
    package["package_hash"] = package_hash(package)
    # Default verify_package allows policy-only
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=prin_b64,
        verification_time=datetime.now(timezone.utc),
    )
    assert ok, reason
