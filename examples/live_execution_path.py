"""End-to-end deterministic execution path using the strong verification API."""

from datetime import datetime, timedelta, timezone

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import (
    build_policy_decision,
    build_package,
    verify_authorized_execution,
    decision_hash,
)
from src.execution_receipt import request_hash
from src.mock_executor import execute_and_sign
from src.replay import InMemoryReplayStore


def main():
    principal_priv, principal_pub = generate_keypair()
    executor_priv, executor_pub = generate_keypair()
    principal_b64 = public_key_to_b64(principal_pub)
    executor_b64 = public_key_to_b64(executor_pub)

    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    request = {
        "model": "grok-4",
        "messages": [{"role": "user", "content": "What is the evidence package?"}],
    }
    action_hash = request_hash(request)

    unsigned = {
        "policy_id": "policy:demo",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": ["xai"],
        "allowed_targets": ["grok-4"],
        "max_cost_usd": 0.05,
        "expires_at": expires,
        "delegation_proof": "",
    }
    d_hash = decision_hash(unsigned)
    sig = sign_delegation(principal_priv, d_hash)
    policy = build_policy_decision(
        policy_id="policy:demo",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=["xai"],
        allowed_targets=["grok-4"],
        max_cost_usd=0.05,
        expires_at=expires,
        delegation_proof=sig,
    )

    result, receipt = execute_and_sign(executor_priv, policy["decision_hash"], request)

    agent = {"id": "agent:demo", "public_key": principal_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=action_hash,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        execution_receipt=receipt,
        settlement={"cost_usd": 0.002},
    )

    store = InMemoryReplayStore()
    ok, reason = verify_authorized_execution(
        package,
        policy_decision=policy,
        principal_public_key_b64=principal_b64,
        verification_time=datetime.now(timezone.utc),
        expected_executor_public_key_b64=executor_b64,
        request=request,
        replay_store=store,
    )
    print("Strong verification:", ok, reason)
    print("Result content:", result["data"]["content"])


if __name__ == "__main__":
    main()
