"""End-to-end: policy decision → model call → evidence package → verify."""

from datetime import datetime, timedelta, timezone

from src.evidence import build_policy_decision, build_package, verify_package


def main():
    # 1. Principal issues a policy decision
    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    policy = build_policy_decision(
        policy_id="policy:research-001",
        principal=principal,
        allowed_action_types=["model_call"],
        allowed_providers=["xai", "openai", "anthropic"],
        allowed_targets=["grok-4", "gpt-4o", "claude-3-5-sonnet"],
        max_cost_usd=0.05,
        expires_at=expires,
        delegation_proof="sig:placeholder-alice-delegation",
    )
    print("Policy decision hash:", policy["decision_hash"])

    # 2. Agent executes within policy (mocked)
    agent = {
        "id": "agent:example-01",
        "public_key": "ed25519:placeholder-pubkey",
        "key_type": "ed25519",
    }

    request = {
        "model": "grok-4",
        "messages": [{"role": "user", "content": "Summarize the policy-bound evidence design."}],
    }
    import hashlib, json
    action_hash = hashlib.sha256(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    result = {
        "type": "model_response",
        "data": {"content": "Policy decision is hashed and bound into the package."},
        "status": "completed",
    }

    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=action_hash,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        settlement={"cost_usd": 0.0012},
    )

    print("Package hash:", package["package_hash"])

    # 3. Independent verification (with the policy)
    ok, reason = verify_package(package, policy_decision=policy)
    print(f"Verification: {ok} ({reason})")

    # Tamper the result
    package["result"]["data"]["content"] = "tampered"
    ok2, reason2 = verify_package(package, policy_decision=policy)
    print(f"After result tamper: {ok2} ({reason2})")

    # Restore and violate cost
    package["result"]["data"]["content"] = "Policy decision is hashed and bound into the package."
    package["package_hash"] = None  # force recompute later if needed; for demo we just show bounds
    # Rebuild a violating package
    bad = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=action_hash,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        settlement={"cost_usd": 1.0},  # exceeds max
    )
    ok3, reason3 = verify_package(bad, policy_decision=policy)
    print(f"Cost violation: {ok3} ({reason3})")


if __name__ == "__main__":
    main()
