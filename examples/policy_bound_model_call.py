"""End-to-end with real Ed25519 delegation proof."""

from datetime import datetime, timedelta, timezone

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import build_policy_decision, build_package, verify_package, decision_hash


def main():
    # 1. Principal keypair
    private, public = generate_keypair()
    pub_b64 = public_key_to_b64(public)
    print("Principal public key (b64):", pub_b64[:32] + "...")

    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    # 2. Build unsigned decision, hash it, then sign
    unsigned = {
        "policy_id": "policy:research-001",
        "principal": principal,
        "allowed_action_types": ["model_call"],
        "allowed_providers": ["xai", "openai", "anthropic"],
        "allowed_targets": ["grok-4", "gpt-4o", "claude-3-5-sonnet"],
        "max_cost_usd": 0.05,
        "expires_at": expires,
        "delegation_proof": "",  # placeholder until signed
    }
    d_hash = decision_hash(unsigned)
    signature = sign_delegation(private, d_hash)

    policy = build_policy_decision(
        policy_id=unsigned["policy_id"],
        principal=principal,
        allowed_action_types=unsigned["allowed_action_types"],
        allowed_providers=unsigned["allowed_providers"],
        allowed_targets=unsigned["allowed_targets"],
        max_cost_usd=unsigned["max_cost_usd"],
        expires_at=expires,
        delegation_proof=signature,
    )
    print("Policy decision hash:", policy["decision_hash"])
    print("Delegation proof is real Ed25519 signature")

    # 3. Agent executes within policy (mocked)
    agent = {
        "id": "agent:example-01",
        "public_key": pub_b64,
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

    # 4. Independent verification with signature check
    ok, reason = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=pub_b64,
        verification_time=datetime.now(timezone.utc),
    )
    print(f"Verification: {ok} ({reason})")

    # Tamper the result (package hash fails)
    package["result"]["data"]["content"] = "tampered"
    ok2, reason2 = verify_package(
        package,
        policy_decision=policy,
        principal_public_key_b64=pub_b64,
        verification_time=datetime.now(timezone.utc),
    )
    print(f"After result tamper: {ok2} ({reason2})")

    # Cost violation
    bad = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=action_hash,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        settlement={"cost_usd": 1.0},
    )
    ok3, reason3 = verify_package(
        bad,
        policy_decision=policy,
        principal_public_key_b64=pub_b64,
        verification_time=datetime.now(timezone.utc),
    )
    print(f"Cost violation: {ok3} ({reason3})")

    # Wrong signature (swapped)
    other_private, _ = generate_keypair()
    other_sig = sign_delegation(other_private, policy["decision_hash"])
    policy_bad_sig = dict(policy)
    policy_bad_sig["delegation_proof"] = other_sig
    # rebuild package with bad sig would fail hash, so just check verify_delegation path via package auth
    package_bad = dict(package)
    package_bad["authorization"] = dict(package["authorization"])
    package_bad["authorization"]["delegation_proof"] = other_sig
    package_bad["package_hash"] = None  # force recompute not needed; we check signature separately
    # Direct signature check fails
    from src.delegation import verify_delegation, public_key_from_b64
    sig_ok = verify_delegation(public_key_from_b64(pub_b64), policy["decision_hash"], other_sig)
    print(f"Wrong-key signature: {sig_ok}")


if __name__ == "__main__":
    main()
