"""End-to-end deterministic execution path with real delegation proof."""

from datetime import datetime, timedelta, timezone
import hashlib
import json

from src.delegation import generate_keypair, public_key_to_b64, sign_delegation
from src.evidence import build_policy_decision, build_package, verify_package, decision_hash
from src.mock_executor import execute_model_call


def main():
    private, public = generate_keypair()
    pub_b64 = public_key_to_b64(public)

    principal = {"id": "user:alice", "type": "human"}
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    # Policy evaluation (hard-coded allow for the demo)
    request = {
        "model": "grok-4",
        "messages": [{"role": "user", "content": "What is the evidence package?"}],
    }
    action_hash = hashlib.sha256(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    # Build and sign decision
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
    sig = sign_delegation(private, d_hash)
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

    # Execute
    result = execute_model_call(request)

    agent = {"id": "agent:demo", "public_key": "ed25519:" + pub_b64, "key_type": "ed25519"}
    package = build_package(
        agent_identity=agent,
        policy_decision=policy,
        action_hash=action_hash,
        action_type="model_call",
        provider="xai",
        target="grok-4",
        result=result,
        settlement={"cost_usd": 0.002},
    )

    ok, reason = verify_package(package, policy_decision=policy, principal_public_key_b64=pub_b64)
    print("End-to-end verification:", ok, reason)
    print("Result content:", result["data"]["content"])


if __name__ == "__main__":
    main()
