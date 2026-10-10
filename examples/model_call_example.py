"""Classical model call evidence example."""

from adapters.model_call import from_model_call
from src.evidence import verify_package


def main():
    agent = {
        "id": "agent:example-01",
        "public_key": "ed25519:placeholder-pubkey",
        "key_type": "ed25519",
    }
    auth = {
        "delegation_proof": "sig:placeholder-layer8-delegation",
        "policy_id": "policy:research-001",
    }

    request = {
        "model": "grok-4",
        "messages": [{"role": "user", "content": "Summarize the evidence package design."}],
    }
    response = {
        "content": "The package binds agent identity to the exact action hash and result.",
        "usage": {"prompt_tokens": 42, "completion_tokens": 18},
    }

    package = from_model_call(
        request_payload=request,
        response_payload=response,
        agent_identity=agent,
        authorization=auth,
        provider="xai",
        model="grok-4",
        cost_usd=0.0012,
    )

    print("Package hash:", package["package_hash"])
    ok, reason = verify_package(package)
    print(f"Verification: {ok} ({reason})")

    package["result"]["data"]["content"] = "tampered"
    ok2, reason2 = verify_package(package)
    print(f"After tamper: {ok2} ({reason2})")


if __name__ == "__main__":
    main()
