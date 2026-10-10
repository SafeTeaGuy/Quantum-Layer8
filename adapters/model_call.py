"""Classical model call adapter.

Maps a typical chat/completions style request + response into the evidence package.
"""

from src.evidence import build_package


def from_model_call(
    request_payload: dict,
    response_payload: dict,
    agent_identity: dict,
    authorization: dict,
    provider: str,
    model: str,
    cost_usd: float | None = None,
) -> dict:
    """Build evidence for a model API call."""
    import hashlib
    import json

    action_hash = hashlib.sha256(
        json.dumps(request_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    result = {
        "type": "model_response",
        "data": {
            "content": response_payload.get("content") or response_payload.get("choices", [{}])[0].get("message", {}).get("content"),
            "usage": response_payload.get("usage"),
        },
        "status": "completed",
    }

    settlement = None
    if cost_usd is not None:
        settlement = {"cost_usd": cost_usd}

    return build_package(
        agent_identity=agent_identity,
        authorization=authorization,
        action_hash=action_hash,
        action_type="model_call",
        provider=provider,
        target=model,
        result=result,
        settlement=settlement,
    )
