"""Deterministic local mock executor for end-to-end policy-bound actions.

No network, no credentials, no external trust. Used to demonstrate the full
flow: request → policy evaluation → decision → signature → execution → evidence.
"""

from typing import Any


def execute_model_call(request: dict) -> dict:
    """Deterministic mock of a model call boundary.

    Returns a result that can be packaged. The content is derived only from
    the request so the path is reproducible.
    """
    model = request.get("model", "unknown")
    messages = request.get("messages", [])
    last = messages[-1].get("content", "") if messages else ""
    return {
        "type": "model_response",
        "data": {
            "content": f"mock-response-for:{model}:{last[:64]}",
            "usage": {"prompt_tokens": len(last), "completion_tokens": 16},
        },
        "status": "completed",
    }
