"""Deterministic local mock executor that can also produce a signed execution receipt.

No network, no credentials. Software-key attestation only.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.execution_receipt import create_signed_receipt, request_hash, result_hash


def execute_model_call(request: dict) -> dict:
    """Deterministic mock of a model call boundary."""
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


def execute_and_sign(
    private_key: Ed25519PrivateKey,
    decision_hash: str,
    request: dict,
    execution_id: str | None = None,
) -> tuple[dict, dict]:
    """Execute the mock call and return (result, signed_receipt)."""
    result = execute_model_call(request)
    eid = execution_id or str(uuid.uuid4())
    receipt = create_signed_receipt(
        private_key=private_key,
        decision_hash=decision_hash,
        request=request,
        result=result,
        execution_id=eid,
        executed_at=datetime.now(timezone.utc).isoformat(),
    )
    return result, receipt
