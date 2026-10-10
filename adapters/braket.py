"""Amazon Braket adapter stub.

Maps a Braket task or hybrid job result into the evidence package.
"""

from datetime import datetime, timezone
from typing import Any

from src.evidence import build_package


def from_braket_task(
    task_result: Any,
    task_arn: str,
    device_arn: str,
    agent_identity: dict,
    authorization: dict,
    circuit_hash: str,
) -> dict:
    """Minimal mapping from a Braket task result."""
    measurements = getattr(task_result, "measurement_counts", {})
    shots = getattr(task_result, "task_metadata", {}).get("shots") if hasattr(task_result, "task_metadata") else None

    results = {
        "type": "counts",
        "data": measurements,
        "shots": shots,
    }

    return build_package(
        agent_identity=agent_identity,
        authorization=authorization,
        job_hash=circuit_hash,
        provider="amazon-braket",
        device_id=device_arn,
        results=results,
        settlement={"receipt_id": task_arn},
    )
