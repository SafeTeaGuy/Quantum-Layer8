"""Amazon Braket adapter (uses generalized package)."""

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
    measurements = getattr(task_result, "measurement_counts", {})
    shots = None
    if hasattr(task_result, "task_metadata"):
        shots = getattr(task_result.task_metadata, "shots", None)

    result = {
        "type": "counts",
        "data": measurements,
        "shots": shots,
        "status": "completed",
    }

    return build_package(
        agent_identity=agent_identity,
        authorization=authorization,
        action_hash=circuit_hash,
        action_type="quantum_job",
        provider="amazon-braket",
        target=device_arn,
        result=result,
        quantum={"device_id": device_arn},
        settlement={"receipt_id": task_arn},
    )
