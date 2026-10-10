"""IBM Quantum adapter (uses generalized package)."""

from datetime import datetime, timezone
from typing import Any

from src.evidence import build_package


def from_ibm_job(
    job_result: Any,
    job_id: str,
    backend_name: str,
    agent_identity: dict,
    authorization: dict,
    circuit_hash: str,
    calibration_pointer: str | None = None,
) -> dict:
    counts = getattr(job_result, "get_counts", lambda: {})()
    shots = sum(counts.values()) if isinstance(counts, dict) else None

    result = {
        "type": "counts",
        "data": counts,
        "shots": shots,
        "status": "completed",
    }

    quantum = {"device_id": backend_name}
    if calibration_pointer:
        quantum["calibration_snapshot"] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pointer": calibration_pointer,
        }

    return build_package(
        agent_identity=agent_identity,
        authorization=authorization,
        action_hash=circuit_hash,
        action_type="quantum_job",
        provider="ibm-quantum",
        target=backend_name,
        result=result,
        quantum=quantum,
        settlement={"receipt_id": job_id},
    )
