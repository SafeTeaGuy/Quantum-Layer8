"""IBM Quantum adapter stub.

Extracts what can be extracted from a Qiskit Runtime job result and maps it
into a QuantumJobEvidence package. Real calibration snapshots require a
separate call to backend.properties(datetime=...) and are left as a pointer
here so the package stays small.
"""

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
    """Map an IBM job result into an evidence package.

    In production this would pull:
    - job.result()
    - job.metrics() / usage
    - backend.properties() near execution time
    - job.inputs() for the exact submitted circuit
    """
    # Minimal extraction — replace with real RuntimeEncoder paths
    counts = getattr(job_result, "get_counts", lambda: {})()
    shots = sum(counts.values()) if isinstance(counts, dict) else None

    results = {
        "type": "counts",
        "data": counts,
        "shots": shots,
    }

    calibration = None
    if calibration_pointer:
        calibration = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pointer": calibration_pointer,
            "hash": "placeholder-until-real-snapshot-hash",
        }

    return build_package(
        agent_identity=agent_identity,
        authorization=authorization,
        job_hash=circuit_hash,
        provider="ibm-quantum",
        device_id=backend_name,
        results=results,
        calibration_snapshot=calibration,
        settlement={"receipt_id": job_id},
    )
