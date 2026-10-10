"""Core helpers for the Quantum Job Evidence package.

Canonicalization is deterministic so the same logical package always produces
the same package_hash. Verification checks structural integrity and the self-hash.
Cryptographic verification of agent signatures and provider attestations is
left to the Layer8 substrate that supplies the identity/authority primitives.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def package_hash(package: dict) -> str:
    """SHA-256 of the package excluding the package_hash field."""
    copy = {k: v for k, v in package.items() if k != "package_hash"}
    return hashlib.sha256(_canonical(copy)).hexdigest()


def build_package(
    agent_identity: dict,
    authorization: dict,
    job_hash: str,
    provider: str,
    device_id: str,
    results: dict,
    calibration_snapshot: dict | None = None,
    policy: dict | None = None,
    settlement: dict | None = None,
    provider_attestation: dict | None = None,
    submitted_at: str | None = None,
    executed_at: str | None = None,
    backend_version: str | None = None,
) -> dict:
    """Construct a valid evidence package and compute its package_hash."""
    package: dict[str, Any] = {
        "version": "0.1.0",
        "agent_identity": agent_identity,
        "authorization": authorization,
        "job_hash": job_hash,
        "provider": provider,
        "device_id": device_id,
        "submitted_at": submitted_at or datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    if executed_at:
        package["executed_at"] = executed_at
    if backend_version:
        package["backend_version"] = backend_version
    if calibration_snapshot:
        package["calibration_snapshot"] = calibration_snapshot
    if policy:
        package["policy"] = policy
    if settlement:
        package["settlement"] = settlement
    if provider_attestation:
        package["provider_attestation"] = provider_attestation

    package["package_hash"] = package_hash(package)
    return package


def verify_package(package: dict) -> tuple[bool, str]:
    """Return (ok, reason). Checks required fields and self-hash integrity."""
    required = [
        "version", "agent_identity", "authorization", "job_hash",
        "provider", "device_id", "submitted_at", "results", "package_hash"
    ]
    missing = [k for k in required if k not in package]
    if missing:
        return False, f"missing required fields: {missing}"

    if package.get("version") != "0.1.0":
        return False, "unsupported version"

    expected = package_hash(package)
    if package["package_hash"] != expected:
        return False, f"package_hash mismatch (expected {expected})"

    # Basic shape checks
    if not isinstance(package["agent_identity"], dict) or "id" not in package["agent_identity"]:
        return False, "invalid agent_identity"
    if not isinstance(package["authorization"], dict) or "delegation_proof" not in package["authorization"]:
        return False, "invalid authorization"

    return True, "ok"
