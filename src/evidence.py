"""Core helpers for the Agent Action Evidence package.

Canonicalization is deterministic so the same logical package always produces
the same package_hash. Verification checks structural integrity and the self-hash.
Cryptographic verification of agent signatures and provider attestations is
left to the Layer8 substrate that supplies the identity/authority primitives.

Quantum jobs are one action_type; classical model/tool/payment actions use the same path.
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
    action_hash: str,
    action_type: str,
    provider: str,
    target: str,
    result: dict,
    policy: dict | None = None,
    settlement: dict | None = None,
    provider_attestation: dict | None = None,
    submitted_at: str | None = None,
    executed_at: str | None = None,
    quantum: dict | None = None,
) -> dict:
    """Construct a valid evidence package and compute its package_hash."""
    package: dict[str, Any] = {
        "version": "0.2.0",
        "agent_identity": agent_identity,
        "authorization": authorization,
        "action_hash": action_hash,
        "action_type": action_type,
        "provider": provider,
        "target": target,
        "submitted_at": submitted_at or datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    if executed_at:
        package["executed_at"] = executed_at
    if policy:
        package["policy"] = policy
    if settlement:
        package["settlement"] = settlement
    if provider_attestation:
        package["provider_attestation"] = provider_attestation
    if quantum:
        package["quantum"] = quantum

    package["package_hash"] = package_hash(package)
    return package


def verify_package(package: dict) -> tuple[bool, str]:
    """Return (ok, reason). Checks required fields and self-hash integrity."""
    required = [
        "version", "agent_identity", "authorization", "action_hash",
        "action_type", "provider", "target", "submitted_at", "result", "package_hash"
    ]
    missing = [k for k in required if k not in package]
    if missing:
        return False, f"missing required fields: {missing}"

    if package.get("version") != "0.2.0":
        return False, "unsupported version"

    expected = package_hash(package)
    if package["package_hash"] != expected:
        return False, f"package_hash mismatch (expected {expected})"

    if not isinstance(package["agent_identity"], dict) or "id" not in package["agent_identity"]:
        return False, "invalid agent_identity"
    if not isinstance(package["authorization"], dict) or "delegation_proof" not in package["authorization"]:
        return False, "invalid authorization"

    return True, "ok"
