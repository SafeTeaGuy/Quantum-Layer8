"""Core helpers for the Agent Action Evidence package.

Every package is preceded by a PolicyDecision. The decision is hashed and bound
into the authorization field so the final package_hash covers both the prior
authorization and the outcome. Verification checks decision integrity, basic
policy bounds, delegation signature (when key supplied), expiry, and agent
identity public-key well-formedness.

Production trusted-time semantics remain unresolved. Callers must supply an
explicit verification_time.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from src.delegation import verify_delegation, public_key_from_b64


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(obj: dict, exclude: str | None = None) -> str:
    copy = {k: v for k, v in obj.items() if k != exclude}
    return hashlib.sha256(_canonical(copy)).hexdigest()


def decision_hash(decision: dict) -> str:
    return _hash(decision, exclude="decision_hash")


def package_hash(package: dict) -> str:
    return _hash(package, exclude="package_hash")


def _parse_iso8601(ts: str) -> datetime | None:
    """Parse ISO-8601 timestamp. Returns None on any ambiguity or error."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        # Require timezone-aware
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def build_policy_decision(
    policy_id: str,
    principal: dict,
    allowed_action_types: list[str],
    expires_at: str,
    delegation_proof: str,
    allowed_providers: list[str] | None = None,
    allowed_targets: list[str] | None = None,
    max_cost_usd: float | None = None,
    data_constraints: dict | None = None,
) -> dict:
    decision: dict[str, Any] = {
        "policy_id": policy_id,
        "principal": principal,
        "allowed_action_types": allowed_action_types,
        "expires_at": expires_at,
        "delegation_proof": delegation_proof,
    }
    if allowed_providers is not None:
        decision["allowed_providers"] = allowed_providers
    if allowed_targets is not None:
        decision["allowed_targets"] = allowed_targets
    if max_cost_usd is not None:
        decision["max_cost_usd"] = max_cost_usd
    if data_constraints is not None:
        decision["data_constraints"] = data_constraints
    decision["decision_hash"] = decision_hash(decision)
    return decision


def build_package(
    agent_identity: dict,
    policy_decision: dict,
    action_hash: str,
    action_type: str,
    provider: str,
    target: str,
    result: dict,
    settlement: dict | None = None,
    provider_attestation: dict | None = None,
    submitted_at: str | None = None,
    executed_at: str | None = None,
    quantum: dict | None = None,
    execution_receipt: dict | None = None,
) -> dict:
    """Construct evidence package bound to a prior policy decision."""
    package: dict[str, Any] = {
        "version": "0.4.0",
        "agent_identity": agent_identity,
        "authorization": {
            "policy_decision_hash": policy_decision["decision_hash"],
            "delegation_proof": policy_decision["delegation_proof"],
            "policy_id": policy_decision["policy_id"],
        },
        "action_hash": action_hash,
        "action_type": action_type,
        "provider": provider,
        "target": target,
        "submitted_at": submitted_at or datetime.now(timezone.utc).isoformat(),
        "result": result,
        "policy": policy_decision,
    }
    if executed_at:
        package["executed_at"] = executed_at
    if settlement:
        package["settlement"] = settlement
    if provider_attestation:
        package["provider_attestation"] = provider_attestation
    if quantum:
        package["quantum"] = quantum
    if execution_receipt:
        package["execution_receipt"] = execution_receipt

    package["package_hash"] = package_hash(package)
    return package


def verify_package(
    package: dict,
    policy_decision: dict | None = None,
    principal_public_key_b64: str | None = None,
    verification_time: datetime | None = None,
    expected_agent_public_key_b64: str | None = None,
) -> tuple[bool, str]:
    """Verify package integrity, policy bounds, delegation signature, expiry, and agent key.

    verification_time must be supplied for expiry checks. Production trusted-time
    is not claimed.
    """
    required = [
        "version", "agent_identity", "authorization", "action_hash",
        "action_type", "provider", "target", "submitted_at", "result", "package_hash"
    ]
    missing = [k for k in required if k not in package]
    if missing:
        return False, f"missing required fields: {missing}"

    if package.get("version") not in ("0.3.0", "0.4.0"):
        return False, "unsupported version"

    expected = package_hash(package)
    if package["package_hash"] != expected:
        return False, f"package_hash mismatch (expected {expected})"

    auth = package["authorization"]
    if not isinstance(auth, dict) or "policy_decision_hash" not in auth or "delegation_proof" not in auth:
        return False, "invalid authorization"

    decision_hash_value = auth["policy_decision_hash"]

    # Agent identity public-key well-formedness (real bytes, not string compare)
    agent_id = package.get("agent_identity") or {}
    agent_pub_b64 = agent_id.get("public_key")
    if not agent_pub_b64:
        return False, "missing agent public_key"
    try:
        agent_pub = public_key_from_b64(agent_pub_b64)
        # Force materialization of bytes
        _ = agent_pub.public_bytes_raw() if hasattr(agent_pub, "public_bytes_raw") else agent_pub.public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
        )
    except Exception:
        return False, "malformed agent public key"

    if expected_agent_public_key_b64 is not None:
        if agent_pub_b64 != expected_agent_public_key_b64:
            return False, "agent public key mismatch"

    if principal_public_key_b64 is not None:
        try:
            pub = public_key_from_b64(principal_public_key_b64)
        except Exception:
            return False, "invalid principal public key encoding"
        if not verify_delegation(pub, decision_hash_value, auth["delegation_proof"]):
            return False, "delegation signature verification failed"

    if policy_decision is not None:
        if decision_hash(policy_decision) != decision_hash_value:
            return False, "policy_decision_hash does not match supplied decision"

        # Expiry enforcement
        expires_at_str = policy_decision.get("expires_at")
        if not expires_at_str:
            return False, "missing expires_at"
        expires_at = _parse_iso8601(expires_at_str)
        if expires_at is None:
            return False, "malformed expires_at"
        if verification_time is None:
            return False, "verification_time required for expiry check"
        if verification_time.tzinfo is None:
            return False, "verification_time must be timezone-aware"
        vt = verification_time.astimezone(timezone.utc)
        if vt >= expires_at:
            return False, "policy decision expired"

        # Basic bounds checks
        if package["action_type"] not in policy_decision.get("allowed_action_types", []):
            return False, "action_type not allowed by policy"

        providers = policy_decision.get("allowed_providers")
        if providers and package["provider"] not in providers:
            return False, "provider not allowed by policy"

        targets = policy_decision.get("allowed_targets")
        if targets and package["target"] not in targets:
            return False, "target not allowed by policy"

        max_cost = policy_decision.get("max_cost_usd")
        if max_cost is not None:
            cost = (package.get("settlement") or {}).get("cost_usd")
            if cost is not None and cost > max_cost:
                return False, "cost exceeds policy max_cost_usd"

    return True, "ok"
