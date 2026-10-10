"""Core helpers for the Agent Action Evidence package.

Every package is preceded by a PolicyDecision. The decision is hashed and bound
into the authorization field so the final package_hash covers both the prior
authorization and the outcome. Verification checks decision integrity and basic
policy bounds.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(obj: dict, exclude: str | None = None) -> str:
    copy = {k: v for k, v in obj.items() if k != exclude}
    return hashlib.sha256(_canonical(copy)).hexdigest()


def decision_hash(decision: dict) -> str:
    return _hash(decision, exclude="decision_hash")


def package_hash(package: dict) -> str:
    return _hash(package, exclude="package_hash")


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
) -> dict:
    """Construct evidence package bound to a prior policy decision."""
    package: dict[str, Any] = {
        "version": "0.3.0",
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
        "policy": policy_decision,  # convenience copy; verification uses hash
    }
    if executed_at:
        package["executed_at"] = executed_at
    if settlement:
        package["settlement"] = settlement
    if provider_attestation:
        package["provider_attestation"] = provider_attestation
    if quantum:
        package["quantum"] = quantum

    package["package_hash"] = package_hash(package)
    return package


def verify_package(package: dict, policy_decision: dict | None = None) -> tuple[bool, str]:
    """Verify package integrity and, if policy_decision is supplied, basic bounds."""
    required = [
        "version", "agent_identity", "authorization", "action_hash",
        "action_type", "provider", "target", "submitted_at", "result", "package_hash"
    ]
    missing = [k for k in required if k not in package]
    if missing:
        return False, f"missing required fields: {missing}"

    if package.get("version") != "0.3.0":
        return False, "unsupported version"

    expected = package_hash(package)
    if package["package_hash"] != expected:
        return False, f"package_hash mismatch (expected {expected})"

    auth = package["authorization"]
    if not isinstance(auth, dict) or "policy_decision_hash" not in auth or "delegation_proof" not in auth:
        return False, "invalid authorization"

    if policy_decision is not None:
        if decision_hash(policy_decision) != auth["policy_decision_hash"]:
            return False, "policy_decision_hash does not match supplied decision"

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
