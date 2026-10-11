"""Generic, provider-neutral contracts for governed quantum execution (EXPERIMENTAL).

Nothing here names IBM, Qiskit or any SDK. A provider appears only as an
opaque ``provider`` string and a backend descriptor registered by the
operator. See docs/quantum/QUANTUM_EXECUTION_CONTRACT.md.

Signed envelopes have the shape ``{"body": {...}, "proof": {...}}``. The
proof is produced by quantum_l8.suites over ``domain_separated(DOMAIN, body)``.
Ids that name a signed object are derived from its body (minus the id), so an
id can never be re-pointed at different content.
"""

from __future__ import annotations

import re
import secrets
from decimal import Decimal, InvalidOperation

from quantum_l8.canonical import digest, is_hex64, sha256_hex
from quantum_l8.suites import LEVELS, KeyBundle

DELEGATION_DOMAIN = "L8X_QUANTUM_DELEGATION_V0"
REQUEST_DOMAIN = "L8X_QUANTUM_EXECUTION_REQUEST_V0"
REVOCATION_DOMAIN = "L8X_QUANTUM_REVOCATION_V0"

DELEGATION_SCHEMA = "l8x.quantum-delegation.v0"
REQUEST_SCHEMA = "l8x.quantum-execution-request.v0"
REVOCATION_SCHEMA = "l8x.quantum-revocation.v0"
BACKEND_SCHEMA = "l8x.compute-backend-descriptor.v0"

# Closed vocabulary, from the core audit's proposed l8.compute.backend-class.v1.
BACKEND_CLASSES = ("CPU", "GPU", "TPU", "QUANTUM_SIMULATOR", "QUANTUM_HARDWARE")

CIRCUIT_ANY_FOR_ALGORITHM = "ANY_FOR_ALGORITHM"
CIRCUIT_PINNED = "PINNED"

PROGRAM_FORMATS = ("openqasm3",)

_PARAM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_DECIMAL = re.compile(r"^-?(0|[1-9][0-9]{0,15})(\.[0-9]{1,17})?\Z")


def new_nonce() -> str:
    return secrets.token_hex(16)


def program_digest(program_text: str) -> str:
    """Digest of the exact program bytes. No normalisation: any byte change
    is a different circuit."""
    return sha256_hex(program_text.encode("utf-8"))


def parameters_valid(params) -> bool:
    if not isinstance(params, dict) or len(params) > 64:
        return False
    for k, v in params.items():
        if not _PARAM_NAME.match(k) or not isinstance(v, str) or not _DECIMAL.match(v):
            return False
        try:
            Decimal(v)
        except InvalidOperation:
            return False
    return True


def _with_id(body: dict, id_field: str) -> dict:
    body = dict(body)
    body.pop(id_field, None)
    body[id_field] = digest(body)
    return body


def canonical_id(body: dict, id_field: str) -> str:
    return digest({k: v for k, v in body.items() if k != id_field})


# --- backend descriptors (operator registered, unsigned config pinned by digest) ---

def backend_descriptor(
    backend_id: str,
    backend_class: str,
    provider: str,
    adapter_id: str,
    provider_backend_names: list[str],
    max_qubits: int,
    per_job_micro_usd: int,
    per_shot_micro_usd: int,
    allowed_tenants: list[str],
    region: str = "unspecified",
) -> dict:
    if backend_class not in BACKEND_CLASSES:
        raise ValueError("unknown backend class")
    return {
        "schema_version": BACKEND_SCHEMA,
        "backend_id": backend_id,
        "backend_class": backend_class,
        "provider": provider,
        "adapter_id": adapter_id,
        "provider_backend_names": sorted(provider_backend_names),
        "max_qubits": max_qubits,
        "pricing": {"per_job_micro_usd": per_job_micro_usd, "per_shot_micro_usd": per_shot_micro_usd},
        "allowed_tenants": sorted(allowed_tenants),
        "region": region,
    }


def estimate_cost_micro_usd(descriptor: dict, shots: int) -> int:
    p = descriptor["pricing"]
    return p["per_job_micro_usd"] + p["per_shot_micro_usd"] * shots


# --- delegation ---

def build_delegation(
    issuer: KeyBundle,
    subject_id: str,
    tenant_id: str,
    algorithm_ids: list[str],
    backend_ids: list[str],
    backend_classes: list[str],
    providers: list[str],
    max_shots_per_execution: int,
    max_executions: int,
    max_cost_micro_usd_per_execution: int,
    max_total_cost_micro_usd: int,
    result_destinations: list[str],
    crypto_policy: str,
    not_before_ms: int,
    expires_at_ms: int,
    circuit_mode: str = CIRCUIT_ANY_FOR_ALGORITHM,
    circuit_digests: list[str] | None = None,
    may_redelegate: bool = False,
    parent_delegation_id: str | None = None,
) -> dict:
    body = {
        "schema_version": DELEGATION_SCHEMA,
        "issuer_id": issuer.identity_id(),
        "subject_id": subject_id,
        "parent_delegation_id": parent_delegation_id,
        "tenant_id": tenant_id,
        "scope": {
            "algorithm_ids": sorted(algorithm_ids),
            "circuits": {"mode": circuit_mode, "digests": sorted(circuit_digests or [])},
            "backend_ids": sorted(backend_ids),
            "backend_classes": sorted(backend_classes),
            "providers": sorted(providers),
            "max_shots_per_execution": max_shots_per_execution,
            "max_executions": max_executions,
            "max_cost_micro_usd_per_execution": max_cost_micro_usd_per_execution,
            "max_total_cost_micro_usd": max_total_cost_micro_usd,
            "result_destinations": sorted(result_destinations),
        },
        "crypto_policy": crypto_policy,
        "may_redelegate": may_redelegate,
        "not_before_ms": not_before_ms,
        "expires_at_ms": expires_at_ms,
        "signature_suite": issuer.suite,
    }
    body = _with_id(body, "delegation_id")
    return {"body": body, "proof": issuer.sign(DELEGATION_DOMAIN, body)}


_SCOPE_KEYS = {
    "algorithm_ids", "circuits", "backend_ids", "backend_classes", "providers",
    "max_shots_per_execution", "max_executions", "max_cost_micro_usd_per_execution",
    "max_total_cost_micro_usd", "result_destinations",
}
_DELEGATION_KEYS = {
    "schema_version", "delegation_id", "issuer_id", "subject_id", "parent_delegation_id",
    "tenant_id", "scope", "crypto_policy", "may_redelegate", "not_before_ms",
    "expires_at_ms", "signature_suite",
}


def _str_list(v, allow_empty=False) -> bool:
    return (
        isinstance(v, list)
        and (allow_empty or len(v) > 0)
        and all(isinstance(x, str) and x for x in v)
        and v == sorted(set(v))
    )


def _nonneg_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def delegation_well_formed(env) -> bool:
    """Strict shape check. Unknown fields, wrong types and implicit wildcards
    are refused (no empty list means 'any')."""
    if not isinstance(env, dict) or set(env) != {"body", "proof"}:
        return False
    b = env["body"]
    if not isinstance(b, dict) or set(b) != _DELEGATION_KEYS:
        return False
    if b["schema_version"] != DELEGATION_SCHEMA:
        return False
    if not (is_hex64(b["delegation_id"]) and is_hex64(b["issuer_id"]) and is_hex64(b["subject_id"])):
        return False
    if b["parent_delegation_id"] is not None and not is_hex64(b["parent_delegation_id"]):
        return False
    if not isinstance(b["tenant_id"], str) or not b["tenant_id"]:
        return False
    s = b["scope"]
    if not isinstance(s, dict) or set(s) != _SCOPE_KEYS:
        return False
    for k in ("algorithm_ids", "backend_ids", "backend_classes", "providers", "result_destinations"):
        if not _str_list(s[k]):
            return False
    if any(c not in BACKEND_CLASSES for c in s["backend_classes"]):
        return False
    c = s["circuits"]
    if not isinstance(c, dict) or set(c) != {"mode", "digests"}:
        return False
    if c["mode"] == CIRCUIT_PINNED:
        if not _str_list(c["digests"]) or not all(is_hex64(d) for d in c["digests"]):
            return False
    elif c["mode"] == CIRCUIT_ANY_FOR_ALGORITHM:
        if c["digests"] != []:
            return False
    else:
        return False
    for k in ("max_shots_per_execution", "max_executions", "max_cost_micro_usd_per_execution", "max_total_cost_micro_usd"):
        if not _nonneg_int(s[k]):
            return False
    if not isinstance(b["crypto_policy"], str) or b["crypto_policy"] not in LEVELS:
        return False
    if not isinstance(b["may_redelegate"], bool):
        return False
    if not (_nonneg_int(b["not_before_ms"]) and _nonneg_int(b["expires_at_ms"])):
        return False
    if b["expires_at_ms"] <= b["not_before_ms"]:
        return False
    return canonical_id(b, "delegation_id") == b["delegation_id"]


def scope_is_attenuation(child: dict, parent: dict) -> list[str]:
    """Return the scope dimensions on which ``child`` is wider than ``parent``."""
    wider = []
    cs, ps = child["scope"], parent["scope"]
    for k in ("algorithm_ids", "backend_ids", "backend_classes", "providers", "result_destinations"):
        if not set(cs[k]).issubset(ps[k]):
            wider.append(k)
    for k in ("max_shots_per_execution", "max_executions", "max_cost_micro_usd_per_execution", "max_total_cost_micro_usd"):
        if cs[k] > ps[k]:
            wider.append(k)
    pc, cc = ps["circuits"], cs["circuits"]
    if pc["mode"] == CIRCUIT_PINNED:
        if cc["mode"] != CIRCUIT_PINNED or not set(cc["digests"]).issubset(pc["digests"]):
            wider.append("circuits")
    if not LEVELS[parent["crypto_policy"]].issubset(LEVELS[child["crypto_policy"]]):
        wider.append("crypto_policy")
    if child["not_before_ms"] < parent["not_before_ms"] or child["expires_at_ms"] > parent["expires_at_ms"]:
        wider.append("validity_window")
    if child["tenant_id"] != parent["tenant_id"]:
        wider.append("tenant_id")
    return wider


# --- execution request ---

def build_workload(algorithm_id: str, program_text: str, parameters: dict, shots: int, num_qubits: int) -> dict:
    return {
        "algorithm_id": algorithm_id,
        "program_format": "openqasm3",
        "program_digest": program_digest(program_text),
        "parameters": dict(sorted(parameters.items())),
        "shots": shots,
        "num_qubits": num_qubits,
    }


def chain_digest(delegation_ids: list[str]) -> str:
    return digest({"delegation_chain": list(delegation_ids)})


def build_request(
    agent: KeyBundle,
    principal_id: str,
    tenant_id: str,
    delegation_ids: list[str],
    workload: dict,
    backend: dict,
    max_qubits: int,
    max_runtime_ms: int,
    cost_limit_micro_usd: int,
    execution_deadline_ms: int,
    result_destination: str,
    crypto_policy: str,
    created_at_ms: int,
    request_id: str | None = None,
    nonce: str | None = None,
) -> dict:
    body = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id or new_nonce(),
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "agent_id": agent.identity_id(),
        "delegation_id": delegation_ids[-1],
        "delegation_chain_digest": chain_digest(delegation_ids),
        "workload": workload,
        "workload_digest": digest(workload),
        "backend": {
            "backend_id": backend["backend_id"],
            "backend_class": backend["backend_class"],
            "provider": backend["provider"],
        },
        "resource_limits": {"max_qubits": max_qubits, "max_runtime_ms": max_runtime_ms},
        "cost_limit_micro_usd": cost_limit_micro_usd,
        "execution_deadline_ms": execution_deadline_ms,
        "result_destination": result_destination,
        "crypto_policy": crypto_policy,
        "nonce": nonce or new_nonce(),
        "created_at_ms": created_at_ms,
        "signature_suite": agent.suite,
    }
    return {"body": body, "proof": agent.sign(REQUEST_DOMAIN, body)}


_REQUEST_KEYS = {
    "schema_version", "request_id", "tenant_id", "principal_id", "agent_id", "delegation_id",
    "delegation_chain_digest", "workload", "workload_digest", "backend", "resource_limits",
    "cost_limit_micro_usd", "execution_deadline_ms", "result_destination", "crypto_policy",
    "nonce", "created_at_ms", "signature_suite",
}
_WORKLOAD_KEYS = {"algorithm_id", "program_format", "program_digest", "parameters", "shots", "num_qubits"}


def request_schema_ok(env) -> bool:
    if not isinstance(env, dict) or set(env) != {"body", "proof"}:
        return False
    return isinstance(env["body"], dict) and env["body"].get("schema_version") == REQUEST_SCHEMA


def request_well_formed(env) -> bool:
    if not request_schema_ok(env):
        return False
    b = env["body"]
    if set(b) != _REQUEST_KEYS:
        return False
    for k in ("request_id", "nonce"):
        v = b[k]
        if not isinstance(v, str) or len(v) != 32 or any(c not in "0123456789abcdef" for c in v):
            return False
    for k in ("principal_id", "agent_id", "delegation_id", "delegation_chain_digest", "workload_digest"):
        if not is_hex64(b[k]):
            return False
    if not isinstance(b["tenant_id"], str) or not b["tenant_id"]:
        return False
    w = b["workload"]
    if not isinstance(w, dict) or set(w) != _WORKLOAD_KEYS:
        return False
    if not isinstance(w["algorithm_id"], str) or w["program_format"] not in PROGRAM_FORMATS:
        return False
    if not is_hex64(w["program_digest"]) or not parameters_valid(w["parameters"]):
        return False
    if not (_nonneg_int(w["shots"]) and w["shots"] > 0 and _nonneg_int(w["num_qubits"]) and w["num_qubits"] > 0):
        return False
    be = b["backend"]
    if not isinstance(be, dict) or set(be) != {"backend_id", "backend_class", "provider"}:
        return False
    if not all(isinstance(be[k], str) and be[k] for k in be) or be["backend_class"] not in BACKEND_CLASSES:
        return False
    rl = b["resource_limits"]
    if not isinstance(rl, dict) or set(rl) != {"max_qubits", "max_runtime_ms"}:
        return False
    if not (_nonneg_int(rl["max_qubits"]) and _nonneg_int(rl["max_runtime_ms"])):
        return False
    for k in ("cost_limit_micro_usd", "execution_deadline_ms", "created_at_ms"):
        if not _nonneg_int(b[k]):
            return False
    if not isinstance(b["result_destination"], str) or not b["result_destination"]:
        return False
    return isinstance(b["crypto_policy"], str) and b["crypto_policy"] in LEVELS


# --- revocation ---

def build_revocation(issuer: KeyBundle, target_kind: str, target_id: str, effective_at_ms: int) -> dict:
    """target_kind: DELEGATION | AGENT. A DELEGATION may be revoked by its
    issuer or the operator. AGENT revokes an identity (an agent, an
    intermediate issuer or a root principal) and only the operator may issue it."""
    if target_kind not in ("DELEGATION", "AGENT"):
        raise ValueError("unknown revocation target kind")
    body = {
        "schema_version": REVOCATION_SCHEMA,
        "issuer_id": issuer.identity_id(),
        "target_kind": target_kind,
        "target_id": target_id,
        "effective_at_ms": effective_at_ms,
        "signature_suite": issuer.suite,
    }
    body = _with_id(body, "revocation_id")
    return {"body": body, "proof": issuer.sign(REVOCATION_DOMAIN, body)}
