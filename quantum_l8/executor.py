"""Layer8 execution node and QuantumExecutionReceipt (EXPERIMENTAL).

The executor is the only component that talks to a provider adapter, and only
after the gate has issued and it has consumed an authorization. It signs a
receipt that binds what was authorized to what the provider reported and what
the executor observed. Every provider-originated field is labelled
PROVIDER_REPORTED: Layer8 records it, attributes it and detects later
alteration. It does not make it true.

Order of operations (fail closed at every step):
 1. verify the authorization against the pinned gate identity;
 2. request digest, workload digest and program bytes match the authorization;
 3. adapter exists for the authorized backend descriptor;
 4. adapter.preflight (refuse-only, before consumption);
 5. gate.consume (single use, revocation re-check);
 6. adapter.submit exactly once; any exception -> outcome UNKNOWN;
 7. provider-reported backend and shots are compared with the authorization;
 8. classical consistency check when the ideal distribution is computable;
 9. deliver result only on SUCCEEDED, only to the authorized destination;
10. sign receipt, append to the evidence log, checkpoint.
"""

from __future__ import annotations

import math
import time

from quantum_l8 import suites
from quantum_l8.canonical import digest
from quantum_l8.contracts import program_digest

RECEIPT_DOMAIN = "L8X_QUANTUM_EXECUTION_RECEIPT_V0"
RECEIPT_SCHEMA = "l8x.quantum-execution-receipt.v0"
AUTHORIZATION_DOMAIN = "L8X_QUANTUM_EXECUTION_AUTHORIZATION_V0"

SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"
PROVIDER_MISMATCH = "PROVIDER_MISMATCH"

BASES = {
    "authorization": "GATE_SIGNED",
    "backend_descriptor": "OPERATOR_REGISTERED",
    "provider_job_id": "PROVIDER_REPORTED",
    "provider_reported_backend": "PROVIDER_REPORTED",
    "counts": "PROVIDER_REPORTED",
    "provider_metadata": "PROVIDER_REPORTED",
    "submitted_at_ms": "EXECUTOR_OBSERVED",
    "completed_at_ms": "EXECUTOR_OBSERVED",
    "classical_verification": "EXECUTOR_COMPUTED",
}


def tvd(counts: dict[str, int], ideal: dict[str, float]) -> float:
    n = sum(counts.values())
    keys = set(counts) | set(ideal)
    return 0.5 * sum(abs(counts.get(k, 0) / n - ideal.get(k, 0.0)) for k in keys)


def tvd_tolerance(ideal: dict[str, float], shots: int) -> float:
    """Heuristic sampling tolerance, sqrt(support / shots), capped at 1."""
    return min(1.0, math.sqrt((len(ideal) + 1) / shots))


def provider_output_problem(run) -> str | None:
    """Shape check for adapter output. Returns a code, or None if usable."""
    if not isinstance(run, dict):
        return "NOT_A_MAPPING"
    for k in ("provider_job_id", "provider_reported_backend", "provider_reported_status"):
        if not isinstance(run.get(k), str):
            return f"FIELD:{k}"
    counts = run.get("counts")
    if not isinstance(counts, dict) or not all(
            isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in counts.items()):
        return "FIELD:counts"
    s = run.get("shots_reported")
    if not isinstance(s, int) or isinstance(s, bool):
        return "FIELD:shots_reported"
    c = run.get("reported_cost_micro_usd")
    if c is not None and (not isinstance(c, int) or isinstance(c, bool)):
        return "FIELD:reported_cost_micro_usd"
    try:
        digest({"m": run.get("provider_metadata"), "r": run.get("reproducibility")})
    except Exception:
        return "NOT_CANONICAL"
    return None


class Executor:
    def __init__(self, key: suites.KeyBundle, gate, adapters: dict, destinations: dict, log, clock=None):
        self.key = key
        self.gate = gate
        self.adapters = adapters          # adapter_id -> adapter
        self.destinations = destinations  # destination id -> list (sink)
        self.log = log
        self.clock = clock or (lambda: int(time.time() * 1000))

    @property
    def executor_id(self) -> str:
        return self.key.identity_id()

    def run(self, authorization_env: dict, request_env: dict, program_text: str) -> dict:
        """Never raises for malformed inputs or provider output: before
        consumption it returns a named refusal; after consumption it always
        signs a receipt (UNKNOWN if the provider output is unusable)."""
        try:
            pre = self._precheck(authorization_env, request_env, program_text)
        except Exception as e:
            return {"executed": False, "reason": "AUTHORIZATION_OR_REQUEST_MALFORMED", "detail": type(e).__name__}
        if "reason" in pre:
            return pre
        return self._execute(authorization_env, request_env, program_text, pre["descriptor"], pre["adapter"])

    def _precheck(self, authorization_env, request_env, program_text) -> dict:
        a = authorization_env["body"]
        ok, why = suites.verify(self.gate.key.public_identity(), AUTHORIZATION_DOMAIN, a, authorization_env["proof"])
        if not ok:
            return {"executed": False, "reason": "AUTHORIZATION_SIGNATURE_INVALID", "detail": why}
        if digest(request_env) != a["request_digest"]:
            return {"executed": False, "reason": "REQUEST_DIGEST_MISMATCH"}
        w = request_env["body"]["workload"]
        if digest(w) != a["workload_digest"] or program_digest(program_text) != a["program_digest"]:
            return {"executed": False, "reason": "WORKLOAD_MISMATCH"}
        descriptor = self.gate.backends.get(a["backend_id"])
        if descriptor is None or digest(descriptor) != a["backend_descriptor_digest"]:
            return {"executed": False, "reason": "BACKEND_DESCRIPTOR_MISMATCH"}
        if not suites.satisfies(self.key.suite, a["crypto_policy"]):
            return {"executed": False, "reason": "EXECUTOR_SUITE_BELOW_POLICY"}
        adapter = self.adapters.get(descriptor["adapter_id"])
        if adapter is None:
            return {"executed": False, "reason": "ADAPTER_UNAVAILABLE"}
        refusal = adapter.preflight(program_text, w, descriptor)
        if refusal:
            return {"executed": False, "reason": f"PREFLIGHT_REFUSED:{refusal}"}
        return {"descriptor": descriptor, "adapter": adapter}

    def _execute(self, authorization_env, request_env, program_text, descriptor, adapter) -> dict:
        a = authorization_env["body"]
        w = request_env["body"]["workload"]
        consumed, creason = self.gate.consume(authorization_env, self.executor_id, self.clock())
        if not consumed:
            return {"executed": False, "reason": creason}

        head_before = {"seq": len(self.log.entries) - 1, "hash": self.log.head}
        submitted_at = self.clock()
        run, outcome, findings = None, UNKNOWN, []
        try:
            run = adapter.submit(program_text, w, descriptor, a["authorization_id"])
        except Exception as e:  # never success on an exception
            findings.append(f"ADAPTER_EXCEPTION:{type(e).__name__}")
        if run is not None:
            problem = provider_output_problem(run)
            if problem:
                findings.append(f"PROVIDER_OUTPUT_MALFORMED:{problem}")
                run = None  # untrusted output is not recorded as if it were well-formed
            else:
                outcome = SUCCEEDED if run["provider_reported_status"] == "COMPLETED" else FAILED
        completed_at = self.clock()

        counts = (run or {}).get("counts")
        if outcome == SUCCEEDED:
            if run.get("provider_reported_backend") not in descriptor["provider_backend_names"]:
                outcome = PROVIDER_MISMATCH
                findings.append("PROVIDER_REPORTED_BACKEND_NOT_AUTHORIZED")
            if run.get("shots_reported") != a["shots"] or sum(counts.values()) != a["shots"]:
                outcome = PROVIDER_MISMATCH
                findings.append("SHOTS_REPORTED_MISMATCH")

        verification = {"method": "none", "verdict": "NOT_CHECKED"}
        if outcome == SUCCEEDED:
            try:
                ideal = adapter.ideal_distribution(program_text, w)
            except Exception:
                ideal = None
            if ideal is not None:
                d, tol = tvd(counts, ideal), tvd_tolerance(ideal, a["shots"])
                verification = {
                    "method": "ideal-statevector-total-variation-distance",
                    "ideal_distribution_digest": digest({k: format(v, ".12f") for k, v in sorted(ideal.items())}),
                    "tvd": format(d, ".6f"),
                    "tolerance": format(tol, ".6f"),
                    "verdict": "CONSISTENT" if d <= tol else "INCONSISTENT",
                }

        reported_cost = (run or {}).get("reported_cost_micro_usd")
        cost = {
            "reserved_micro_usd": a["reserved_cost_micro_usd"],
            "reported_micro_usd": reported_cost,
            "overrun": reported_cost is not None and reported_cost > a["reserved_cost_micro_usd"],
        }
        if cost["overrun"]:
            findings.append("REPORTED_COST_EXCEEDS_RESERVATION")

        result = {"type": "counts", "counts": counts} if counts is not None else None
        body = {
            "schema_version": RECEIPT_SCHEMA,
            "executor_id": self.executor_id,
            "authorization_id": a["authorization_id"],
            "authorization_digest": digest(authorization_env),
            "request_id": a["request_id"],
            "request_digest": a["request_digest"],
            "tenant_id": a["tenant_id"],
            "principal_id": a["principal_id"],
            "agent_id": a["agent_id"],
            "delegation_chain": a["delegation_chain"],
            "workload_digest": a["workload_digest"],
            "program_digest": a["program_digest"],
            "parameters": w["parameters"],
            "shots_authorized": a["shots"],
            "backend_id": a["backend_id"],
            "backend_descriptor_digest": a["backend_descriptor_digest"],
            "backend_class": a["backend_class"],
            "provider": a["provider"],
            "adapter": {"adapter_id": adapter.adapter_id, "adapter_version": adapter.adapter_version},
            "execution": {
                "provider_job_id": (run or {}).get("provider_job_id"),
                "provider_reported_backend": (run or {}).get("provider_reported_backend"),
                "provider_reported_status": (run or {}).get("provider_reported_status"),
                "shots_reported": (run or {}).get("shots_reported"),
                "submitted_at_ms": submitted_at,
                "completed_at_ms": completed_at,
                "reproducibility": (run or {}).get("reproducibility"),
            },
            "provider_metadata": (run or {}).get("provider_metadata"),
            "provider_metadata_digest": digest((run or {}).get("provider_metadata")),
            "result": result,
            "result_digest": digest(result),
            "result_destination": a["result_destination"],
            "classical_verification": verification,
            "cost": cost,
            "outcome": outcome,
            "findings": findings,
            "bases": BASES,
            "crypto_policy": a["crypto_policy"],
            "evidence_log_head_before": head_before,
            "signature_suite": self.key.suite,
        }
        body["receipt_id"] = digest(body)
        receipt = {"body": body, "proof": self.key.sign(RECEIPT_DOMAIN, body)}
        self.log.append("EXECUTION_RECEIPT", {"receipt_id": body["receipt_id"], "receipt_digest": digest(receipt),
                                              "outcome": outcome, "authorization_id": a["authorization_id"]})
        delivered = False
        if outcome == SUCCEEDED:
            self.destinations.setdefault(a["result_destination"], []).append(
                {"receipt_id": body["receipt_id"], "result": result})
            delivered = True
        self.log.checkpoint(self.clock())
        return {"executed": True, "receipt": receipt, "delivered": delivered}
