"""Workload router: AUTHORITY separated from OPTIMIZATION (EXPERIMENTAL).

1. ``permitted_options`` (authority): which registered backends this signed
   delegation chain permits for this workload. It reuses the gate's own
   ``scope_violations`` so the router and the gate cannot drift. The router
   grants nothing: the gate re-evaluates every request independently.
2. An optimizer (any object with ``optimizer_id`` and ``score(option,
   signals)``) ranks ONLY the permitted set. Signals are inputs, never
   authority.
3. ``route`` refuses a choice outside the permitted set
   (ROUTE_NOT_PERMITTED), even if a compromised optimizer proposes it, and
   records a RoutingDecision as evidence.

A router outcome is advice that a later signed request may follow. Routing
evidence shows what was permitted, what signals were seen and what was
chosen; it does not show the signals were true.
"""

from __future__ import annotations

from quantum_l8.canonical import digest
from quantum_l8.gate import scope_violations

ROUTING_SCHEMA = "l8x.routing-decision.v0"

SIGNAL_KEYS = (
    "available", "queue_depth", "est_queue_ms", "est_runtime_ms", "est_cost_micro_usd",
    "error_rate_ppm", "historical_success_ppm", "provider_trust", "region",
)


def classical_simulation_log2_cost(num_qubits: int) -> int:
    """log2 of the amplitude count of an exact statevector simulation."""
    return num_qubits


def permitted_options(chain_bodies: list[dict], workload: dict, backends: list[dict],
                      allowed_regions: list[str] | None = None) -> tuple[list[dict], dict]:
    permitted, excluded = [], {}
    for d in sorted(backends, key=lambda x: x["backend_id"]):
        reasons = scope_violations(chain_bodies, workload, d, None)
        if allowed_regions is not None and d["region"] not in allowed_regions:
            reasons.append("REGION_NOT_PERMITTED")
        if reasons:
            excluded[d["backend_id"]] = reasons
        else:
            permitted.append(d)
    return permitted, excluded


class WeightedOptimizer:
    """Deterministic: lower score wins, ties broken by backend_id.

    Preference for classical execution when exact classical simulation is
    cheap is an optimization rule, not an authority rule: it only reorders
    the permitted set.
    """

    optimizer_id = "l8x.optimizer.weighted.v0"

    def __init__(self, w_time=1.0, w_cost=1.0, w_error=1.0, classical_exact_log2_limit=20):
        self.w_time, self.w_cost, self.w_error = w_time, w_cost, w_error
        self.limit = classical_exact_log2_limit

    def score(self, option: dict, signals: dict, workload: dict) -> float | None:
        if not signals.get("available", False):
            return None
        t = signals.get("est_queue_ms", 0) + signals.get("est_runtime_ms", 0)
        s = self.w_time * t / 1000 + self.w_cost * signals.get("est_cost_micro_usd", 0) / 1000
        s += self.w_error * signals.get("error_rate_ppm", 0) / 10_000
        if option["backend_class"] == "QUANTUM_HARDWARE" and \
                classical_simulation_log2_cost(workload["num_qubits"]) <= self.limit:
            s += 1e6  # an exactly simulable circuit gains nothing from a QPU
        return s


def route(chain_bodies: list[dict], workload: dict, backends: list[dict], signals: dict, optimizer,
          log=None, proposed: str | None = None, allowed_regions: list[str] | None = None) -> dict:
    permitted, excluded = permitted_options(chain_bodies, workload, backends, allowed_regions)
    permitted_ids = [d["backend_id"] for d in permitted]
    scored = []
    for d in permitted:
        s = optimizer.score(d, signals.get(d["backend_id"], {}), workload)
        if s is None:
            excluded.setdefault(d["backend_id"], []).append("UNAVAILABLE")
        else:
            scored.append((s, d["backend_id"]))
    scored.sort()
    choice = proposed if proposed is not None else (scored[0][1] if scored else None)
    status = "ROUTED"
    if choice is None:
        status = "NO_PERMITTED_OPTION"
    elif choice not in permitted_ids:
        status = "ROUTE_NOT_PERMITTED"
    elif choice not in [b for _, b in scored]:
        status = "ROUTE_UNAVAILABLE"
    decision = {
        "schema_version": ROUTING_SCHEMA,
        "workload_digest": digest(workload),
        "delegation_chain": [b["delegation_id"] for b in chain_bodies],
        "permitted": permitted_ids,
        "excluded": excluded,
        "signals_digest": digest({k: signals.get(k) for k in sorted(signals)}),
        "signals": {k: signals.get(k) for k in sorted(signals)},
        "optimizer_id": optimizer.optimizer_id,
        "ranking": [b for _, b in scored],
        "chosen": choice if status == "ROUTED" else None,
        "proposed": proposed,
        "status": status,
    }
    if log is not None:
        log.append("ROUTING_DECISION", {"routing_digest": digest(decision), "status": status,
                                        "chosen": decision["chosen"]})
    return decision
