"""Quantum/Classical Arena (EXPERIMENTAL benchmark harness).

Never assumes quantum is better. For one problem it runs, where practical:

    classical_exact        brute force (ground truth for small n)
    classical_heuristic    greedy + 1-flip local search, seeded restarts
    quantum_simulator      QAOA p=1: parameter grid on an exact statevector,
                           then sampling the best circuit on Qiskit's
                           BasicSimulator
    hybrid_simulator       QAOA samples polished by classical local search
    quantum_hardware       only if an adapter and credentials exist; otherwise
                           recorded as NOT_RUN with the reason

Verdict rules are fixed in code BEFORE any run (pre-registration):

* fewer than MIN_REPEATS repeats for any executed leg -> INSUFFICIENT_EVIDENCE
* quality = best cut / optimal cut, median over repeats; a quality lead must
  exceed QUALITY_MARGIN to count
* among legs tied on quality, a time lead must be at least TIME_RATIO
* the winning leg's family gives the verdict:
  classical_* -> CLASSICAL_WINS, quantum_* -> QUANTUM_WINS,
  hybrid_* -> HYBRID_WINS; a tie with no time lead -> NO_MEANINGFUL_ADVANTAGE
* a QUANTUM_WINS or HYBRID_WINS that rests only on a *simulator* is
  reported as INSUFFICIENT_EVIDENCE: a simulator is classical computation,
  so it cannot show a hardware advantage.

Every leg result is appended to the evidence log.
"""

from __future__ import annotations

import itertools
import statistics
import time

import numpy as np

from quantum_l8.canonical import digest

MIN_REPEATS = 3
QUALITY_MARGIN = 0.01
TIME_RATIO = 1.5

ARENA_SCHEMA = "l8x.arena-report.v0"


def random_graph(n: int, p: float, seed: int) -> list[tuple[int, int]]:
    rng = np.random.default_rng(seed)
    edges = [(i, j) for i in range(n) for j in range(i + 1, n) if rng.random() < p]
    return edges or [(0, 1)]


def cut_value(bits: int, edges) -> int:
    return sum(1 for i, j in edges if ((bits >> i) & 1) != ((bits >> j) & 1))


def _cut_table(n, edges) -> np.ndarray:
    idx = np.arange(2 ** n)
    c = np.zeros(2 ** n, dtype=np.int64)
    for i, j in edges:
        c += ((idx >> i) & 1) != ((idx >> j) & 1)
    return c


def classical_exact(n, edges, seed):
    t = _cut_table(n, edges)
    return int(t.max()), {"evaluations": 2 ** n}


def _local_search(bits, n, edges):
    best = cut_value(bits, edges)
    improved, evals = True, 0
    while improved:
        improved = False
        for k in range(n):
            cand = bits ^ (1 << k)
            v = cut_value(cand, edges)
            evals += 1
            if v > best:
                bits, best, improved = cand, v, True
    return bits, best, evals


def classical_heuristic(n, edges, seed, restarts=8):
    rng = np.random.default_rng(seed)
    best, evals = 0, 0
    for _ in range(restarts):
        start = int(rng.integers(0, 2 ** n))
        _, v, e = _local_search(start, n, edges)
        best, evals = max(best, v), evals + e
    return best, {"evaluations": evals, "restarts": restarts}


def _qaoa_state(n, cuts, gamma, beta):
    psi = np.full(2 ** n, 1 / np.sqrt(2 ** n), dtype=complex) * np.exp(-1j * gamma * cuts)
    c, s = np.cos(beta), -1j * np.sin(beta)
    psi = psi.reshape([2] * n)
    for q in range(n):
        ax = n - 1 - q
        a0 = np.take(psi, 0, axis=ax)
        a1 = np.take(psi, 1, axis=ax)
        psi = np.stack([c * a0 + s * a1, s * a0 + c * a1], axis=ax)
    return psi.reshape(-1)


def _qaoa_circuit(n, edges, gamma, beta):
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(n, n)
    qc.h(range(n))
    for i, j in edges:
        qc.cx(i, j)
        qc.rz(2 * gamma, j)  # exp(-i*gamma*Z_iZ_j) up to global phase
        qc.cx(i, j)
    qc.rx(2 * beta, range(n))
    qc.measure(range(n), range(n))
    return qc


def _qaoa_samples(n, edges, seed, shots, grid):
    cuts = _cut_table(n, edges)
    best = (-1.0, 0.0, 0.0)
    for g in np.linspace(0, np.pi, grid):
        for b in np.linspace(0, np.pi / 2, grid):
            p = np.abs(_qaoa_state(n, cuts, g, b)) ** 2
            e = float(p @ cuts)
            if e > best[0]:
                best = (e, g, b)
    from qiskit import transpile
    from qiskit.providers.basic_provider import BasicSimulator
    backend = BasicSimulator()
    qc = _qaoa_circuit(n, edges, best[1], best[2])
    counts = backend.run(transpile(qc, backend), shots=shots, seed_simulator=seed).result().get_counts()
    samples = [int(k, 2) for k in counts]
    return samples, {"grid_points": grid * grid, "shots": shots, "expected_cut": format(best[0], ".4f")}


def quantum_simulator(n, edges, seed, shots=256, grid=12):
    samples, meta = _qaoa_samples(n, edges, seed, shots, grid)
    return max(cut_value(s, edges) for s in samples), meta


def hybrid_simulator(n, edges, seed, shots=256, grid=12, polish=8):
    samples, meta = _qaoa_samples(n, edges, seed, shots, grid)
    top = sorted(set(samples), key=lambda s: -cut_value(s, edges))[:polish]
    best = max(_local_search(s, n, edges)[1] for s in top)
    meta["polished"] = len(top)
    return best, meta


LEGS = {
    "classical_exact": ("classical", False, classical_exact),
    "classical_heuristic": ("classical", False, classical_heuristic),
    "quantum_simulator": ("quantum", True, quantum_simulator),
    "hybrid_simulator": ("hybrid", True, hybrid_simulator),
}


def run_arena(n: int, edge_p: float, graph_seed: int, repeats: int = MIN_REPEATS, log=None,
              qpu_adapter=None) -> dict:
    edges = random_graph(n, edge_p, graph_seed)
    optimum, _ = classical_exact(n, edges, 0)
    legs = {}
    for name, (family, simulated, fn) in LEGS.items():
        qualities, times, metas = [], [], []
        for rep in range(repeats):
            t0 = time.perf_counter()
            value, meta = fn(n, edges, 1000 + rep)
            times.append(time.perf_counter() - t0)
            qualities.append(value / optimum)
            metas.append(meta)
        legs[name] = {
            "family": family,
            "simulated": simulated,
            "status": "RUN",
            "repeats": repeats,
            "quality_median": statistics.median(qualities),
            "quality_min": min(qualities),
            "quality_stdev": statistics.pstdev(qualities),
            "wall_time_s_median": statistics.median(times),
            "queue_time_s": 0.0,
            "cost_micro_usd": 0,
            "resources": metas[0],
        }
    legs["quantum_hardware"] = {
        "family": "quantum", "simulated": False, "status": "NOT_RUN",
        "reason": "NO_QPU_ADAPTER_OR_CREDENTIALS" if qpu_adapter is None else "NOT_IMPLEMENTED",
    }
    verdict, rationale = decide_verdict(legs)
    report = {
        "schema_version": ARENA_SCHEMA,
        "problem": {"kind": "maxcut", "n": n, "edges": len(edges), "graph_digest": digest([list(e) for e in edges]),
                    "optimum": optimum},
        "rules": {"min_repeats": MIN_REPEATS, "quality_margin": QUALITY_MARGIN, "time_ratio": TIME_RATIO},
        "legs": legs,
        "verdict": verdict,
        "rationale": rationale,
    }
    if log is not None:
        log.append("ARENA_RESULT", {"report_digest": digest(_canon(report)), "verdict": verdict, "n": n})
    return report


def _canon(obj):
    """Floats -> fixed decimal strings so the report can be digested."""
    if isinstance(obj, float):
        return format(obj, ".9f")
    if isinstance(obj, dict):
        return {k: _canon(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_canon(v) for v in obj]
    return obj


def decide_verdict(legs: dict) -> tuple[str, str]:
    run = {k: v for k, v in legs.items() if v["status"] == "RUN"}
    if not run or any(v["repeats"] < MIN_REPEATS for v in run.values()):
        return "INSUFFICIENT_EVIDENCE", "a leg has fewer than the pre-registered repeats"
    best_q = max(v["quality_median"] for v in run.values())
    tied = {k: v for k, v in run.items() if v["quality_median"] >= best_q - QUALITY_MARGIN}
    families = {v["family"] for v in tied.values()}
    if len(families) == 1:
        winner_family = families.pop()
        winner = min(tied, key=lambda k: tied[k]["wall_time_s_median"])
        why = f"only {winner_family} legs reach the best quality ({best_q:.3f})"
    else:
        by_family = {f: min(v["wall_time_s_median"] for v in tied.values() if v["family"] == f) for f in families}
        ordered = sorted(by_family.items(), key=lambda kv: kv[1])
        if ordered[1][1] / max(ordered[0][1], 1e-12) < TIME_RATIO:
            return "NO_MEANINGFUL_ADVANTAGE", f"families tie on quality and the time lead is under {TIME_RATIO}x"
        winner_family = ordered[0][0]
        winner = min((k for k in tied if tied[k]["family"] == winner_family), key=lambda k: tied[k]["wall_time_s_median"])
        why = f"{winner_family} ties on quality and is >= {TIME_RATIO}x faster ({ordered[0][1]:.4f}s vs {ordered[1][1]:.4f}s)"
    verdict = {"classical": "CLASSICAL_WINS", "quantum": "QUANTUM_WINS", "hybrid": "HYBRID_WINS"}[winner_family]
    if verdict != "CLASSICAL_WINS" and run[winner]["simulated"]:
        return "INSUFFICIENT_EVIDENCE", f"{winner} leads but is simulated; a simulator cannot show hardware advantage ({why})"
    return verdict, f"{winner}: {why}"
