# Workload router and Quantum/Classical Arena

> **Experimental.** Implemented in `quantum_l8/router.py` and
> `quantum_l8/arena.py`. Run the arena with `python -m examples.quantum_arena`.

## 1. Authority is separate from optimization

```
 signed delegation chain ──► permitted_options()  ──► permitted set  (AUTHORITY: Layer8)
                                (gate's own scope_violations)
 signals (queue, cost,  ──► optimizer.score()     ──► ranking        (OPTIMIZATION: replaceable)
  errors, availability)        over the permitted set only
                         ──► route()               ──► RoutingDecision (evidence)
                                refuses a choice outside the permitted set
 agent signs a request naming the choice ──► Quantum Trust Gate re-checks everything
```

- **The router grants nothing.** Its output is advice. If the router is
  compromised or bypassed, the gate still refuses an unpermitted backend
  (`test_compromised_optimizer_cannot_route_outside_authority`).
- **One scope function.** `permitted_options` calls the gate's
  `scope_violations`. Router and gate cannot disagree about what is
  permitted.
- **Optimizer preferences never widen the set.** If the only permitted
  option scores badly, it is still the only option
  (`test_optimizer_preference_never_overrides_authority`). The reverse also
  holds: no score can add an option.
- **Region and geography are authority, not optimization.** They are
  applied as a permitted-set filter (`allowed_regions`), never as a weight.

## 2. Routing signals

| Signal | Source | Authority or optimization? | Trust |
|---|---|---|---|
| backend class, provider, backend id | operator descriptor plus delegation scope | **authority** | signed / pinned |
| qubit requirement vs `max_qubits` | declared workload plus descriptor | **authority** (hard limit) | the declaration is checked by adapter preflight |
| shots, cost ceiling, budget | delegation scope | **authority** | signed |
| region / jurisdiction, tenant | descriptor, policy | **authority** | pinned |
| provider trust | operator | **authority** if it is a deny-list; optimization if it is a weight | operator statement |
| availability, queue depth, estimated queue time | provider API | optimization | **CLAIMED** |
| estimated runtime | provider, historical | optimization | CLAIMED or history |
| estimated cost | descriptor pricing × shots | optimization (the ceiling is authority) | operator config |
| error rates, calibration | provider | optimization | CLAIMED, time-varying |
| circuit depth, after transpilation | adapter | optimization | computed |
| classical simulation cost (≈ 2^n amplitudes for statevector) | computed | optimization: a strong prior *against* QPU for small n | computed |
| historical performance and confidence | arena records in the evidence log | optimization | Layer8 evidence |

The prototype's `WeightedOptimizer` scores (queue + runtime) time, cost and
error rate. It adds a large penalty to `QUANTUM_HARDWARE` whenever exact
classical simulation is cheap (n ≤ 20 by default). The penalty is an
optimizer rule and is replaceable.

## 3. Routing evidence

Each `route()` call produces a `RoutingDecision` and appends its digest to
the evidence log. The decision contains:

- `workload_digest` and `delegation_chain`;
- `permitted`, plus `excluded`, with a reason for each exclusion;
- `signals` and `signals_digest`;
- `optimizer_id` and `ranking`;
- `chosen`, `proposed` and `status` (`ROUTED / ROUTE_NOT_PERMITTED /
  ROUTE_UNAVAILABLE / NO_PERMITTED_OPTION`).

**What it proves:** what was permitted, which signals the router saw, and
what it chose.

**What it does not prove:** that the signals were true, or that the choice
was optimal.

## 4. CPU / GPU / QPU / hybrid as permitted choices

The same workload (`algorithm_id` + program digest) can be authorized on
several backend classes. The prototype registers three:

| Backend | Class | Adapter |
|---|---|---|
| `cpu.exact_sampler` | CPU | exact statevector + classical RNG |
| `qiskit.basic_simulator` | QUANTUM_SIMULATOR | Qiskit `BasicSimulator` |
| `ibm.qpu.example_heron` | QUANTUM_HARDWARE | none; registered so authority can name it |

For the Bell workload, the router picks `cpu.exact_sampler`: it is permitted,
available, fastest and free (`test_router_only_ranks_permitted`). Hybrid
algorithms such as QAOA are a *sequence* of authorized jobs plus classical
steps. A hybrid budget belongs on the delegation (`max_executions`,
`max_total_cost`), not on each job. GPU and TPU are in the backend-class
vocabulary but were not prototyped.

## 5. Arena results (negative results are results)

Pre-registered rules are in `arena.py`:

- at least 3 repeats per leg;
- a quality margin of 0.01;
- a 1.5× time ratio;
- a simulator lead never counts as `QUANTUM_WINS`.

Run: `python -m examples.quantum_arena`, MaxCut on G(n, 0.5), graph seed 42,
5 repeats. Times are medians on the build container.

| n | edges | classical exact | classical heuristic | QAOA p=1 (simulator) | hybrid (QAOA + local search) | real QPU | Verdict |
|---|---|---|---|---|---|---|---|
| 6 | 6 | 1.000, 0.02 ms | 1.000, 0.11 ms | 1.000, 25 ms | 1.000, 22 ms | NOT_RUN | **CLASSICAL_WINS** |
| 8 | 12 | 1.000, 0.05 ms | 1.000, 0.19 ms | 1.000, 28 ms | 1.000, 29 ms | NOT_RUN | **CLASSICAL_WINS** |
| 10 | 22 | 1.000, 0.15 ms | 1.000, 0.37 ms | 1.000 (min 0.938), 46 ms | 1.000, 47 ms | NOT_RUN | **CLASSICAL_WINS** |
| 12 | 31 | 1.000, 0.36 ms | 1.000, 0.67 ms | **0.955**, 92 ms | 1.000, 74 ms | NOT_RUN | **CLASSICAL_WINS** |
| 14 | 47 | 1.000, 1.3 ms | 1.000, 0.9 ms | **0.824**, 387 ms | 1.000, 350 ms | NOT_RUN | **CLASSICAL_WINS** |

Quality is (best cut found) / (optimal cut), as a median over repeats.

How to read these results:

- **No quantum advantage was observed, and none was expected at this scale.**
  Brute force is exact and sub-millisecond up to n = 14.
- **QAOA sample quality is misleading at small n.** Below about n = 10,
  256 shots nearly enumerate the 2^n bitstrings, so the "best sampled cut"
  is close to random search. That is why QAOA ties classical at n ≤ 10 and
  falls behind at n = 12–14, where enumeration stops working.
- **"Hybrid" matches classical only because its classical local-search step
  does the work.** It is slower than the classical heuristic alone.
- **The simulator is classical computation.** Even a simulator win would
  show only that the *algorithm* is good. It would not show a hardware
  advantage. That is why the rule downgrades it to `INSUFFICIENT_EVIDENCE`.
- **The real-QPU leg is `NOT_RUN`** (no adapter or credentials). Any hardware
  claim is `INSUFFICIENT_EVIDENCE`. A hardware run would add queue time
  (often minutes to hours) and noise. Both make it *less* likely to win at
  this scale.

**Implication for the router:** the default optimizer should route
classically simulable workloads (roughly n ≤ 30 for statevector, and more for
structured circuits) to CPU/GPU. It should send work to a QPU only when the
user's purpose is the hardware itself (characterisation, research,
benchmarking) or when the circuit is beyond classical simulation. In the
second case the result cannot be checked classically
(PROOF_OF_COMPUTE.md §4).
