"""Run the Quantum/Classical Arena on MaxCut and print the verdicts.

    python -m examples.quantum_arena [n ...]

Every leg result is appended to an evidence log. No QPU is used; the hardware
leg is reported NOT_RUN with its reason.
"""

import sys

from quantum_l8 import suites
from quantum_l8.arena import run_arena
from quantum_l8.evidence_log import EvidenceLog


def main(sizes):
    log = EvidenceLog("log:arena", suites.KeyBundle.generate(suites.SUITE_HYBRID))
    for n in sizes:
        r = run_arena(n, 0.5, graph_seed=42, repeats=5, log=log)
        p = r["problem"]
        print(f"MaxCut n={n} edges={p['edges']} optimum={p['optimum']}: {r['verdict']}")
        print(f"  {r['rationale']}")
        for name, leg in r["legs"].items():
            if leg["status"] == "RUN":
                print(f"  {name:20} quality median {leg['quality_median']:.3f} (min {leg['quality_min']:.3f})"
                      f"  wall {leg['wall_time_s_median'] * 1000:8.2f} ms")
            else:
                print(f"  {name:20} {leg['status']}: {leg['reason']}")
    log.checkpoint(0)
    print(f"evidence log: {len(log.entries)} entries, head {log.head[:16]}")


if __name__ == "__main__":
    main([int(x) for x in sys.argv[1:]] or [6, 8, 10, 12, 14])
