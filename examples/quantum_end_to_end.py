"""Smallest end-to-end governed quantum execution.

Principal -> Delegation -> Agent -> Quantum Trust Gate -> Authorization
-> Qiskit (local seeded simulator) -> result -> QuantumExecutionReceipt
-> append-only evidence log -> independent verification.

    python -m examples.quantum_end_to_end [OUT_DIR]

Writes bundle.json and trust_roots.json to OUT_DIR (default
./quantum_demo_out), then verifies them with re-execution. No network, no
credentials, no real QPU.
"""

import json
import os
import sys

from quantum_l8 import suites
from quantum_l8.adapters.qiskit_adapter import CPUExactSamplerAdapter, QiskitBasicSimulatorAdapter
from quantum_l8.executor import Executor
from quantum_l8.scenario import ALG_ROT, DEST, ROT_QASM, TENANT, delegate, make_world, request, trust_roots
from quantum_l8.verify import export_bundle, verify_bundle


def main(out_dir: str = "quantum_demo_out") -> int:
    if not suites.mldsa_available():
        print("ML-DSA unavailable in this cryptography build: hybrid policy cannot be satisfied. Refusing.")
        return 2
    w = make_world(suites.SUITE_HYBRID)
    d = delegate(w, algorithm_ids=[ALG_ROT], max_executions=1)
    print("1. principal", w.principal.identity_id()[:16], "delegated to agent", w.agent.identity_id()[:16])
    print("   scope:", json.dumps(d["body"]["scope"]["algorithm_ids"]), d["body"]["scope"]["backend_ids"],
          "max_exec", d["body"]["scope"]["max_executions"], "policy", d["body"]["crypto_policy"])

    req = request(w, program=ROT_QASM, algorithm_id=ALG_ROT, parameters={"theta": "1.0471975512"}, shots=2048)
    print("2. agent signed request", req["body"]["request_id"], "workload", req["body"]["workload_digest"][:16])

    out = w.gate.decide(req, ROT_QASM, TENANT, w.now(), w.executor_key.identity_id())
    dec = out["decision"]["body"]
    print("3. gate decision:", dec["state"], dec["reasons"])
    if dec["state"] != "AUTHORIZED":
        return 1

    sinks: dict = {}
    adapters = {a.adapter_id: a for a in (QiskitBasicSimulatorAdapter(seed=7), CPUExactSamplerAdapter(seed=7))}
    ex = Executor(w.executor_key, w.gate, adapters, sinks, w.log, clock=w.now)
    res = ex.run(out["authorization"], req, ROT_QASM)
    rb = res["receipt"]["body"]
    print("4. executed on", rb["execution"]["provider_reported_backend"], "outcome", rb["outcome"],
          "counts", rb["result"]["counts"])
    print("   classical check:", rb["classical_verification"]["verdict"], "tvd", rb["classical_verification"]["tvd"])
    print("   delivered to", DEST, ":", res["delivered"])

    replay = w.gate.decide(req, ROT_QASM, TENANT, w.now(), w.executor_key.identity_id())
    print("5. replay of the same request:", replay["decision"]["body"]["state"], replay["decision"]["body"]["reasons"])

    bundle = export_bundle(w, req, ROT_QASM, out, res["receipt"])
    roots = trust_roots(w)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "bundle.json"), "w") as f:
        json.dump(bundle, f, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "trust_roots.json"), "w") as f:
        json.dump(roots, f, indent=1, sort_keys=True)

    report = verify_bundle(json.loads(json.dumps(bundle)), json.loads(json.dumps(roots)), reexecute=True)
    print("6. independent verification: chain_established =", report["chain_established"])
    for f in report["findings"]:
        print(f"   {f['dimension']:22} {f['status']:22} {', '.join(f['codes'])[:90]}")
    print("   wrote", out_dir + "/bundle.json and trust_roots.json")
    return 0 if report["chain_established"] else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
