# Quantum-Layer8

Open evidence substrate for quantum job provenance.

Persistent agent identity + delegated authority stay with the agent.
The QPU (like a model) is a swappable intelligence/compute provider.

This repo supplies the boring infrastructure layer that becomes necessary once agents take consequential actions that depend on quantum results:

- Who authorized the job?
- What exact circuit/job was submitted?
- Which provider/device ran it?
- What calibration / error bounds applied at execution time?
- What was returned?
- Can a third party independently verify the package?

## Evidence Package

Canonical JSON document defined by `schema/quantum_job_evidence.schema.json`.

Core fields:
- `agent_identity` / `authorization` — cryptographic binding from Layer8-style substrate
- `job_hash` — SHA-256 of the exact submitted circuit/program
- `provider` / `device_id` / `backend_version`
- `calibration_snapshot` — timestamped properties (T1/T2, gate fidelities, readout errors) or pointer + hash
- `results` + `error_bounds`
- `policy` applied
- `settlement` record
- `provider_attestation` (optional signed claim from the cloud)
- `package_hash` — self-hash of the canonical form for anchoring

## Quick Start

```bash
pip install -r requirements.txt
python examples/minimal_example.py
```

## What this is not

- Quantum hardware or control systems
- A quantum cloud or marketplace
- A full hybrid scheduler
- A circuit optimizer
- A closed platform that owns the agent relationship

Adapters exist so the same agent can produce and verify evidence across providers without rebuilding its identity or history.

## Status

Minimal viable format + stubs. Real provider integrations and Layer8 identity binding are the next commits.
