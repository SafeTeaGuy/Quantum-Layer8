# Quantum-Layer8

Open evidence substrate for agent actions.

The persistent agent keeps its identity, delegated authority, and verifiable history. Models, tools, APIs, and QPUs are swappable providers underneath.

This repo supplies the boring infrastructure layer that becomes necessary once agents take consequential actions whose authorization, exact request, result, and policy must be independently checkable:

- Who authorized the action?
- What exact request / tool call / circuit was submitted?
- Which provider / resource executed it?
- What policy applied?
- What was returned?
- Can a third party verify the package without trusting only the originating agent or provider?

## Evidence Package

Canonical JSON document defined by `schema/agent_action_evidence.schema.json`.

Core fields:
- `agent_identity` / `authorization` — cryptographic binding from Layer8-style substrate
- `action_hash` — SHA-256 of the exact submitted payload (prompt, tool call, circuit, API request)
- `action_type` — `model_call`, `tool_call`, `quantum_job`, `payment`, `other`
- `provider` / `target`
- `policy` applied
- `result` + optional bounds / status
- `settlement` record
- `provider_attestation` (optional)
- `package_hash` — self-hash of the canonical form

Quantum-specific fields (`calibration_snapshot`, quantum result shapes) remain optional under the same package so existing adapters continue to work.

## Quick Start

```bash
pip install -r requirements.txt
python examples/minimal_example.py          # quantum stub path
python examples/model_call_example.py       # classical model call path
```

## What this is not

- Quantum hardware or control systems
- A quantum cloud or marketplace
- A full hybrid scheduler or agent runtime
- A circuit optimizer
- A closed platform that owns the agent relationship

Adapters exist so the same agent can produce and verify evidence across providers and action types without rebuilding its identity or history.

## Status

Generalized format + quantum stubs + classical model-call example. Real provider integrations and Layer8 identity binding are next.
