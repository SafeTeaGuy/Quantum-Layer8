# Quantum-Layer8

Authority-and-evidence substrate for autonomous computation.

An entity (agent, machine, service) can prove:
- Who authorized the action (prior policy decision)
- Exactly what was submitted
- What executed and what came back
- That the record was not altered

Models, tools, APIs, and QPUs are swappable providers. The protocol does not care which one wins.

## Objects

- **PolicyDecision** (`schema/policy_decision.schema.json`) — prior authorization: allowed action types, providers, targets, max cost, expiry, delegation proof. Self-hashed.
- **AgentActionEvidence** (`schema/agent_action_evidence.schema.json`) — outcome package that binds the policy decision hash into `authorization`. Self-hashed. Covers both the decision and the result.

Verification checks package integrity and, when the original policy decision is supplied, basic bounds (action type, provider, target, cost).

## Quick Start

```bash
pip install -r requirements.txt
python examples/policy_bound_model_call.py
```

## Status

Policy decision + bound evidence package (v0.3.0). Classical model-call path works end-to-end. Quantum adapters remain as optional extensions under the same path. Real cryptographic signatures and Layer8 identity binding are next.
