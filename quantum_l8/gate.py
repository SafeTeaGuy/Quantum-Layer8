"""Quantum Trust Gate (EXPERIMENTAL, prototype-local semantics).

One decision function, ``QuantumTrustGate.decide``. It answers, for one signed
QuantumExecutionRequest, who asked, who ultimately authorized it, through which
delegation chain, for which exact workload, backend, resources, budget and
crypto policy, and whether any of that was replayed, revoked, substituted,
downgraded or altered.

Determinism: every check runs in a fixed order and appends named reason codes.
The state is derived from the reason set by a fixed precedence:

    any REVOKED_* reason          -> REVOKED
    any other non-evidence reason -> DENIED
    only evidence-missing reasons -> INSUFFICIENT_EVIDENCE
    no reasons                    -> AUTHORIZED

Checks that cannot be evaluated without an authenticated request (schema,
unknown agent, bad agent signature) stop evaluation early; that is also
deterministic.

AUTHORIZED is the only state that issues a gate-signed
QuantumExecutionAuthorization, records the request id and nonce, and reserves
execution count and cost on every delegation in the chain. Rejected requests
burn nothing.

Consumption (``consume``) is single-use, atomic under a lock, and re-checks
revocation and validity at the moment of execution.
"""

from __future__ import annotations

import threading

from quantum_l8 import suites
from quantum_l8.canonical import digest, is_hex64
from quantum_l8.contracts import (
    CIRCUIT_PINNED,
    DELEGATION_DOMAIN,
    REQUEST_DOMAIN,
    REVOCATION_DOMAIN,
    REVOCATION_SCHEMA,
    canonical_id,
    chain_digest,
    delegation_well_formed,
    estimate_cost_micro_usd,
    program_digest,
    request_schema_ok,
    request_well_formed,
    scope_is_attenuation,
)
from quantum_l8.evidence_log import EvidenceLog

AUTHORIZATION_DOMAIN = "L8X_QUANTUM_EXECUTION_AUTHORIZATION_V0"
DECISION_DOMAIN = "L8X_QUANTUM_GATE_DECISION_V0"
AUTHORIZATION_SCHEMA = "l8x.quantum-execution-authorization.v0"
DECISION_SCHEMA = "l8x.quantum-gate-decision.v0"
GATE_POLICY_SCHEMA = "l8x.quantum-gate-policy.v0"

AUTHORIZED = "AUTHORIZED"
DENIED = "DENIED"
REVOKED = "REVOKED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

MAX_CHAIN_DEPTH = 4

# Reason codes that mean "evidence is missing", not "evidence says no".
INSUFFICIENT_REASONS = frozenset({
    "REQUEST_SCHEMA_UNSUPPORTED",
    "AGENT_IDENTITY_UNKNOWN",
    "DELEGATION_NOT_FOUND",
    "ISSUER_IDENTITY_UNKNOWN",
    "BACKEND_UNKNOWN",
    "PROGRAM_MISSING",
})
REVOKED_REASONS = frozenset({"REVOKED_DELEGATION", "REVOKED_AGENT", "REVOKED_ISSUER"})


def state_for(reasons: list[str]) -> str:
    if any(r in REVOKED_REASONS for r in reasons):
        return REVOKED
    if any(r not in INSUFFICIENT_REASONS for r in reasons):
        return DENIED
    if reasons:
        return INSUFFICIENT_EVIDENCE
    return AUTHORIZED


def build_gate_policy(
    policy_id: str,
    operator_id: str,
    root_principal_ids: list[str],
    crypto_floor: str,
    backends: list[dict],
    executor_ids: list[str],
    max_clock_skew_ms: int = 300_000,
) -> dict:
    return {
        "schema_version": GATE_POLICY_SCHEMA,
        "policy_id": policy_id,
        "operator_id": operator_id,
        "root_principal_ids": sorted(root_principal_ids),
        "crypto_floor": crypto_floor,
        "max_clock_skew_ms": max_clock_skew_ms,
        "backends": sorted(backends, key=lambda d: d["backend_id"]),
        "executor_ids": sorted(executor_ids),
    }


def backend_map(policy: dict) -> dict:
    return {d["backend_id"]: d for d in policy["backends"]}


class IdentityRegistry:
    """Claim-once map identity_id -> public identity. The id must derive from
    the key material and the suite (no re-binding, no suite substitution)."""

    def __init__(self):
        self._ids: dict[str, dict] = {}

    def register(self, public_identity: dict) -> str:
        iid = suites.identity_id(public_identity)
        existing = self._ids.get(iid)
        if existing is not None and existing != public_identity:
            raise ValueError("identity id already bound")
        self._ids[iid] = public_identity
        return iid

    def get(self, iid: str) -> dict | None:
        return self._ids.get(iid)

    def snapshot(self) -> dict:
        return dict(self._ids)


def scope_violations(chain: list[dict], workload: dict, backend: dict | None, request: dict | None,
                     program_text: str | None = None) -> list[str]:
    """Scope checks shared by the gate and the router. ``chain`` is the list of
    delegation bodies root -> leaf. ``backend`` is a registered descriptor."""
    reasons: list[str] = []
    for d in chain:
        s = d["scope"]
        if workload["algorithm_id"] not in s["algorithm_ids"]:
            reasons.append("ALGORITHM_NOT_AUTHORIZED")
        if s["circuits"]["mode"] == CIRCUIT_PINNED and workload["program_digest"] not in s["circuits"]["digests"]:
            reasons.append("CIRCUIT_NOT_AUTHORIZED")
        if workload["shots"] > s["max_shots_per_execution"]:
            reasons.append("SHOTS_EXCEED_DELEGATION")
        if backend is not None:
            if backend["backend_id"] not in s["backend_ids"]:
                reasons.append("BACKEND_NOT_AUTHORIZED")
            if backend["backend_class"] not in s["backend_classes"]:
                reasons.append("BACKEND_CLASS_NOT_AUTHORIZED")
            if backend["provider"] not in s["providers"]:
                reasons.append("PROVIDER_NOT_AUTHORIZED")
        if request is not None:
            if request["cost_limit_micro_usd"] > s["max_cost_micro_usd_per_execution"]:
                reasons.append("COST_LIMIT_EXCEEDS_DELEGATION")
            if request["result_destination"] not in s["result_destinations"]:
                reasons.append("RESULT_DESTINATION_NOT_AUTHORIZED")
    if backend is not None:
        if workload["num_qubits"] > backend["max_qubits"]:
            reasons.append("QUBITS_EXCEED_BACKEND")
        if chain and chain[-1]["tenant_id"] not in backend["allowed_tenants"]:
            reasons.append("BACKEND_TENANT_NOT_PERMITTED")
    return _dedupe(reasons)


def _dedupe(xs: list[str]) -> list[str]:
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


class QuantumTrustGate:
    def __init__(self, gate_key: suites.KeyBundle, policy: dict, identities: IdentityRegistry, log: EvidenceLog):
        self.key = gate_key
        self.policy = policy
        self.policy_digest = digest(policy)
        self.identities = identities
        self.log = log
        self.backends = backend_map(policy)
        self._delegations: dict[str, dict] = {}
        self._revoked: dict[str, int] = {}  # target id -> effective_at_ms
        self._seen_requests: set[str] = set()
        self._seen_nonces: set[tuple[str, str]] = set()
        self._reserved: dict[str, dict] = {}  # delegation_id -> {"executions", "cost"}
        self._authorizations: dict[str, dict] = {}
        self._consumed: set[str] = set()
        self._lock = threading.Lock()
        if suites.combine_levels([policy["crypto_floor"]]) is None:
            raise ValueError("unknown crypto floor")

    @property
    def gate_id(self) -> str:
        return self.key.identity_id()

    # --- stores ---

    def register_delegation(self, env: dict) -> None:
        """Stores only well-formed records with a canonical id. Signatures are
        verified at every use, not trusted from the store."""
        if not delegation_well_formed(env):
            raise ValueError("malformed delegation")
        did = env["body"]["delegation_id"]
        if did in self._delegations and self._delegations[did] != env:
            raise ValueError("delegation id already bound")
        self._delegations[did] = env
        self.log.append("DELEGATION_REGISTERED", {"delegation_id": did, "delegation_digest": digest(env)})

    def record_revocation(self, env: dict) -> str:
        """Accepts a signed revocation from the operator (any target) or from
        the issuer of the target delegation. Returns a reason code."""
        try:
            b = env["body"]
            if b.get("schema_version") != REVOCATION_SCHEMA or canonical_id(b, "revocation_id") != b.get("revocation_id"):
                return "REVOCATION_MALFORMED"
            eff = b.get("effective_at_ms")
            if not isinstance(eff, int) or isinstance(eff, bool) or eff < 0:
                return "REVOCATION_MALFORMED"
            if b.get("target_kind") not in ("DELEGATION", "AGENT") or not is_hex64(b.get("target_id")):
                return "REVOCATION_MALFORMED"
            issuer = self.identities.get(b["issuer_id"])
            if issuer is None:
                return "REVOCATION_ISSUER_UNKNOWN"
            ok, _ = suites.verify(issuer, REVOCATION_DOMAIN, b, env["proof"])
            if not ok:
                return "REVOCATION_SIGNATURE_INVALID"
            is_operator = b["issuer_id"] == self.policy["operator_id"]
            if b["target_kind"] == "DELEGATION":
                target = self._delegations.get(b["target_id"])
                if not is_operator and (target is None or target["body"]["issuer_id"] != b["issuer_id"]):
                    return "REVOCATION_UNAUTHORIZED_REVOKER"
            elif not is_operator:
                return "REVOCATION_UNAUTHORIZED_REVOKER"
        except Exception:
            return "REVOCATION_MALFORMED"
        prev = self._revoked.get(b["target_id"])
        self._revoked[b["target_id"]] = b["effective_at_ms"] if prev is None else min(prev, b["effective_at_ms"])
        self.log.append("REVOCATION_RECORDED", {"revocation_id": b["revocation_id"], "target_kind": b["target_kind"],
                                                "target_id": b["target_id"], "effective_at_ms": b["effective_at_ms"],
                                                "revocation_digest": digest(env)})
        return "REVOCATION_RECORDED"

    def _is_revoked(self, target_id: str, now_ms: int) -> bool:
        eff = self._revoked.get(target_id)
        return eff is not None and now_ms >= eff

    # --- delegation chain ---

    def resolve_chain(self, leaf_id: str) -> tuple[list[dict] | None, list[str]]:
        """Walk leaf -> root. Returns envelopes root -> leaf, or None with reasons."""
        chain, seen, cur = [], set(), leaf_id
        while cur is not None:
            if cur in seen:
                return None, ["DELEGATION_CYCLE"]
            seen.add(cur)
            env = self._delegations.get(cur)
            if env is None:
                return None, ["DELEGATION_NOT_FOUND"]
            chain.append(env)
            if len(chain) > MAX_CHAIN_DEPTH:
                return None, ["DELEGATION_DEPTH_EXCEEDED"]
            cur = env["body"]["parent_delegation_id"]
        chain.reverse()
        return chain, []

    def _check_chain(self, chain: list[dict], agent_id: str, now_ms: int) -> list[str]:
        reasons: list[str] = []
        root = chain[0]["body"]
        if root["issuer_id"] not in self.policy["root_principal_ids"]:
            reasons.append("ROOT_PRINCIPAL_NOT_PERMITTED")
        for i, env in enumerate(chain):
            b = env["body"]
            if not delegation_well_formed(env):
                reasons.append("DELEGATION_MALFORMED")
                continue
            issuer = self.identities.get(b["issuer_id"])
            if issuer is None:
                reasons.append("ISSUER_IDENTITY_UNKNOWN")
            else:
                ok, why = suites.verify(issuer, DELEGATION_DOMAIN, b, env["proof"])
                if not ok:
                    reasons.extend(["DELEGATION_SIGNATURE_INVALID", why])
            if b["issuer_id"] == b["subject_id"]:
                reasons.append("SELF_DELEGATION")
            if i > 0:
                parent = chain[i - 1]["body"]
                if b["issuer_id"] != parent["subject_id"]:
                    reasons.append("DELEGATION_CHAIN_BROKEN")
                if not parent["may_redelegate"]:
                    reasons.append("REDELEGATION_NOT_PERMITTED")
                wider = scope_is_attenuation(b, parent)
                if wider:
                    reasons.append("DELEGATION_ESCALATION")
            if now_ms < b["not_before_ms"]:
                reasons.append("DELEGATION_NOT_YET_VALID")
            if now_ms >= b["expires_at_ms"]:
                reasons.append("DELEGATION_EXPIRED")
            if self._is_revoked(b["delegation_id"], now_ms):
                reasons.append("REVOKED_DELEGATION")
            if self._is_revoked(b["issuer_id"], now_ms):
                reasons.append("REVOKED_ISSUER")
        if chain[-1]["body"]["subject_id"] != agent_id:
            reasons.append("DELEGATION_SUBJECT_MISMATCH")
        return reasons

    def effective_crypto_policy(self, chain: list[dict]) -> str | None:
        return suites.combine_levels([self.policy["crypto_floor"]] + [e["body"]["crypto_policy"] for e in chain])

    # --- the decision ---

    def decide(self, request_env: dict, program_text: str | None, tenant_context: str, now_ms: int,
               intended_executor_id: str) -> dict:
        try:
            request_digest = digest(request_env)
        except Exception:  # not canonical (e.g. a float): a named refusal, never an exception
            request_digest = None
        if request_digest is None:
            reasons, chain, req = ["REQUEST_MALFORMED"], None, None
        else:
            reasons, chain, req = self._evaluate(request_env, program_text, tenant_context, now_ms,
                                                 intended_executor_id)
        state = state_for(reasons)
        authorization = None
        with self._lock:
            if state == AUTHORIZED:
                # Re-check single-use and budgets under the lock (linearization point).
                late = self._replay_and_budget(req, chain)
                if late:
                    reasons, state = late, state_for(late)
            if state == AUTHORIZED:
                authorization = self._issue(req, request_digest, chain, now_ms, intended_executor_id)
        decision_body = {
            "schema_version": DECISION_SCHEMA,
            "request_id": req["request_id"] if req else None,
            "request_digest": request_digest,
            "state": state,
            "reasons": reasons,
            "gate_policy_digest": self.policy_digest,
            "authorization_id": authorization["body"]["authorization_id"] if authorization else None,
            "decided_at_ms": now_ms,
            "gate_id": self.gate_id,
            "signature_suite": self.key.suite,
        }
        decision = {"body": decision_body, "proof": self.key.sign(DECISION_DOMAIN, decision_body)}
        self.log.append("GATE_DECISION", {"decision_digest": digest(decision), "state": state, "reasons": reasons,
                                          "request_digest": request_digest})
        if authorization is not None:
            self.log.append("AUTHORIZATION_ISSUED", {"authorization_id": authorization["body"]["authorization_id"],
                                                     "authorization_digest": digest(authorization)})
        return {"decision": decision, "authorization": authorization}

    def _evaluate(self, env, program_text, tenant_context, now_ms, intended_executor_id):
        if not request_schema_ok(env):
            return ["REQUEST_SCHEMA_UNSUPPORTED"], None, None
        if not request_well_formed(env):
            return ["REQUEST_MALFORMED"], None, None
        req = env["body"]
        agent = self.identities.get(req["agent_id"])
        if agent is None:
            return ["AGENT_IDENTITY_UNKNOWN"], None, req
        ok, why = suites.verify(agent, REQUEST_DOMAIN, req, env["proof"])
        if not ok:
            return ["AGENT_SIGNATURE_INVALID", why], None, req

        reasons: list[str] = []
        if req["tenant_id"] != tenant_context:
            reasons.append("TENANT_MISMATCH")
        if intended_executor_id not in self.policy["executor_ids"]:
            reasons.append("EXECUTOR_NOT_PERMITTED")
        if self._is_revoked(req["agent_id"], now_ms):
            reasons.append("REVOKED_AGENT")

        chain, chain_reasons = self.resolve_chain(req["delegation_id"])
        reasons.extend(chain_reasons)
        if chain is None:
            return _dedupe(reasons), None, req
        bodies = [e["body"] for e in chain]
        reasons.extend(self._check_chain(chain, req["agent_id"], now_ms))
        if req["principal_id"] != bodies[0]["issuer_id"]:
            reasons.append("PRINCIPAL_MISMATCH")
        if req["delegation_chain_digest"] != chain_digest([b["delegation_id"] for b in bodies]):
            reasons.append("DELEGATION_CHAIN_DIGEST_MISMATCH")
        if any(b["tenant_id"] != req["tenant_id"] for b in bodies):
            reasons.append("TENANT_MISMATCH")

        # Crypto policy: the requirement comes from the operator floor and the
        # principal-signed chain, never from the request. The request must
        # restate at least that level, and every signature must satisfy it.
        effective = self.effective_crypto_policy(chain)
        if effective is None:
            reasons.append("CRYPTO_POLICY_UNSATISFIABLE")
        else:
            if not suites.level_at_least(req["crypto_policy"], effective):
                reasons.append("CRYPTO_POLICY_DOWNGRADE")
            if not suites.satisfies(req["signature_suite"], effective):
                reasons.append("REQUEST_SUITE_BELOW_POLICY")
            if any(not suites.satisfies(b["signature_suite"], effective) for b in bodies):
                reasons.append("DELEGATION_SUITE_BELOW_POLICY")
            if not suites.satisfies(self.key.suite, effective):
                reasons.append("GATE_SUITE_BELOW_POLICY")

        # Workload integrity: the exact bytes and parameters that were signed.
        w = req["workload"]
        if digest(w) != req["workload_digest"]:
            reasons.append("WORKLOAD_DIGEST_MISMATCH")
        if program_text is None:
            reasons.append("PROGRAM_MISSING")
        else:
            try:
                pd = program_digest(program_text)
            except Exception:
                pd = None
            if pd is None:
                reasons.append("PROGRAM_MALFORMED")
            elif pd != w["program_digest"]:
                reasons.append("PROGRAM_DIGEST_MISMATCH")

        backend = self.backends.get(req["backend"]["backend_id"])
        if backend is None:
            reasons.append("BACKEND_UNKNOWN")
        else:
            if req["backend"]["backend_class"] != backend["backend_class"]:
                reasons.append("BACKEND_CLASS_MISMATCH")
            if req["backend"]["provider"] != backend["provider"]:
                reasons.append("PROVIDER_MISMATCH")
            if w["num_qubits"] > req["resource_limits"]["max_qubits"]:
                reasons.append("QUBITS_EXCEED_REQUEST_LIMIT")
            if estimate_cost_micro_usd(backend, w["shots"]) > req["cost_limit_micro_usd"]:
                reasons.append("COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT")
        reasons.extend(scope_violations(bodies, w, backend, req))

        skew = self.policy["max_clock_skew_ms"]
        if req["created_at_ms"] > now_ms + skew:
            reasons.append("REQUEST_FROM_FUTURE")
        if req["execution_deadline_ms"] <= now_ms:
            reasons.append("EXECUTION_DEADLINE_PASSED")

        reasons.extend(self._replay_and_budget(req, bodies))
        return _dedupe(reasons), bodies, req

    def _replay_and_budget(self, req, bodies) -> list[str]:
        reasons = []
        if req["request_id"] in self._seen_requests:
            reasons.append("REQUEST_REPLAYED")
        if (req["agent_id"], req["nonce"]) in self._seen_nonces:
            reasons.append("NONCE_REPLAYED")
        for b in bodies:
            r = self._reserved.get(b["delegation_id"], {"executions": 0, "cost": 0})
            if r["executions"] + 1 > b["scope"]["max_executions"]:
                reasons.append("EXECUTION_COUNT_EXHAUSTED")
            if r["cost"] + req["cost_limit_micro_usd"] > b["scope"]["max_total_cost_micro_usd"]:
                reasons.append("COST_BUDGET_EXHAUSTED")
        return _dedupe(reasons)

    def _issue(self, req, request_digest, bodies, now_ms, intended_executor_id) -> dict:
        self._seen_requests.add(req["request_id"])
        self._seen_nonces.add((req["agent_id"], req["nonce"]))
        for b in bodies:
            r = self._reserved.setdefault(b["delegation_id"], {"executions": 0, "cost": 0})
            r["executions"] += 1
            r["cost"] += req["cost_limit_micro_usd"]
        backend = self.backends[req["backend"]["backend_id"]]
        valid_until = min([req["execution_deadline_ms"]] + [b["expires_at_ms"] for b in bodies])
        body = {
            "schema_version": AUTHORIZATION_SCHEMA,
            "gate_id": self.gate_id,
            "gate_policy_digest": self.policy_digest,
            "request_id": req["request_id"],
            "request_digest": request_digest,
            "tenant_id": req["tenant_id"],
            "principal_id": req["principal_id"],
            "agent_id": req["agent_id"],
            "delegation_chain": [b["delegation_id"] for b in bodies],
            "workload_digest": req["workload_digest"],
            "program_digest": req["workload"]["program_digest"],
            "algorithm_id": req["workload"]["algorithm_id"],
            "shots": req["workload"]["shots"],
            "backend_id": backend["backend_id"],
            "backend_descriptor_digest": digest(backend),
            "backend_class": backend["backend_class"],
            "provider": backend["provider"],
            "reserved_cost_micro_usd": req["cost_limit_micro_usd"],
            "result_destination": req["result_destination"],
            "crypto_policy": self.effective_crypto_policy([{"body": b} for b in bodies]),
            "intended_executor_id": intended_executor_id,
            "permitted_execution_count": 1,
            "issued_at_ms": now_ms,
            "valid_until_ms": valid_until,
            "signature_suite": self.key.suite,
        }
        body["authorization_id"] = digest(body)
        env = {"body": body, "proof": self.key.sign(AUTHORIZATION_DOMAIN, body)}
        self._authorizations[body["authorization_id"]] = env
        return env

    # --- consumption ---

    def consume(self, authorization_env: dict, executor_id: str, now_ms: int) -> tuple[bool, str]:
        """Single use. Re-checks revocation and validity at execution time."""
        with self._lock:
            try:
                b = authorization_env["body"]
                aid = b["authorization_id"]
            except Exception:
                return False, "AUTHORIZATION_MALFORMED"
            issued = self._authorizations.get(aid)
            if issued is None or issued != authorization_env:
                return False, "AUTHORIZATION_NOT_ISSUED_BY_GATE"
            ok, _ = suites.verify(self.key.public_identity(), AUTHORIZATION_DOMAIN, b, authorization_env["proof"])
            if not ok:
                return False, "AUTHORIZATION_SIGNATURE_INVALID"
            if aid in self._consumed:
                return False, "AUTHORIZATION_ALREADY_CONSUMED"
            if executor_id != b["intended_executor_id"]:
                return False, "EXECUTOR_MISMATCH"
            if now_ms >= b["valid_until_ms"]:
                return False, "AUTHORIZATION_EXPIRED"
            if self._is_revoked(b["agent_id"], now_ms):
                return False, "REVOKED_AGENT"
            for did in b["delegation_chain"]:
                if self._is_revoked(did, now_ms):
                    return False, "REVOKED_DELEGATION"
                if self._is_revoked(self._delegations[did]["body"]["issuer_id"], now_ms):
                    return False, "REVOKED_ISSUER"
            self._consumed.add(aid)
            self.log.append("AUTHORIZATION_CONSUMED", {"authorization_id": aid, "executor_id": executor_id,
                                                       "consumed_at_ms": now_ms})
            return True, "CONSUMED"

    def delegation_envelopes(self, ids: list[str]) -> list[dict]:
        return [self._delegations[i] for i in ids]
