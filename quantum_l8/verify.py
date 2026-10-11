"""Independent verifier for a governed quantum execution bundle (EXPERIMENTAL).

Inputs: an exported bundle and trust roots pinned out of band (root
principals, gate, executors, log signers, gate-policy digest). Nothing is
read from a live gate.

Output: one finding per dimension, each with a status:

    ESTABLISHED            cryptographically or recomputably shown
    FAILED                 shown to be false or inconsistent
    INSUFFICIENT_EVIDENCE  cannot be decided from this bundle
    CLAIMED                attributed statement, recorded but not verifiable
    NOT_CHECKED            optional check not run

There is deliberately no single "valid" verdict. ``chain_established`` is
True only if every authority and evidence-binding dimension is ESTABLISHED;
provider facts stay CLAIMED regardless.

Usage: python -m quantum_l8.verify BUNDLE.json TRUST_ROOTS.json [--reexecute]

Limitation: this verifier shares quantum_l8.suites/contracts/canonical with
the code that produced the evidence, so it is not an independent
implementation in the sense of the core layer8_verifier. A second,
standalone implementation is a roadmap item.
"""

from __future__ import annotations

import json
import sys

from quantum_l8 import suites
from quantum_l8.canonical import digest
from quantum_l8.contracts import (
    estimate_cost_micro_usd,
    DELEGATION_DOMAIN,
    REQUEST_DOMAIN,
    chain_digest,
    delegation_well_formed,
    program_digest,
    request_well_formed,
    scope_is_attenuation,
)
from quantum_l8.evidence_log import verify_log
from quantum_l8.executor import RECEIPT_DOMAIN, tvd, tvd_tolerance
from quantum_l8.gate import AUTHORIZATION_DOMAIN, DECISION_DOMAIN, scope_violations

BUNDLE_SCHEMA = "l8x.quantum-execution-bundle.v0"

ESTABLISHED = "ESTABLISHED"
FAILED = "FAILED"
INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
CLAIMED = "CLAIMED"
NOT_CHECKED = "NOT_CHECKED"

# Dimensions that must be ESTABLISHED for the authority/evidence chain.
CHAIN_DIMENSIONS = (
    "gate_policy", "identities", "delegation_chain", "request", "crypto_policy",
    "decision", "authorization", "authorization_scope", "receipt",
    "result_binding", "evidence_log", "log_binding",
)


def export_bundle(world, request_env: dict, program_text: str, gate_out: dict, receipt: dict) -> dict:
    """Checkpoints the log at export time so the exported head is attested."""
    if not world.log.checkpoints or world.log.checkpoints[-1]["body"]["seq"] != len(world.log.entries) - 1:
        world.log.checkpoint(world.now())
    ids = request_env["body"]
    chain = world.gate.delegation_envelopes(gate_out["authorization"]["body"]["delegation_chain"]) \
        if gate_out.get("authorization") else []
    idents = {}
    for env in chain:
        for iid in (env["body"]["issuer_id"], env["body"]["subject_id"]):
            pi = world.identities.get(iid)
            if pi is not None:
                idents[iid] = pi
    idents[ids["agent_id"]] = world.identities.get(ids["agent_id"])
    return {
        "schema_version": BUNDLE_SCHEMA,
        "gate_policy": world.policy,
        "identities": idents,
        "delegations": chain,
        "program": program_text,
        "request": request_env,
        "decision": gate_out["decision"],
        "authorization": gate_out["authorization"],
        "receipt": receipt,
        "evidence_log": world.log.export(),
    }


class _Report:
    def __init__(self):
        self.findings: list[dict] = []

    def add(self, dim: str, status: str, codes: list[str] | str):
        self.findings.append({"dimension": dim, "status": status, "codes": [codes] if isinstance(codes, str) else codes})
        return status == ESTABLISHED

    def status(self, dim):
        for f in self.findings:
            if f["dimension"] == dim:
                return f["status"]
        return None


def verify_bundle(bundle: dict, roots: dict, reexecute: bool = False) -> dict:
    r = _Report()
    try:
        _verify(bundle, roots, reexecute, r)
    except Exception as e:  # malformed input is a named failure, never success
        r.add("bundle", FAILED, f"BUNDLE_MALFORMED:{type(e).__name__}")
    # A revocation visible in the log that predates execution defeats the
    # chain. Its absence proves nothing (completeness is never established).
    established = all(r.status(d) == ESTABLISHED for d in CHAIN_DIMENSIONS) and r.status("revocation") != FAILED
    return {
        "verifier": "l8x.quantum-independent-verifier.v0",
        "chain_established": established,
        "findings": r.findings,
        "what_this_does_not_prove": [
            "that the provider's hardware executed the circuit (provider facts are CLAIMED)",
            "that the result is correct beyond the recorded classical consistency check",
            "that no revocation existed outside this evidence log",
            "the true wall-clock time of any event (no trusted time)",
            "that entries after the newest checkpoint were not truncated (no external anchor)",
            "post-quantum security of any Ed25519-only component",
        ],
    }


def _verify(b: dict, roots: dict, reexecute: bool, r: _Report) -> None:
    if b.get("schema_version") != BUNDLE_SCHEMA:
        r.add("bundle", FAILED, "BUNDLE_SCHEMA_UNSUPPORTED")
        return
    policy = b["gate_policy"]
    r.add("gate_policy", ESTABLISHED if digest(policy) == roots["gate_policy_digest"] else FAILED,
          "GATE_POLICY_PINNED" if digest(policy) == roots["gate_policy_digest"] else "GATE_POLICY_DIGEST_MISMATCH")

    # Identities: every id must derive from its own key material and suite.
    idents = dict(b["identities"])
    bad = [iid for iid, pi in idents.items() if suites.identity_id(pi) != iid]
    for iid, pi in roots["root_principals"].items():
        if idents.get(iid, pi) != pi:
            bad.append(iid)
        idents[iid] = pi
    r.add("identities", FAILED if bad else ESTABLISHED, ["IDENTITY_NOT_BOUND_TO_KEY"] if bad else ["IDS_DERIVE_FROM_KEYS"])

    # Delegation chain: root must be a pinned principal; signatures; linkage; attenuation.
    chain = b["delegations"]
    codes = []
    if not chain:
        codes.append("NO_DELEGATION")
    else:
        if chain[0]["body"]["issuer_id"] not in roots["root_principals"]:
            codes.append("ROOT_PRINCIPAL_NOT_PINNED")
        if chain[0]["body"]["parent_delegation_id"] is not None:
            codes.append("CHAIN_NOT_ROOTED")
        for i, env in enumerate(chain):
            body = env["body"]
            if not delegation_well_formed(env):
                codes.append("DELEGATION_MALFORMED")
                continue
            issuer = idents.get(body["issuer_id"])
            ok, why = suites.verify(issuer, DELEGATION_DOMAIN, body, env["proof"]) if issuer else (False, "ISSUER_UNKNOWN")
            if not ok:
                codes.append(f"DELEGATION_SIGNATURE:{why}")
            if body["issuer_id"] == body["subject_id"]:
                codes.append("SELF_DELEGATION")
            if i > 0:
                parent = chain[i - 1]["body"]
                if body["parent_delegation_id"] != parent["delegation_id"] or body["issuer_id"] != parent["subject_id"]:
                    codes.append("CHAIN_BROKEN")
                if not parent["may_redelegate"] or scope_is_attenuation(body, parent):
                    codes.append("DELEGATION_ESCALATION")
    r.add("delegation_chain", FAILED if codes else ESTABLISHED, codes or ["CHAIN_SIGNED_AND_ATTENUATING"])

    # Request: agent signature, ids, workload and program bytes.
    req_env, program = b["request"], b["program"]
    req = req_env["body"]
    codes = []
    if not request_well_formed(req_env):
        codes.append("REQUEST_MALFORMED")
    agent = idents.get(req["agent_id"])
    ok, why = suites.verify(agent, REQUEST_DOMAIN, req, req_env["proof"]) if agent else (False, "AGENT_UNKNOWN")
    if not ok:
        codes.append(f"REQUEST_SIGNATURE:{why}")
    if chain:
        if req["agent_id"] != chain[-1]["body"]["subject_id"]:
            codes.append("AGENT_NOT_DELEGATE")
        if req["principal_id"] != chain[0]["body"]["issuer_id"]:
            codes.append("PRINCIPAL_MISMATCH")
        if req["delegation_chain_digest"] != chain_digest([e["body"]["delegation_id"] for e in chain]):
            codes.append("CHAIN_DIGEST_MISMATCH")
    if digest(req["workload"]) != req["workload_digest"]:
        codes.append("WORKLOAD_DIGEST_MISMATCH")
    if program_digest(program) != req["workload"]["program_digest"]:
        codes.append("PROGRAM_BYTES_MISMATCH")
    r.add("request", FAILED if codes else ESTABLISHED, codes or ["AGENT_SIGNED_EXACT_WORKLOAD"])

    # Crypto policy: recompute the effective requirement and check every signature.
    effective = suites.combine_levels([policy["crypto_floor"]] + [e["body"]["crypto_policy"] for e in chain])
    auth_env, rec_env, dec_env = b["authorization"], b["receipt"], b["decision"]
    codes = []
    if effective is None:
        codes.append("CRYPTO_POLICY_UNSATISFIABLE")
    else:
        if not suites.level_at_least(req["crypto_policy"], effective):
            codes.append("REQUEST_DECLARED_POLICY_DOWNGRADED")
        if auth_env and auth_env["body"]["crypto_policy"] != effective:
            codes.append("AUTHORIZATION_POLICY_NOT_EFFECTIVE_POLICY")
        signed = [("request", req["signature_suite"])] + [("delegation", e["body"]["signature_suite"]) for e in chain]
        if auth_env:
            signed.append(("authorization", auth_env["body"]["signature_suite"]))
        if rec_env:
            signed.append(("receipt", rec_env["body"]["signature_suite"]))
        for cp in b["evidence_log"]["checkpoints"]:
            signed.append(("checkpoint", cp["body"]["signature_suite"]))
        for name, s in signed:
            if not suites.satisfies(s, effective):
                codes.append(f"{name.upper()}_SUITE_BELOW_POLICY")
    r.add("crypto_policy", FAILED if codes else ESTABLISHED,
          _dedupe(codes) or [f"EVERY_SIGNATURE_SATISFIES:{effective}"])

    # Decision.
    gate = roots["gate"]
    ok, why = suites.verify(gate, DECISION_DOMAIN, dec_env["body"], dec_env["proof"])
    codes = [] if ok else [f"DECISION_SIGNATURE:{why}"]
    if dec_env["body"]["request_digest"] != digest(req_env):
        codes.append("DECISION_REQUEST_DIGEST_MISMATCH")
    if dec_env["body"]["state"] != "AUTHORIZED":
        codes.append(f"DECISION_NOT_AUTHORIZED:{dec_env['body']['state']}")
    if dec_env["body"]["gate_policy_digest"] != roots["gate_policy_digest"]:
        codes.append("DECISION_POLICY_DIGEST_MISMATCH")
    r.add("decision", FAILED if codes else ESTABLISHED, codes or ["GATE_SIGNED_AUTHORIZED"])

    if not auth_env:
        r.add("authorization", FAILED, "NO_AUTHORIZATION")
        return
    a = auth_env["body"]
    ok, why = suites.verify(gate, AUTHORIZATION_DOMAIN, a, auth_env["proof"])
    codes = [] if ok else [f"AUTHORIZATION_SIGNATURE:{why}"]
    expect = {
        "request_digest": digest(req_env), "request_id": req["request_id"], "agent_id": req["agent_id"],
        "principal_id": req["principal_id"], "tenant_id": req["tenant_id"],
        "workload_digest": req["workload_digest"], "program_digest": req["workload"]["program_digest"],
        "shots": req["workload"]["shots"], "backend_id": req["backend"]["backend_id"],
        "backend_class": req["backend"]["backend_class"], "provider": req["backend"]["provider"],
        "result_destination": req["result_destination"], "gate_policy_digest": roots["gate_policy_digest"],
        "delegation_chain": [e["body"]["delegation_id"] for e in chain],
        "authorization_id": digest({k: v for k, v in a.items() if k != "authorization_id"}),
    }
    codes += [f"AUTHORIZATION_{k.upper()}_MISMATCH" for k, v in expect.items() if a.get(k) != v]
    if dec_env["body"]["authorization_id"] != a["authorization_id"]:
        codes.append("DECISION_AUTHORIZATION_ID_MISMATCH")
    r.add("authorization", FAILED if codes else ESTABLISHED, codes or ["GATE_SIGNED_EXACT_REQUEST"])

    # Authorization scope: recompute from the signed chain and pinned policy.
    descriptors = {d["backend_id"]: d for d in policy["backends"]}
    desc = descriptors.get(a["backend_id"])
    codes = []
    if desc is None or digest(desc) != a["backend_descriptor_digest"]:
        codes.append("BACKEND_DESCRIPTOR_NOT_IN_PINNED_POLICY")
    else:
        if desc["backend_class"] != a["backend_class"] or desc["provider"] != a["provider"]:
            codes.append("BACKEND_CLASS_OR_PROVIDER_SUBSTITUTED")
        codes += scope_violations([e["body"] for e in chain], req["workload"], desc, req)
        # Re-derive the gate's non-scope checks too: the gate is not trusted
        # to have applied them.
        if estimate_cost_micro_usd(desc, req["workload"]["shots"]) > req["cost_limit_micro_usd"]:
            codes.append("COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT")
    if req["workload"]["num_qubits"] > req["resource_limits"]["max_qubits"]:
        codes.append("QUBITS_EXCEED_REQUEST_LIMIT")
    if any(e["body"]["tenant_id"] != req["tenant_id"] for e in chain):
        codes.append("TENANT_MISMATCH")
    if a["intended_executor_id"] not in policy["executor_ids"]:
        codes.append("EXECUTOR_NOT_PERMITTED")
    if chain and chain[0]["body"]["issuer_id"] not in policy["root_principal_ids"]:
        codes.append("ROOT_PRINCIPAL_NOT_IN_POLICY")
    if not (a["issued_at_ms"] < req["execution_deadline_ms"]):
        codes.append("ISSUED_AFTER_DEADLINE")
    if req["created_at_ms"] > a["issued_at_ms"] + policy["max_clock_skew_ms"]:
        codes.append("REQUEST_FROM_FUTURE")
    if a["reserved_cost_micro_usd"] != req["cost_limit_micro_usd"]:
        codes.append("RESERVED_COST_MISMATCH")
    if any(not (e["body"]["not_before_ms"] <= a["issued_at_ms"] < e["body"]["expires_at_ms"]) for e in chain):
        codes.append("ISSUED_OUTSIDE_DELEGATION_WINDOW")
    if a["valid_until_ms"] > min([req["execution_deadline_ms"]] + [e["body"]["expires_at_ms"] for e in chain]):
        codes.append("AUTHORIZATION_OUTLIVES_AUTHORITY")
    r.add("authorization_scope", FAILED if codes else ESTABLISHED, codes or ["WITHIN_SIGNED_SCOPE"])

    # Receipt.
    rb = rec_env["body"]
    ex = roots["executors"].get(rb["executor_id"])
    ok, why = suites.verify(ex, RECEIPT_DOMAIN, rb, rec_env["proof"]) if ex else (False, "EXECUTOR_NOT_PINNED")
    codes = [] if ok else [f"RECEIPT_SIGNATURE:{why}"]
    if rb["executor_id"] != a["intended_executor_id"]:
        codes.append("EXECUTOR_NOT_INTENDED")
    for k in ("authorization_id", "request_id", "request_digest", "workload_digest", "program_digest", "backend_id",
              "backend_descriptor_digest", "backend_class", "provider", "principal_id", "agent_id", "tenant_id",
              "delegation_chain", "result_destination", "crypto_policy"):
        if rb[k] != a[k]:
            codes.append(f"RECEIPT_{k.upper()}_MISMATCH")
    if rb["authorization_digest"] != digest(auth_env):
        codes.append("RECEIPT_AUTHORIZATION_DIGEST_MISMATCH")
    if rb["receipt_id"] != digest({k: v for k, v in rb.items() if k != "receipt_id"}):
        codes.append("RECEIPT_ID_MISMATCH")
    if rb["parameters"] != req["workload"]["parameters"]:
        codes.append("RECEIPT_PARAMETERS_MISMATCH")
    if not (a["issued_at_ms"] <= rb["execution"]["submitted_at_ms"] < a["valid_until_ms"]):
        codes.append("SUBMITTED_OUTSIDE_AUTHORIZATION_WINDOW")
    if rb["outcome"] != "SUCCEEDED":
        codes.append(f"OUTCOME_{rb['outcome']}")
    r.add("receipt", FAILED if codes else ESTABLISHED, codes or ["EXECUTOR_SIGNED_BINDS_AUTHORIZATION"])

    codes = []
    if rb["result_digest"] != digest(rb["result"]):
        codes.append("RESULT_DIGEST_MISMATCH")
    if rb["provider_metadata_digest"] != digest(rb["provider_metadata"]):
        codes.append("PROVIDER_METADATA_DIGEST_MISMATCH")
    if rb["result"] and sum(rb["result"]["counts"].values()) != a["shots"]:
        codes.append("RESULT_SHOTS_MISMATCH")
    r.add("result_binding", FAILED if codes else ESTABLISHED, codes or ["RESULT_BOUND_TO_RECEIPT"])

    # Provider facts: recorded, attributed, never verified.
    ex_info = rb["execution"]
    if desc is not None and ex_info["provider_reported_backend"] not in desc["provider_backend_names"]:
        r.add("provider_execution", FAILED, "PROVIDER_REPORTED_BACKEND_NOT_AUTHORIZED")
    else:
        r.add("provider_execution", CLAIMED,
              [f"PROVIDER_REPORTED_BACKEND:{ex_info['provider_reported_backend']}",
               f"PROVIDER_JOB_ID:{ex_info['provider_job_id']}", f"BACKEND_CLASS_REGISTERED:{a['backend_class']}"])

    # Classical consistency: recompute if possible, else it is the executor's claim.
    cv = rb["classical_verification"]
    if cv["verdict"] == "NOT_CHECKED":
        r.add("classical_consistency", NOT_CHECKED, "NO_CLASSICAL_CHECK_RECORDED")
    elif reexecute:
        from quantum_l8.adapters.qiskit_adapter import ideal_probabilities
        ideal = ideal_probabilities(program, req["workload"])
        if ideal is None:
            r.add("classical_consistency", INSUFFICIENT, "IDEAL_NOT_COMPUTABLE")
        else:
            d, tol = tvd(rb["result"]["counts"], ideal), tvd_tolerance(ideal, a["shots"])
            same = format(d, ".6f") == cv["tvd"]
            r.add("classical_consistency", ESTABLISHED if (d <= tol and same) else FAILED,
                  [f"TVD:{d:.6f}", f"TOL:{tol:.6f}"] + ([] if same else ["RECORDED_TVD_DIFFERS"]))
    else:
        r.add("classical_consistency", CLAIMED, [f"EXECUTOR_REPORTED:{cv['verdict']}"])

    if reexecute and ex_info.get("reproducibility"):
        from quantum_l8.adapters.qiskit_adapter import reexecute as rerun
        counts = rerun(rb["adapter"]["adapter_id"], program, req["workload"], ex_info["reproducibility"])
        if counts is None:
            r.add("reexecution", INSUFFICIENT, "NOT_REPRODUCIBLE_HERE")
        else:
            r.add("reexecution", ESTABLISHED if counts == rb["result"]["counts"] else FAILED,
                  "REPRODUCED_BIT_FOR_BIT" if counts == rb["result"]["counts"] else "REEXECUTION_DIFFERS")
    else:
        r.add("reexecution", NOT_CHECKED, "NOT_REQUESTED_OR_NOT_REPRODUCIBLE")

    # Evidence log integrity and binding.
    log = b["evidence_log"]
    ok, codes = verify_log(log, roots["log_signers"])
    r.add("evidence_log", ESTABLISHED if ok and "LOG_TAIL_NOT_CHECKPOINTED" not in codes else FAILED, codes)
    r.add("log_binding", *_log_binding(log, dec_env, auth_env, rec_env, chain))

    # Revocation: only what this log shows.
    targets = {e["body"]["delegation_id"] for e in chain} | {e["body"]["issuer_id"] for e in chain} | {req["agent_id"]}
    revs = [e for e in log["entries"] if e["kind"] == "REVOCATION_RECORDED" and e["body"]["target_id"] in targets
            and e["body"]["effective_at_ms"] <= ex_info["submitted_at_ms"]]
    if revs:
        r.add("revocation", FAILED, "REVOCATION_EFFECTIVE_BEFORE_EXECUTION")
    else:
        r.add("revocation", INSUFFICIENT, "NO_REVOCATION_IN_THIS_LOG_COMPLETENESS_UNPROVEN")


def _log_binding(log, dec_env, auth_env, rec_env, chain):
    want = [
        ("GATE_DECISION", "decision_digest", digest(dec_env)),
        ("AUTHORIZATION_ISSUED", "authorization_digest", digest(auth_env)),
        ("AUTHORIZATION_CONSUMED", "authorization_id", auth_env["body"]["authorization_id"]),
        ("EXECUTION_RECEIPT", "receipt_digest", digest(rec_env)),
    ]
    seqs, codes = [], []
    for kind, field, value in want:
        hits = [e["seq"] for e in log["entries"] if e["kind"] == kind and e["body"].get(field) == value]
        if len(hits) != 1:
            codes.append(f"LOG_{kind}_{'MISSING' if not hits else 'DUPLICATED'}")
        else:
            seqs.append(hits[0])
    for env in chain:
        if not any(e["kind"] == "DELEGATION_REGISTERED" and e["body"].get("delegation_digest") == digest(env)
                   for e in log["entries"]):
            codes.append("LOG_DELEGATION_MISSING")
    if not codes and seqs != sorted(seqs):
        codes.append("LOG_LIFECYCLE_OUT_OF_ORDER")
    if not codes and seqs[-1] > log["checkpoints"][-1]["body"]["seq"]:
        codes.append("RECEIPT_NOT_CHECKPOINTED")
    return (FAILED if codes else ESTABLISHED), (codes or ["DECISION<AUTHORIZATION<CONSUMPTION<RECEIPT_IN_CHECKPOINTED_LOG"])


def _dedupe(xs):
    return list(dict.fromkeys(xs))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    with open(argv[0]) as f:
        bundle = json.load(f)
    with open(argv[1]) as f:
        roots = json.load(f)
    report = verify_bundle(bundle, roots, reexecute="--reexecute" in argv)
    print(json.dumps(report, indent=2))
    return 0 if report["chain_established"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
