# Threat model: governed quantum execution

> **Experimental.** This covers the prototype in `quantum_l8/`. Every row of
> the attack matrix is a test in `tests/quantum/`. Rows marked **CANNOT
> PROVE** are pinned by `test_limit_*` tests, which assert that the attack is
> *not* detected. A future change that claims to detect one must change that
> test and this document together.

## 1. Assets

| Asset | What is protected |
|---|---|
| Authority | delegations, gate policy, authorizations, revocations |
| Budgets | per-delegation execution counts and reserved cost |
| Workload integrity | exact program bytes, parameters, shots and qubits |
| Backend selection | the descriptor (class, provider, adapter) the authority permitted |
| Evidence | decisions, receipts, the evidence log and checkpoints |
| Results | delivery only to the authorized destination; integrity after the receipt |

## 2. Actors and trust assumptions

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Root principal | issuing delegations within the operator's root list | anything beyond its signed scope |
| Agent (AI or scripted) | holding its own key | its scope, crypto level, backend choice, cost, destination |
| Router / optimizer | ranking permitted options | authority; its output is advice, re-checked by the gate |
| Gate (Layer8) | applying policy correctly; holding the authorization and log keys | being honest about policy: the verifier recomputes the effective crypto policy and scope itself |
| Executor (Layer8 node) | invoking the adapter once and reporting what it observed | provider facts |
| Adapter / provider | nothing it says is authority | backend identity, hardware execution, result correctness: all `CLAIMED` |
| Independent verifier | holding trust roots pinned out of band | |
| Storage | nothing | integrity is checked from hashes and signatures |

Out of scope: production key custody, side channels, network transport,
denial of service, trusted time, and an external anchor. These are the same
gaps core Layer8 has.

## 3. Attack matrix

"Gate" means `QuantumTrustGate.decide`. "Exec" means `Executor.run` or the
gate's consume step. "Verifier" means `verify_bundle`.

| # | Attack | Detected by | Result / reason code | Test |
|---|---|---|---|---|
| 1 | Signature downgrade: classical-only signature for a hybrid identity | Gate, Verifier | `AGENT_SIGNATURE_INVALID` + `SIGNATURE_SUITE_MISMATCH` | `test_forged_classical_signature_for_hybrid_agent_refused`, `test_signature_downgrade_in_bundle` |
| 1b | Strip the PQ component; lift the Ed25519 component out of a hybrid proof | Suites | `SIGNATURE_PROOF_MALFORMED`, `SIGNATURE_INVALID` | `test_d2_*` |
| 2 | Crypto-policy downgrade by the agent | Gate | `CRYPTO_POLICY_DOWNGRADE` | `test_d9_request_cannot_lower_policy` |
| 2b | Crypto-policy downgrade by a key-holding (malicious) gate | Verifier | `AUTHORIZATION_POLICY_NOT_EFFECTIVE_POLICY` (the verifier recomputes the floor from the pinned policy and the signed chain) | `test_policy_downgrade_by_gate_detected_by_verifier` |
| 2c | Operator floor above a classical delegation | Gate | `*_SUITE_BELOW_POLICY` | `test_operator_floor_applies_even_if_delegation_is_classical` |
| 3 | Backend substitution in the request | Gate | `BACKEND_CLASS_MISMATCH`, `PROVIDER_MISMATCH`, `BACKEND_NOT_AUTHORIZED` | `test_backend_substitution_at_request`, `test_backend_unknown_and_provider_mismatch` |
| 3b | Backend substitution in the receipt, even re-signed with the real executor key | Verifier | `RECEIPT_BACKEND_ID_MISMATCH` (the authorization is gate-signed) | `test_backend_substitution_in_receipt` |
| 4 | Fake QPU identity: provider reports an unregistered backend name | Exec | outcome `PROVIDER_MISMATCH`, result not delivered | `test_fake_qpu_identity_detected_when_name_differs` |
| 4b | **Consistent provider lie**: classical computation reported under the expected backend name | — | **CANNOT PROVE.** `chain_established = True`, provider execution stays `CLAIMED` | `test_limit_consistent_provider_lie_is_not_detectable` |
| 5 | Replayed job: same request, or a new signature reusing the `request_id` | Gate | `REQUEST_REPLAYED`, `NONCE_REPLAYED` | `test_replay_same_request`, `test_replayed_job_with_fresh_signature_refused`, `test_reused_nonce_new_request_id` |
| 5b | Replayed authorization | Exec | `AUTHORIZATION_ALREADY_CONSUMED` | `test_authorization_single_use` |
| 6 | Modified circuit after authorization | Exec, Gate, Verifier | `WORKLOAD_MISMATCH`, `PROGRAM_DIGEST_MISMATCH`, `PROGRAM_BYTES_MISMATCH` | `test_modified_circuit_*` |
| 6b | Program disagrees with the declared qubit count | Exec (preflight, before consumption) | `PREFLIGHT_REFUSED:DECLARED_QUBITS_MISMATCH`; authorization not spent | `test_preflight_refuses_before_consumption` |
| 7 | Modified parameters or shots | Gate, Verifier | signature failures | `test_modified_parameters_or_shots` |
| 8 | Forged result | Verifier | `RECEIPT_SIGNATURE` | `test_forged_result` |
| 8b | Forged result by an **executor-key holder** | Verifier, partly | Log binding fails if the log key is separate. Re-execution and the classical check catch it **only for reproducible or classically simulable runs**. On real hardware with both keys compromised: **CANNOT PROVE** | `test_limit_executor_key_holder_can_forge_result` |
| 9 | Receipt substitution: the receipt of another execution | Verifier | `RECEIPT_AUTHORIZATION_ID_MISMATCH` … | `test_receipt_substitution` |
| 10 | Cross-domain delegation (another Layer8 domain's principal) | Gate | `ROOT_PRINCIPAL_NOT_PERMITTED` | `test_cross_domain_delegation` |
| 10b | Cross-tenant execution | Gate | `TENANT_MISMATCH`, `BACKEND_TENANT_NOT_PERMITTED` | `test_cross_tenant` |
| 11 | Revoked authority: before the decision, between authorization and execution, scheduled; delegation, agent, issuer or root principal | Gate, Exec; Verifier if the revocation is in the log | `REVOKED_DELEGATION`, `REVOKED_AGENT`, `REVOKED_ISSUER`; verifier `REVOCATION_EFFECTIVE_BEFORE_EXECUTION` blocks `chain_established` | `test_revocation_*`, `test_scheduled_revocation_takes_effect_later`, `test_root_principal_identity_revoked_by_operator` |
| 11b | Revocation by an unauthorized party | Gate | `REVOCATION_UNAUTHORIZED_REVOKER` | `test_agent_revocation_by_operator_only` |
| 11c | Revocation that exists but is **not in the evidence log** | Verifier | **CANNOT PROVE** completeness. `revocation` is always `INSUFFICIENT_EVIDENCE` | `test_end_to_end_chain_verifies_with_reexecution` |
| 12 | Expired authority: delegation, deadline, authorization window | Gate, Exec, Verifier | `DELEGATION_EXPIRED`, `EXECUTION_DEADLINE_PASSED`, `AUTHORIZATION_EXPIRED`, `SUBMITTED_OUTSIDE_AUTHORIZATION_WINDOW` | `test_expired_*`, `test_authorization_expires`, `test_expired_authorization_window_in_bundle` |
| 13 | Key substitution: agent key swapped in the bundle; executor re-signs with its own key | Verifier | `IDENTITY_NOT_BOUND_TO_KEY`, `EXECUTOR_NOT_PINNED` | `test_agent_key_substitution`, `test_executor_key_substitution` |
| 14 | Evidence deletion inside the checkpointed range | Verifier | `LOG_SEQ_GAP_OR_REORDER` | `test_evidence_deletion` |
| 14b | Evidence rewrite with every hash recomputed | Verifier | `CHECKPOINT_HEAD_MISMATCH` | `test_evidence_rewrite_with_recomputed_hashes` |
| 14c | **Tail truncation** after the newest checkpoint the verifier holds | — | **CANNOT PROVE** without an external anchor | `test_limit_tail_truncation_after_last_checkpoint_undetected` |
| 15 | Evidence reordering | Verifier | chain broken | `test_evidence_reordering` |
| 16 | Classical result presented as quantum (CPU run relabelled) | Verifier | `RECEIPT_SIGNATURE`; after re-signing, `RECEIPT_BACKEND_CLASS_MISMATCH` | `test_classical_run_relabelled_as_quantum` |
| 17 | Quantum result presented as coming from another backend | Verifier | `RECEIPT_SIGNATURE` | `test_result_moved_to_other_backends_receipt` |
| 18 | Delegation escalation through re-delegation | Gate | `REDELEGATION_NOT_PERMITTED`, `DELEGATION_ESCALATION` | `test_agent_cannot_escalate_by_redelegating` |
| 19 | Cost-limit bypass: low declared limit, over-budget, many small jobs | Gate | `COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT`, `COST_LIMIT_EXCEEDS_DELEGATION`, `COST_BUDGET_EXHAUSTED`, `EXECUTION_COUNT_EXHAUSTED` | `test_cost_limits`, `test_max_executions` |
| 19b | **Provider bills more than the estimate** | Exec | Recorded as `REPORTED_COST_EXCEEDS_RESERVATION`. **Cannot prevent** the charge after submission | (receipt field `cost.overrun`) |
| 20 | Stolen signed request | Gate | Another tenant gets `TENANT_MISMATCH`. Same tenant: the thief cannot change the destination, but **can pre-empt** the victim (availability, not authority) | `test_stolen_request_gives_thief_nothing` |
| 21 | Result exfiltration to another destination | Gate, Exec | `RESULT_DESTINATION_NOT_AUTHORIZED`; delivery only to the authorized sink | `test_result_destination`, `test_result_goes_only_to_authorized_destination` |
| 22 | Compromised router chooses an unpermitted backend | Router, Gate | `ROUTE_NOT_PERMITTED`; the gate refuses independently | `test_compromised_optimizer_cannot_route_outside_authority` |
| 23 | Malformed or non-canonical input (float, unknown field, unknown schema, unhashable value, un-encodable program text) | Gate, Exec, Verifier | `REQUEST_MALFORMED`, `REQUEST_SCHEMA_UNSUPPORTED`, `PROGRAM_MALFORMED`, `AUTHORIZATION_OR_REQUEST_MALFORMED`, `BUNDLE_MALFORMED` | `test_schema_malformed_missing_inputs`, `test_unhashable_crypto_policy_is_malformed`, `test_unencodable_program_text`, `test_malformed_bundle_is_a_named_failure` |
| 24 | Malformed revocation (missing or non-integer effective time, bad target) reported as recorded but not enforced | Gate | `REVOCATION_MALFORMED` | `test_revocation_effective_time_must_be_an_int` |
| 25 | Malformed provider output after consumption (float metadata, missing counts) | Exec | signed receipt with outcome `UNKNOWN`, `PROVIDER_OUTPUT_MALFORMED:*`, no delivery | `test_malformed_provider_output_yields_unknown_receipt` |
| 26 | Key-holding gate skips tenant, qubit-limit or cost-estimate checks | Verifier | `TENANT_MISMATCH`, `QUBITS_EXCEED_REQUEST_LIMIT`, `COST_ESTIMATE_EXCEEDS_REQUEST_LIMIT` in `authorization_scope` | `test_verifier_rederives_*` |

## 4. What Layer8 can prove, and what it cannot

**Can establish** (given pinned trust roots and uncompromised keys):

- Which root principal delegated which scope to which agent, through which
  chain, and that every link only narrowed authority.
- That the agent signed this exact request: program bytes, parameters,
  shots, backend, cost limit, destination and crypto level.
- That the gate authorized exactly that request under exactly that policy
  digest, with the crypto level recomputed from the signed inputs.
- That the executor named in the authorization signed a receipt binding the
  authorization, the backend descriptor, the provider's reported facts and
  the returned result.
- That none of those objects, nor any checkpointed log entry, was altered,
  reordered, deleted or substituted afterwards.
- For seeded simulators: that the result reproduces bit for bit.
- For circuits up to 16 qubits: whether the result is statistically
  consistent with the ideal distribution.

**Cannot establish:**

- That quantum hardware executed anything, or which physical device did.
  Provider facts are `CLAIMED`.
- That a result is *correct* for circuits that cannot be simulated
  classically. And a circuit that *can* be simulated classically gains
  nothing from a QPU (PROOF_OF_COMPUTE.md §4).
- That no revocation existed outside the log.
- When anything happened. All times are the signers' own clocks.
- Completeness of the log tail beyond the verifier's newest checkpoint.
- Anything at all after a compromise of the key that signed it. For
  Ed25519-only components, that includes a future CRQC.

## 5. Residual risks to track

- **Cross-execution budgets are not verifiable from one bundle.** A
  key-holding gate that authorizes more executions or more total cost than a
  delegation allows, spread across several jobs, is not detected by
  verifying any single bundle. Detecting it needs per-authorization
  delegation and cost records in the log, plus a verifier pass over the
  whole log.
- **`resource_limits.max_runtime_ms` is carried and signed but not
  enforced.** No adapter implements a timeout.
- Rows 23–26 come from an adversarial review of this prototype. Each was
  reproduced before it was fixed, and each regression test was confirmed to
  fail on the pre-fix code (`tests/quantum/test_review_regressions.py`).

- The verifier shares code with the producer (`suites`, `contracts`). A
  shared bug would be invisible to it. Mitigation: a standalone second
  implementation and conformance vectors (ROADMAP).
- The gate, executor and log are one process in the prototype. The log is
  signed with the gate key, so a gate-key compromise also compromises the
  log.
- Identity registration has no proof of possession in the prototype, as in
  core.
- Budgets are reserved at authorization and never released. A failed job
  still consumes budget, which is deliberate and matches core.
