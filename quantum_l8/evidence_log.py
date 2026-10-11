"""Append-only, hash-chained evidence log with signed checkpoints (EXPERIMENTAL).

Entry:       {seq, prev_hash, kind, body, entry_hash}
entry_hash = sha256(canonical({seq, prev_hash, kind, body}))

A checkpoint is a signed statement "the log ``log_id`` had ``seq + 1`` entries
with head ``head_hash``". Holding a checkpoint lets a verifier detect deletion,
reordering, insertion and rewriting of any entry at or before ``seq``.

What it does NOT detect without an external anchor: removal of entries after
the newest checkpoint the verifier holds (tail truncation), or a whole log
rebuilt and re-signed by someone holding (or forging) the signing key. Time in
a checkpoint is the signer's own clock.

Re-attestation: ``reattest`` appends a REATTESTATION entry citing the previous
checkpoint and signs a new checkpoint with a (newer-suite) key. History is not
rewritten; the old signatures keep exactly the meaning they had. The new
checkpoint is a new, separately attributed statement.
"""

from __future__ import annotations

from quantum_l8 import suites
from quantum_l8.canonical import digest

CHECKPOINT_DOMAIN = "L8X_EVIDENCE_LOG_CHECKPOINT_V0"
CHECKPOINT_SCHEMA = "l8x.evidence-log-checkpoint.v0"
GENESIS = "0" * 64


def entry_hash(entry: dict) -> str:
    return digest({k: entry[k] for k in ("seq", "prev_hash", "kind", "body")})


class EvidenceLog:
    def __init__(self, log_id: str, signer: suites.KeyBundle):
        self.log_id = log_id
        self.signer = signer
        self.entries: list[dict] = []
        self.checkpoints: list[dict] = []

    @property
    def head(self) -> str:
        return self.entries[-1]["entry_hash"] if self.entries else GENESIS

    def append(self, kind: str, body: dict) -> dict:
        entry = {"seq": len(self.entries), "prev_hash": self.head, "kind": kind, "body": body}
        entry["entry_hash"] = entry_hash(entry)
        self.entries.append(entry)
        return entry

    def checkpoint(self, now_ms: int, signer: suites.KeyBundle | None = None) -> dict:
        signer = signer or self.signer
        body = {
            "schema_version": CHECKPOINT_SCHEMA,
            "log_id": self.log_id,
            "seq": len(self.entries) - 1,
            "head_hash": self.head,
            "prev_checkpoint_digest": digest(self.checkpoints[-1]) if self.checkpoints else None,
            "created_at_ms": now_ms,
            "signer_id": signer.identity_id(),
            "signature_suite": signer.suite,
        }
        cp = {"body": body, "proof": signer.sign(CHECKPOINT_DOMAIN, body)}
        self.checkpoints.append(cp)
        return cp

    def reattest(self, new_signer: suites.KeyBundle, now_ms: int) -> dict:
        """Countersign the current history under a newer suite."""
        prior = self.checkpoints[-1] if self.checkpoints else None
        self.append("REATTESTATION", {
            "prior_checkpoint_digest": digest(prior) if prior else None,
            "prior_head_hash": prior["body"]["head_hash"] if prior else None,
            "prior_signature_suite": prior["body"]["signature_suite"] if prior else None,
            "new_signer_id": new_signer.identity_id(),
            "new_signature_suite": new_signer.suite,
        })
        return self.checkpoint(now_ms, signer=new_signer)

    def export(self) -> dict:
        return {"log_id": self.log_id, "entries": list(self.entries), "checkpoints": list(self.checkpoints)}


def verify_log(exported: dict, signers: dict[str, dict]) -> tuple[bool, list[str]]:
    """Verify chain integrity and every checkpoint against pinned signer
    identities (identity_id -> public identity). Returns (ok, codes)."""
    codes: list[str] = []
    entries = exported.get("entries", [])
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            codes.append(f"LOG_SEQ_GAP_OR_REORDER@{i}")
            return False, codes
        if e.get("prev_hash") != prev:
            codes.append(f"LOG_CHAIN_BROKEN@{i}")
            return False, codes
        if entry_hash(e) != e.get("entry_hash"):
            codes.append(f"LOG_ENTRY_REWRITTEN@{i}")
            return False, codes
        prev = e["entry_hash"]
    cps = exported.get("checkpoints", [])
    if not cps:
        codes.append("LOG_NO_CHECKPOINT")
        return False, codes
    prev_cp = None
    for cp in cps:
        b = cp.get("body", {})
        ident = signers.get(b.get("signer_id"))
        if ident is None:
            codes.append("CHECKPOINT_SIGNER_NOT_PINNED")
            return False, codes
        ok, why = suites.verify(ident, CHECKPOINT_DOMAIN, b, cp.get("proof"))
        if not ok:
            codes.append(f"CHECKPOINT_SIGNATURE_INVALID:{why}")
            return False, codes
        if b.get("log_id") != exported.get("log_id"):
            codes.append("CHECKPOINT_LOG_ID_MISMATCH")
            return False, codes
        if b.get("prev_checkpoint_digest") != (digest(prev_cp) if prev_cp else None):
            codes.append("CHECKPOINT_CHAIN_BROKEN")
            return False, codes
        seq = b.get("seq")
        if not isinstance(seq, int) or seq >= len(entries):
            codes.append("LOG_TRUNCATED_BEFORE_CHECKPOINT")
            return False, codes
        if seq >= 0 and entries[seq]["entry_hash"] != b.get("head_hash"):
            codes.append("CHECKPOINT_HEAD_MISMATCH")
            return False, codes
        prev_cp = cp
    last = cps[-1]["body"]["seq"]
    if last < len(entries) - 1:
        codes.append("LOG_TAIL_NOT_CHECKPOINTED")
    return True, codes or ["LOG_CONSISTENT"]
