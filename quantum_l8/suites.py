"""Signature suites, hybrid proofs and crypto-policy requirements (EXPERIMENTAL).

This module tests the crypto-agility design in the core Layer8 quantum
readiness audit (suite bound to the key, suite inside the signed bytes,
AND-composed hybrid proofs, no fallback). It does not decide which PQ
standard Layer8 adopts. That is an open owner decision, so the PQ and hybrid
suite ids live in an experimental namespace (``l8x.``) and are not the
reserved core names.

Rules enforced here:

* The suite is taken from the pinned public identity, never from the artifact.
* The signed body must carry ``signature_suite`` equal to the key's suite, so
  a component lifted out of a hybrid proof is not a valid standalone proof.
* A hybrid proof is valid only if every component verifies (AND), in the
  fixed order of the suite definition, with exact lengths. There is no
  "try PQ, else classical" path.
* ML-DSA signs with the message domain as its FIPS 204 context string.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from quantum_l8.canonical import digest, domain_separated

try:  # ML-DSA needs cryptography >= 47 built against an OpenSSL that has it.
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _MLDSA_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _mldsa = None
    _MLDSA_AVAILABLE = False

ED25519 = "ed25519"
MLDSA65 = "ml-dsa-65"

_ALG_SIZES = {
    ED25519: {"public_key": 32, "signature": 64},
    MLDSA65: {"public_key": 1952, "signature": 3309},
}

SUITE_ED25519 = "l8.sig.ed25519.v1"
SUITE_MLDSA65 = "l8x.sig.ml-dsa-65.exp0"
SUITE_HYBRID = "l8x.sig.hybrid-ed25519-ml-dsa-65.exp0"

# Closed table. Component order is part of the suite definition.
SUITES: dict[str, tuple[str, ...]] = {
    SUITE_ED25519: (ED25519,),
    SUITE_MLDSA65: (MLDSA65,),
    SUITE_HYBRID: (ED25519, MLDSA65),
}

# Crypto-policy requirement levels: the set of component algorithms every
# signature must contain. A suite satisfies a level iff its components are a
# superset. Hybrid therefore satisfies all three; PQ-only does not satisfy
# REQUIRE_ED25519.
REQUIRE_ED25519 = "REQUIRE_ED25519"
REQUIRE_HYBRID = "REQUIRE_HYBRID_ED25519_ML_DSA_65"
REQUIRE_PQ = "REQUIRE_ML_DSA_65"

LEVELS: dict[str, frozenset[str]] = {
    REQUIRE_ED25519: frozenset({ED25519}),
    REQUIRE_HYBRID: frozenset({ED25519, MLDSA65}),
    REQUIRE_PQ: frozenset({MLDSA65}),
}

IDENTITY_DOMAIN = "L8X_IDENTITY_ID_V0"

# Verification reason codes.
OK = "OK"
SUITE_UNSUPPORTED = "SIGNATURE_SUITE_UNSUPPORTED"
SUITE_MISMATCH = "SIGNATURE_SUITE_MISMATCH"
MALFORMED_PROOF = "SIGNATURE_PROOF_MALFORMED"
SIGNATURE_INVALID = "SIGNATURE_INVALID"
MALFORMED_KEY = "PUBLIC_KEY_MALFORMED"


def mldsa_available() -> bool:
    return _MLDSA_AVAILABLE


def suite_supported(suite_id: str) -> bool:
    comps = SUITES.get(suite_id)
    if comps is None:
        return False
    return all(c != MLDSA65 or _MLDSA_AVAILABLE for c in comps)


def satisfies(suite_id: str, level: str) -> bool:
    comps = SUITES.get(suite_id)
    req = LEVELS.get(level)
    if comps is None or req is None:
        return False
    return req.issubset(comps)


def combine_levels(levels: list[str]) -> str | None:
    """Union of requirements. Returns None for an unknown level or a union
    with no named level (fail closed)."""
    acc: set[str] = set()
    for lv in levels:
        req = LEVELS.get(lv)
        if req is None:
            return None
        acc |= req
    for name, comps in LEVELS.items():
        if comps == acc:
            return name
    return None


def level_at_least(declared: str, required: str) -> bool:
    """True iff the declared level demands everything the required one does."""
    d, r = LEVELS.get(declared), LEVELS.get(required)
    return d is not None and r is not None and r.issubset(d)


def _raw_pub(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class KeyBundle:
    """Private keys for one identity under one suite. Software keys only."""

    suite: str
    keys: dict

    @classmethod
    def generate(cls, suite: str) -> "KeyBundle":
        if not suite_supported(suite):
            raise ValueError(f"suite unsupported: {suite}")
        keys = {}
        for comp in SUITES[suite]:
            if comp == ED25519:
                keys[comp] = Ed25519PrivateKey.generate()
            elif comp == MLDSA65:
                keys[comp] = _mldsa.MLDSA65PrivateKey.generate()
        return cls(suite=suite, keys=keys)

    def public_identity(self) -> dict:
        return {
            "suite": self.suite,
            "public_keys": {c: _raw_pub(self.keys[c].public_key()).hex() for c in SUITES[self.suite]},
        }

    def identity_id(self) -> str:
        return identity_id(self.public_identity())

    def sign(self, domain: str, body: dict) -> dict:
        if body.get("signature_suite") != self.suite:
            raise ValueError("body.signature_suite must equal the signing suite")
        msg = domain_separated(domain, body)
        sigs = []
        for comp in SUITES[self.suite]:
            k = self.keys[comp]
            if comp == ED25519:
                sig = k.sign(msg)
            else:
                sig = k.sign(msg, domain.encode("ascii"))
            sigs.append({"alg": comp, "sig": sig.hex()})
        return {"suite": self.suite, "signatures": sigs}


def identity_id(public_identity: dict) -> str:
    """Full SHA-256, suite in the preimage, disjoint domain from core v1 ids."""
    return digest({"domain": IDENTITY_DOMAIN, "identity": public_identity})


def _strict_hex(v, nbytes: int) -> bytes | None:
    if not isinstance(v, str) or len(v) != 2 * nbytes:
        return None
    if any(c not in "0123456789abcdef" for c in v):
        return None
    return bytes.fromhex(v)


def _load_pub(alg: str, raw: bytes):
    if alg == ED25519:
        return Ed25519PublicKey.from_public_bytes(raw)
    if alg == MLDSA65 and _MLDSA_AVAILABLE:
        return _mldsa.MLDSA65PublicKey.from_public_bytes(raw)
    raise ValueError("unsupported algorithm")


def verify(public_identity: dict, domain: str, body: dict, proof: dict) -> tuple[bool, str]:
    """Total, fail-closed verification. Never raises."""
    try:
        suite = public_identity.get("suite") if isinstance(public_identity, dict) else None
        if not isinstance(suite, str) or not suite_supported(suite):
            return False, SUITE_UNSUPPORTED
        comps = SUITES[suite]
        pks = public_identity.get("public_keys")
        if not isinstance(pks, dict) or set(pks) != set(comps):
            return False, MALFORMED_KEY
        if not isinstance(body, dict) or body.get("signature_suite") != suite:
            return False, SUITE_MISMATCH
        if not isinstance(proof, dict) or set(proof) != {"suite", "signatures"}:
            return False, MALFORMED_PROOF
        if proof["suite"] != suite:
            return False, SUITE_MISMATCH
        sigs = proof["signatures"]
        if not isinstance(sigs, list) or len(sigs) != len(comps):
            return False, MALFORMED_PROOF
        msg = domain_separated(domain, body)
        for comp, entry in zip(comps, sigs):
            if not isinstance(entry, dict) or set(entry) != {"alg", "sig"} or entry["alg"] != comp:
                return False, MALFORMED_PROOF
            raw_pk = _strict_hex(pks[comp], _ALG_SIZES[comp]["public_key"])
            if raw_pk is None:
                return False, MALFORMED_KEY
            raw_sig = _strict_hex(entry["sig"], _ALG_SIZES[comp]["signature"])
            if raw_sig is None:
                return False, MALFORMED_PROOF
            pub = _load_pub(comp, raw_pk)
            try:
                if comp == ED25519:
                    pub.verify(raw_sig, msg)
                else:
                    pub.verify(raw_sig, msg, domain.encode("ascii"))
            except Exception:
                return False, SIGNATURE_INVALID
        return True, OK
    except Exception:
        return False, MALFORMED_PROOF
