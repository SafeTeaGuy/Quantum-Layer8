"""Local Ed25519 execution receipt for the Quantum-Layer8 prototype.

The executor signs a domain-separated canonical payload that binds:
- policy decision hash
- canonical request hash
- canonical result hash
- unique execution nonce/id
- execution timestamp
- executor public-key identity

Signed message:
    b"quantum-layer8-proto-v1:execution-receipt:" + canonical_payload_bytes

This is software-key attestation in a local prototype only.
"""

import hashlib
import json
import base64
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from src.delegation import public_key_to_b64, public_key_from_b64

EXECUTION_DOMAIN = b"quantum-layer8-proto-v1:execution-receipt:"


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_hash(request: dict) -> str:
    return hashlib.sha256(_canonical(request)).hexdigest()


def result_hash(result: dict) -> str:
    return hashlib.sha256(_canonical(result)).hexdigest()


def build_receipt_payload(
    decision_hash: str,
    request_hash: str,
    result_hash: str,
    execution_id: str,
    executed_at: str,
    executor_public_key_b64: str,
) -> dict:
    return {
        "decision_hash": decision_hash,
        "request_hash": request_hash,
        "result_hash": result_hash,
        "execution_id": execution_id,
        "executed_at": executed_at,
        "executor_public_key": executor_public_key_b64,
    }


def sign_execution_receipt(
    private_key: Ed25519PrivateKey,
    payload: dict,
) -> str:
    """Sign the domain-separated canonical payload. Returns base64 signature."""
    message = EXECUTION_DOMAIN + _canonical(payload)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_execution_receipt(
    public_key: Ed25519PublicKey,
    payload: dict,
    signature_b64: str,
) -> bool:
    """Fail-closed verification of the execution receipt signature."""
    try:
        message = EXECUTION_DOMAIN + _canonical(payload)
        signature = base64.b64decode(signature_b64)
        if len(signature) != 64:
            return False
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def create_signed_receipt(
    private_key: Ed25519PrivateKey,
    decision_hash: str,
    request: dict,
    result: dict,
    execution_id: str,
    executed_at: str | None = None,
) -> dict:
    """Convenience: build payload, sign, return receipt object."""
    pub_b64 = public_key_to_b64(private_key.public_key())
    executed_at = executed_at or datetime.now(timezone.utc).isoformat()
    payload = build_receipt_payload(
        decision_hash=decision_hash,
        request_hash=request_hash(request),
        result_hash=result_hash(result),
        execution_id=execution_id,
        executed_at=executed_at,
        executor_public_key_b64=pub_b64,
    )
    sig = sign_execution_receipt(private_key, payload)
    return {
        "payload": payload,
        "signature": sig,
    }
