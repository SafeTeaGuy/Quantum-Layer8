"""Local Ed25519 delegation proof helper for the Quantum-Layer8 prototype.

This is an explicit local helper for this repository. It is not claimed to be
an authoritative Layer8 protocol format. It reuses the existing canonical
hashing style where possible and adds only the minimal domain-separated
signature binding required by the current evidence package.

Signed message (deterministic, domain-separated):
    b"quantum-layer8-proto-v1:policy-delegation:" + decision_hash.encode("ascii")

The signature binds the delegation proof to the exact policy decision hash.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import base64

DOMAIN_PREFIX = b"quantum-layer8-proto-v1:policy-delegation:"


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def private_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_from_b64(b64: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(b64)
    return Ed25519PrivateKey.from_private_bytes(raw)


def delegation_message(decision_hash: str) -> bytes:
    """Domain-separated message that binds the signature to the exact decision hash."""
    if not isinstance(decision_hash, str) or len(decision_hash) != 64:
        raise ValueError("decision_hash must be a 64-character hex string")
    return DOMAIN_PREFIX + decision_hash.encode("ascii")


def sign_delegation(private_key: Ed25519PrivateKey, decision_hash: str) -> str:
    """Return base64 Ed25519 signature over the domain-separated decision hash."""
    message = delegation_message(decision_hash)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_delegation(public_key: Ed25519PublicKey, decision_hash: str, signature_b64: str) -> bool:
    """Return True if the signature is valid for the exact decision_hash. Fail closed."""
    try:
        message = delegation_message(decision_hash)
        signature = base64.b64decode(signature_b64)
        if len(signature) != 64:
            return False
        public_key.verify(signature, message)
        return True
    except Exception:
        return False
