"""Quantum job evidence example (uses the generalized package)."""

from src.evidence import build_package, verify_package


def main():
    agent = {
        "id": "agent:example-01",
        "public_key": "ed25519:placeholder-pubkey",
        "key_type": "ed25519",
    }
    auth = {
        "delegation_proof": "sig:placeholder-layer8-delegation",
        "policy_id": "policy:quantum-research-001",
    }

    package = build_package(
        agent_identity=agent,
        authorization=auth,
        action_hash="b" * 64,
        action_type="quantum_job",
        provider="ibm-quantum",
        target="ibm_kingston",
        result={
            "type": "counts",
            "data": {"00": 512, "11": 512},
            "status": "completed",
            "error_bounds": {"method": "reported", "value": 0.02},
        },
        quantum={
            "device_id": "ibm_kingston",
            "calibration_snapshot": {
                "timestamp": "2026-10-10T22:00:00Z",
                "pointer": "ibm://backend/ibm_kingston/properties/2026-10-10T21:55:00Z",
                "hash": "c" * 64,
            },
        },
        settlement={"resource_units": 0.1, "receipt_id": "job-abc123"},
    )

    print("Package hash:", package["package_hash"])
    ok, reason = verify_package(package)
    print(f"Verification: {ok} ({reason})")

    package["result"]["data"]["00"] = 999
    ok2, reason2 = verify_package(package)
    print(f"After tamper: {ok2} ({reason2})")


if __name__ == "__main__":
    main()
