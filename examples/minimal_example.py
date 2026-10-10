"""Minimal end-to-end example of building and verifying a quantum job evidence package."""

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
        "intent_hash": "a" * 64,
    }

    package = build_package(
        agent_identity=agent,
        authorization=auth,
        job_hash="b" * 64,
        provider="ibm-quantum",
        device_id="ibm_kingston",
        results={
            "type": "counts",
            "data": {"00": 512, "11": 512},
            "shots": 1024,
            "error_bounds": {"method": "reported", "value": 0.02},
        },
        calibration_snapshot={
            "timestamp": "2026-10-10T22:00:00Z",
            "pointer": "ibm://backend/ibm_kingston/properties/2026-10-10T21:55:00Z",
            "hash": "c" * 64,
            "summary": {"avg_readout_error": 0.015},
        },
        settlement={"resource_units": 0.1, "receipt_id": "job-abc123"},
    )

    print("Package hash:", package["package_hash"])
    ok, reason = verify_package(package)
    print(f"Verification: {ok} ({reason})")

    # Tamper test
    package["results"]["data"]["00"] = 999
    ok2, reason2 = verify_package(package)
    print(f"After tamper: {ok2} ({reason2})")


if __name__ == "__main__":
    main()
