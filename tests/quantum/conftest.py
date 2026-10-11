import pytest

from quantum_l8 import suites
from quantum_l8.adapters.qiskit_adapter import CPUExactSamplerAdapter, QiskitBasicSimulatorAdapter
from quantum_l8.executor import Executor
from quantum_l8.scenario import BELL_QASM, TENANT, delegate, make_world, request


def pytest_collection_modifyitems(config, items):
    # The hybrid suite needs ML-DSA. Absence must fail loudly, never skip.
    assert suites.mldsa_available(), "ML-DSA unavailable: cryptography>=47 with ML-DSA support is required"


@pytest.fixture
def world():
    w = make_world(suites.SUITE_HYBRID)
    delegate(w)
    return w


def decide(w, req, program=BELL_QASM, tenant=TENANT, executor_id=None):
    return w.gate.decide(req, program, tenant, w.now(), executor_id or w.executor_key.identity_id())


def state(out):
    return out["decision"]["body"]["state"]


def reasons(out):
    return out["decision"]["body"]["reasons"]


def make_executor(w, sinks=None, adapters=None):
    adapters = adapters or [QiskitBasicSimulatorAdapter(seed=11), CPUExactSamplerAdapter(seed=11)]
    return Executor(w.executor_key, w.gate, {a.adapter_id: a for a in adapters},
                    sinks if sinks is not None else {}, w.log, clock=w.now)


__all__ = ["decide", "state", "reasons", "make_executor", "request", "BELL_QASM", "TENANT"]
