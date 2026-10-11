"""Provider adapter boundary (EXPERIMENTAL).

An adapter translates. It is never an authority source:

* it receives an already-consumed authorization's id only as an idempotency
  tag, never the authority objects themselves;
* ``preflight`` may only refuse (return a reason code), before consumption;
* ``submit`` runs the job exactly once and never retries;
* everything it returns about the provider is PROVIDER_REPORTED, unless the
  adapter itself computed it locally (EXECUTOR_OBSERVED);
* any exception or ambiguity becomes outcome UNKNOWN at the executor.
"""

from __future__ import annotations

from typing import Protocol


class ProviderRun(dict):
    """Keys:
    provider_job_id (str), provider_reported_backend (str),
    provider_reported_status (str), shots_reported (int),
    counts (dict[str, int]), provider_metadata (dict[str, str|int|bool|None]),
    reproducibility (dict | None: how a third party could re-run it),
    reported_cost_micro_usd (int | None)
    """


class ProviderAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def preflight(self, program_text: str, workload: dict, descriptor: dict) -> str | None: ...

    def submit(self, program_text: str, workload: dict, descriptor: dict, idempotency_key: str) -> ProviderRun: ...

    def ideal_distribution(self, program_text: str, workload: dict) -> dict[str, float] | None: ...
