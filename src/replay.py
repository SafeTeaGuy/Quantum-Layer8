"""Minimal local replay protection abstraction.

Cryptographic uniqueness of execution_id is distinct from durable production
replay prevention. This is an in-memory set for the prototype only.
"""

from typing import Set


class InMemoryReplayStore:
    """Simple set of seen execution_ids. Not durable."""

    def __init__(self):
        self._seen: Set[str] = set()

    def check_and_record(self, execution_id: str) -> bool:
        """Return True if new (and record it). Return False if already seen."""
        if not execution_id or not isinstance(execution_id, str):
            return False
        if execution_id in self._seen:
            return False
        self._seen.add(execution_id)
        return True

    def seen(self, execution_id: str) -> bool:
        return execution_id in self._seen
