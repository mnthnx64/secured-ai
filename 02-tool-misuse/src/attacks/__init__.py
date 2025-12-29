"""
Attack payloads for testing ASI02 vulnerabilities.

These payloads demonstrate various tool misuse attack scenarios.
"""

from .payloads import (
    ATTACK_PAYLOADS,
    get_attack_payload,
    get_all_attack_names,
    AttackScenario,
)

__all__ = [
    "ATTACK_PAYLOADS",
    "get_attack_payload",
    "get_all_attack_names",
    "AttackScenario",
]

