"""Adaptive tarpitting (PRD Section 5.4).

Delay grows with each failed attempt to waste attacker resources.
"""


def get_tarpit_delay(attempt_count: int) -> float:
    """Returns delay in seconds.

    attempt 0 → 1s
    attempt 1 → 3s
    attempt 2 → 8s
    attempt 3+ → 20s (cap)
    """
    delays = [1, 3, 8, 20]
    index = min(attempt_count, len(delays) - 1)
    return delays[index]
