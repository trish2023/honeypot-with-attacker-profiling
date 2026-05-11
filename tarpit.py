import time


BOT_DELAYS = {
    0: 0,
    1: 2,
    2: 5,
    3: 10,
}
MAX_BOT_DELAY = 20


def get_delay(attempt_count: int, behavior_class: str) -> float:
    """Return the tarpit delay in seconds for an attempt."""
    base_delay = BOT_DELAYS.get(attempt_count, MAX_BOT_DELAY)

    if behavior_class == "human":
        return base_delay / 2
    if behavior_class == "unknown":
        return base_delay / 4
    return float(base_delay)


def apply_tarpit(attempt_count: int, behavior_class: str) -> float:
    """Sleep for the calculated tarpit delay and return it."""
    delay = get_delay(attempt_count, behavior_class)
    time.sleep(delay)
    return delay
