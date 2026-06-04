"""Behavioural classification engine (PRD Section 5.9).

Labels a session as 'bot', 'human', or 'unknown' from the inter-attempt
timing recorded in the attempts table. Any sub-500ms delay is a strong bot
signal; consistently slow (>3s) delays indicate a human; mixed timing defaults
conservatively to 'bot'.
"""

from core.database import get_db, _db_lock


def classify_session(session_id: str) -> str:
    with _db_lock:
        rows = get_db().execute(
            "SELECT delay_ms FROM attempts WHERE session_id=? AND delay_ms IS NOT NULL",
            (session_id,),
        ).fetchall()

    if not rows:
        return "unknown"

    delays = [r[0] for r in rows]
    if any(d < 500 for d in delays):
        return "bot"
    if all(d > 3000 for d in delays):
        return "human"
    return "bot"
