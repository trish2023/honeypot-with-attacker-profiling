"""SSH honeypot handler (PRD Section 5.2).

Sends a fake SSH identification banner, discards the client banner (no real
key exchange), then drops to a plaintext login/password prompt loop. Each
credential pair is enriched and written to the database, the session is
re-classified, and the response is tarpitted with an exponential delay.

Sessions that pass should_grant_access are dropped into the fake interactive
shell (5.7); everything else gets "Permission denied".
"""

import time

from core.database import db_insert_session, db_insert_attempt, db_update_classification
from core.enrichment import enrich_credentials
from core.tarpitting import get_tarpit_delay
from core.classification import classify_session
from core.fake_shell import should_grant_access, handle_fake_shell


def handle_ssh(conn, addr, session_id):
    ip, port = addr
    print(f"[SSH] Connection from {ip}:{port} (session {session_id})")
    db_insert_session(session_id, ip, port, "SSH")

    try:
        # Step 1: Send SSH identification banner
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

        # Step 2: Read client banner (discarded — no real key exchange)
        conn.recv(1024)

        # Step 3: Fake auth prompt loop
        attempt_count = 0
        last_attempt_time = None

        while attempt_count < 6:
            conn.send(b"login: ")
            username = conn.recv(256).decode(errors="ignore").strip()
            if not username:
                break

            conn.send(b"password: ")
            password = conn.recv(256).decode(errors="ignore").strip()
            if not password:
                break

            now = time.time()
            delay_ms = (now - last_attempt_time) * 1000 if last_attempt_time else None
            last_attempt_time = now

            is_default, is_common = enrich_credentials(username, password)
            db_insert_attempt(session_id, username, password, now, delay_ms, is_default, is_common)

            # Adaptive tarpitting — delay grows with each failed attempt.
            time.sleep(get_tarpit_delay(attempt_count))

            # Re-classify the session from its accumulated timing.
            db_update_classification(session_id, classify_session(session_id))

            attempt_count += 1

            # Fake shell: grant access on ~10% of sessions or after 3+ attempts.
            if should_grant_access(session_id, attempt_count):
                conn.send(b"\r\nWelcome to Ubuntu 22.04 LTS\r\n$ ")
                handle_fake_shell(conn, session_id)
                break
            else:
                conn.send(b"Permission denied, please try again.\r\n")

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
