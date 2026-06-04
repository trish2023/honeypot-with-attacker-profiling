"""FTP honeypot handler (PRD Section 5.3).

Simulates the plaintext FTP 220/331/530 flow. Parses USER/PASS commands, enriches
and writes each credential pair to the database, re-classifies the session, and
tarpits before replying. Sessions that pass should_grant_access receive a
"230 Login successful" and are dropped into the fake interactive shell (5.7);
everything else gets "530 Login incorrect".
"""

import time

from core.database import db_insert_session, db_insert_attempt, db_update_classification
from core.enrichment import enrich_credentials
from core.tarpitting import get_tarpit_delay
from core.classification import classify_session
from core.fake_shell import should_grant_access, handle_fake_shell


def handle_ftp(conn, addr, session_id):
    ip, port = addr
    print(f"[FTP] Connection from {ip}:{port} (session {session_id})")
    db_insert_session(session_id, ip, port, "FTP")

    try:
        # FTP greeting
        conn.send(b"220 FTP Server Ready (vsftpd 3.0.5)\r\n")

        attempt_count = 0
        last_attempt_time = None
        current_user = None

        while attempt_count < 6:
            data = conn.recv(1024).decode(errors="ignore").strip()
            if not data:
                break

            command = data[:4].upper()

            if command == "USER":
                current_user = data[5:].strip()
                conn.send(b"331 Please specify the password.\r\n")

            elif command == "PASS":
                password = data[5:].strip()
                now = time.time()
                delay_ms = (now - last_attempt_time) * 1000 if last_attempt_time else None
                last_attempt_time = now

                if current_user:
                    is_default, is_common = enrich_credentials(current_user, password)
                    db_insert_attempt(
                        session_id, current_user, password, now, delay_ms, is_default, is_common
                    )

                    # Adaptive tarpitting — delay grows with each failed attempt.
                    time.sleep(get_tarpit_delay(attempt_count))

                    # Re-classify the session from its accumulated timing.
                    db_update_classification(session_id, classify_session(session_id))

                    attempt_count += 1

                    # Fake shell: grant access on ~10% of sessions or after 3+ attempts.
                    if should_grant_access(session_id, attempt_count):
                        conn.send(b"230 Login successful.\r\n")
                        handle_fake_shell(conn, session_id)
                        break
                    else:
                        conn.send(b"530 Login incorrect.\r\n")
                current_user = None

            elif command == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break

            else:
                conn.send(b"530 Please login with USER and PASS.\r\n")

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
