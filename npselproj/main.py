"""HoneyTrap Logger — entry point.

Starts both honeypot servers (SSH + FTP) on their respective ports. Each
accepted connection is dispatched to a protocol handler in its own daemon
thread (see PRD Section 5.1). The main thread then runs the live Rich
dashboard.
"""

import socket
import threading
import uuid

from core.enrichment import load_credential_lists
from dashboard.ui import run_dashboard
from servers.ssh_honeypot import handle_ssh
from servers.ftp_honeypot import handle_ftp

SSH_PORT = 2222
FTP_PORT = 2121


def start_server(port, handler_fn):
    """Bind a TCP socket on the given port and dispatch each accepted
    connection to ``handler_fn`` in its own daemon thread."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(100)
    print(f"[*] Listening on port {port}")

    while True:
        conn, addr = server.accept()
        session_id = str(uuid.uuid4())
        t = threading.Thread(
            target=handler_fn,
            args=(conn, addr, session_id),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    load_credential_lists()

    threading.Thread(
        target=start_server, args=(SSH_PORT, handle_ssh), daemon=True
    ).start()
    threading.Thread(
        target=start_server, args=(FTP_PORT, handle_ftp), daemon=True
    ).start()

    print("[*] HoneyTrap Logger running. Press Ctrl+C to stop.")

    # Hand the main thread off to the live dashboard.
    try:
        run_dashboard()
    except KeyboardInterrupt:
        pass
    print("\n[*] Shutting down.")
