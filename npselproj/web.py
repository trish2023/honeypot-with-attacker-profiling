"""HoneyTrap Logger — web dashboard entry point.

Runs everything in one process and one command:

    python web.py

It loads the credential wordlists, starts both honeypot servers (SSH 2222 /
FTP 2121) on daemon threads, then serves the interactive web dashboard. Open
the printed URL in a browser. The original terminal dashboard remains available
via ``python main.py``.
"""

import threading

import uvicorn

from core.enrichment import load_credential_lists
from main import FTP_PORT, SSH_PORT, start_server
from servers.ftp_honeypot import handle_ftp
from servers.ssh_honeypot import handle_ssh

WEB_HOST = "127.0.0.1"
WEB_PORT = 8000


def main():
    load_credential_lists()

    threading.Thread(
        target=start_server, args=(SSH_PORT, handle_ssh), daemon=True
    ).start()
    threading.Thread(
        target=start_server, args=(FTP_PORT, handle_ftp), daemon=True
    ).start()

    print("\n" + "=" * 60)
    print("  HoneyTrap Logger — web dashboard")
    print(f"  Open:  http://{WEB_HOST}:{WEB_PORT}")
    print("  Honeypots listening on SSH 2222 and FTP 2121")
    print("=" * 60 + "\n")

    uvicorn.run("webapp.server:app", host=WEB_HOST, port=WEB_PORT, log_level="warning")


if __name__ == "__main__":
    main()
