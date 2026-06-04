"""Single-machine attacker simulation (PRD Section 8).

Drives the FTP honeypot from the same machine to exercise the behavioural
classification engine — a fast "bot" and a slow "human".

NOTE on deviation from the PRD snippet: the PRD opens a fresh TCP connection
for every credential, which produces one attempt per session. Because
``delay_ms`` is NULL on the first attempt of a session, such single-attempt
sessions can never be classified (they stay 'unknown'). To give the engine the
inter-attempt timing it needs, each simulated attacker here reuses a single
connection for several USER/PASS attempts — which is also closer to how real
brute-force tools behave.
"""

import socket
import sys
import time

HOST = "127.0.0.1"
FTP_PORT = 2121

FTP_CREDS = [
    ("admin", "admin"),
    ("root", "toor"),
    ("pi", "raspberry"),
    ("user", "password123"),
]


def _recv(sock) -> str:
    try:
        return sock.recv(256).decode(errors="ignore").strip()
    except socket.timeout:
        return ""


def _simulate(delay: float, label: str):
    """Run through FTP_CREDS over one connection, pausing ``delay`` seconds
    around each PASS. Stops once access is granted (non-530 reply)."""
    try:
        sock = socket.create_connection((HOST, FTP_PORT), 5)
    except ConnectionRefusedError:
        sys.exit(
            f"\n[!] Could not connect to the FTP honeypot at {HOST}:{FTP_PORT}.\n"
            "    The honeypot server is not running. Start it first in another\n"
            "    terminal with:  python main.py\n"
        )
    sock.settimeout(30)
    print(f"[{label}] {_recv(sock)}")                     # 220 greeting

    for user, pwd in FTP_CREDS:
        sock.send(f"USER {user}\r\n".encode())
        _recv(sock)                                       # 331
        time.sleep(delay)
        sock.send(f"PASS {pwd}\r\n".encode())
        resp = _recv(sock)
        print(f"[{label}] {user}:{pwd} -> {resp}")
        if "530" not in resp:                             # granted (230) — stop
            break
        time.sleep(delay)

    sock.close()


def simulate_bot(delay: float = 0.1):
    """Fast bot — should trigger bot classification."""
    _simulate(delay, "BOT")


def simulate_human(delay: float = 4.0):
    """Slow human — should trigger human classification."""
    _simulate(delay, "HUMAN")


if __name__ == "__main__":
    print("=== Simulating bot ===")
    simulate_bot(delay=0.1)
    time.sleep(2)
    print("=== Simulating human ===")
    simulate_human(delay=4.0)
