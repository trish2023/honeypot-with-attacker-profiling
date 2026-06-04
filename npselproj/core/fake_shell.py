"""Fake interactive shell + intent tagging (PRD Section 5.7).

Roughly 10% of sessions, or any session with 3+ attempts, is "granted" access
and dropped into a simulated Linux shell. Every command is logged and tagged
with an intent category so post-authentication behaviour can be analysed.
"""

import random
import time

from core.database import db_insert_shell_command


def should_grant_access(session_id: str, attempt_count: int) -> bool:
    if attempt_count >= 3:
        return True
    return random.random() < 0.10


INTENT_TAGS = {
    "wget":             "malware_download",
    "curl":             "malware_download",
    "cat /etc/passwd":  "credential_harvesting",
    "cat /etc/shadow":  "credential_harvesting",
    "netstat":          "network_recon",
    "ifconfig":         "network_recon",
    "ip addr":          "network_recon",
    "ps aux":           "process_enum",
    "ps -ef":           "process_enum",
    "uname":            "system_info",
    "id":               "system_info",
    "crontab":          "persistence_attempt",
    "cron":             "persistence_attempt",
}

FAKE_RESPONSES = {
    "ls":               "Desktop  Documents  Downloads  Music  Pictures  Videos",
    "pwd":              "/home/user",
    "whoami":           "root",
    "id":               "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a":         "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ifconfig":         "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> inet 192.168.1.105",
    "netstat":          "Active Internet connections\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN",
    "ps aux":           "root         1  0.0  0.1  bash\nroot       123  0.0  0.2  sshd",
    "cat /etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin",
    "wget":             "Connecting to attacker-c2... (simulated)",
    "curl":             "  % Total    % Received ... simulated transfer",
}


def handle_fake_shell(conn, session_id):
    conn.send(b"Last login: Mon Jan 15 09:32:11 2024\r\n$ ")

    while True:
        try:
            data = conn.recv(1024).decode(errors="ignore").strip()
        except Exception:
            break

        if not data:
            continue

        if data in ("exit", "logout", "quit"):
            conn.send(b"logout\r\n")
            break

        # Determine intent tag
        intent_tag = None
        for keyword, tag in INTENT_TAGS.items():
            if keyword in data.lower():
                intent_tag = tag
                break

        # Log the command
        db_insert_shell_command(session_id, data, time.time(), intent_tag)

        # Send fake response
        response = None
        for cmd_key, resp in FAKE_RESPONSES.items():
            if data.lower().startswith(cmd_key):
                response = resp
                break

        if response:
            conn.send(f"{response}\r\n$ ".encode())
        else:
            conn.send(f"bash: {data}: command not found\r\n$ ".encode())
