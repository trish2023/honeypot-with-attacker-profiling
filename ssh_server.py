print("Server starting...")
import random
import socket
import threading
import time
from datetime import datetime, timezone

from db import init_db, insert_attempt
from enrichment import categorize, classify_behavior, fingerprint_tool, locate
from shell_emulator import FakeShell
from tarpit import apply_tarpit


SSH_BANNER = b"SSH-2.0-OpenSSH_8.4p1 Ubuntu-3ubuntu0.6\r\n"
ACCESS_DENIED = b"Access denied\r\n"


class SSHHoneypot:
    def __init__(self, host: str = "0.0.0.0", port: int = 2222) -> None:
        init_db()
        self.host = host
        self.port = port
        self.attempt_times: dict[str, list[str]] = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))

    def start(self) -> None:
        self.server_socket.listen()
        while True:
            try:
                conn, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
            except Exception:
                pass

    def handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        ip = addr[0]
        failed_attempts = 0
        last_attempt_time: float | None = None

        try:
            conn.sendall(SSH_BANNER)

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                credentials = self._parse_credentials(data)
                if credentials is None:
                    continue

                username, password = credentials
                now_monotonic = time.monotonic()
                timing_gap = (
                    1.0
                    if last_attempt_time is None
                    else now_monotonic - last_attempt_time
                )
                last_attempt_time = now_monotonic

                timestamp = datetime.now(timezone.utc).isoformat()
                location = locate(ip)
                credential_type = categorize(username, password)
                behavior_class = classify_behavior(ip, timestamp, self.attempt_times)
                tool_fingerprint = fingerprint_tool(
                    data.decode("utf-8", errors="replace"),
                    timing_gap,
                )
                response_delay = apply_tarpit(failed_attempts, behavior_class)
                accept_session = failed_attempts >= 3 and random.random() < 0.10

                insert_attempt(
                    {
                        "timestamp": timestamp,
                        "ip": ip,
                        "port": self.port,
                        "protocol": "SSH",
                        "username": username,
                        "password": password,
                        "country": location["country"],
                        "city": location["city"],
                        "lat": location["lat"],
                        "lon": location["lon"],
                        "credential_type": credential_type,
                        "behavior_class": behavior_class,
                        "tool_fingerprint": tool_fingerprint,
                        "response_delay": response_delay,
                        "session_type": "accepted" if accept_session else "rejected",
                    }
                )

                if accept_session:
                    FakeShell(conn, ip).run()
                    break

                conn.sendall(ACCESS_DENIED)
                failed_attempts += 1
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _parse_credentials(self, data: bytes) -> tuple[str, str] | None:
        text = data.decode("utf-8", errors="ignore")
        username = self._extract_value(
            text,
            ("username", "user", "login", "name"),
        )
        password = self._extract_value(
            text,
            ("password", "pass", "passwd", "pwd"),
        )

        if username and password:
            return username, password
        return None

    def _extract_value(self, text: str, labels: tuple[str, ...]) -> str | None:
        normalized = text.replace("\r", "\n").replace("\x00", "\n")
        lower_text = normalized.lower()

        for label in labels:
            for separator in ("=", ":", " "):
                marker = f"{label}{separator}"
                start = lower_text.find(marker)
                if start == -1:
                    continue

                value_start = start + len(marker)
                value = normalized[value_start:].lstrip()
                return self._read_token(value)

        return None

    def _read_token(self, value: str) -> str | None:
        token_chars = []
        for char in value:
            if char.isspace() or char in "\x00;&|":
                break
            token_chars.append(char)

        token = "".join(token_chars).strip("\"'")
        return token or None
print("Listening on port 2222")
if __name__ == "__main__":
    server = SSHHoneypot()
    server.start()