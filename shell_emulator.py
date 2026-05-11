from datetime import datetime, timezone
from socket import timeout as SocketTimeout
from typing import Any

from db import log_shell_session


PROMPT = "root@ubuntu-server:~# "

COMMAND_RESPONSES = {
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var",
    "whoami": "root",
    "pwd": "/root",
    "uname -a": "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "cat /etc/passwd": "\n".join(
        (
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        )
    ),
    "ifconfig": "\n".join(
        (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
            "        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255",
            "        ether 00:16:3e:4f:8a:21  txqueuelen 1000  (Ethernet)",
            "        RX packets 18429  bytes 2358129 (2.3 MB)",
            "        TX packets 12933  bytes 1974421 (1.9 MB)",
        )
    ),
}


class FakeShell:
    def __init__(self, connection: Any, ip: str) -> None:
        self.connection = connection
        self.ip = ip
        self.commands: list[dict[str, str]] = []

    def run(self) -> None:
        """Start a fake interactive shell and log commands when it ends."""
        try:
            self._send_prompt()
            while True:
                command = self._receive_command()
                if command is None:
                    break

                if command:
                    self._log_command(command)
                    self._send_response(self._response_for(command))

                self._send_prompt()
        except (ConnectionError, OSError, SocketTimeout):
            pass
        finally:
            log_shell_session(self.ip, self.commands)

    def _receive_command(self) -> str | None:
        data = self.connection.recv(4096)
        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip()

    def _send_prompt(self) -> None:
        self.connection.sendall(PROMPT.encode("utf-8"))

    def _send_response(self, response: str) -> None:
        self.connection.sendall(f"{response}\n".encode("utf-8"))

    def _log_command(self, command: str) -> None:
        self.commands.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "command": command,
            }
        )

    def _response_for(self, command: str) -> str:
        return COMMAND_RESPONSES.get(command, "command not found")
