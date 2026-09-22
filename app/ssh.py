"""Thin paramiko wrapper: run commands as root (directly or via `sudo -n`)."""
import os
import shlex

import paramiko


class RemoteError(RuntimeError):
    pass


class Remote:
    def __init__(self, server: dict, timeout: int = 15):
        self.server, self.timeout = server, timeout
        self.host = server["host"]
        self.user = server.get("user") or "root"
        self._connect()

    def _connect(self):
        server, timeout = self.server, self.timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=int(server.get("ssh_port") or 22),
            username=self.user,
            password=server.get("password") or None,
            key_filename=os.path.expanduser(server["key_path"]) if server.get("key_path") else None,
            timeout=timeout,
            allow_agent=True,
            look_for_keys=not server.get("password"),
        )
        self.client.get_transport().set_keepalive(15)

    def run(self, cmd: str, input: str | None = None, check: bool = True, timeout: int = 900) -> str:
        """Run `cmd` through bash as root. Returns stdout; raises RemoteError on non-zero exit if check."""
        wrapped = f"bash -c {shlex.quote(cmd)}"
        if self.user != "root":
            wrapped = f"sudo -n {wrapped}"
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout)
        if input is not None:
            stdin.write(input)
        stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        if check and code != 0:
            raise RemoteError(f"[{self.host}] `{cmd[:120]}` exit {code}: {err.strip() or out.strip()}")
        return out

    def put(self, path: str, content: str, mode: str = "600") -> None:
        self.run(f"cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}", input=content)

    def reconnect(self) -> None:
        self.close()
        self._connect()

    def close(self) -> None:
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
