"""Loopback-only scoped kubectl forward, with no global process cleanup."""

import os
import socket
import subprocess
import time


class Forward:
    def __init__(self, cluster, namespace, target, remote_port):
        if namespace not in cluster.namespaces:
            raise ValueError("Forward outside the isolated trial refused")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.process = subprocess.Popen([str(cluster.kubectl), "--kubeconfig", str(cluster.config), "-n", namespace,
            "port-forward", "--address=127.0.0.1", target, str(self.port) + ":" + str(remote_port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Scoped forward exited")
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                        return
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError("Scoped forward startup timeout")
        except BaseException:
            self.close()
            raise

    def __repr__(self):
        return "<isolated trial loopback forward>"

    @property
    def origin(self):
        return "https://localhost:" + str(self.port)

    def close(self):
        if self.process.poll() is not None:
            return
        try:
            owned_group = os.name == "posix" and os.getpgid(self.process.pid) == self.process.pid
        except ProcessLookupError:
            return
        if owned_group:
            subprocess.run(["sudo", "-n", "kill", "-TERM", "--", "-" + str(self.process.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        elif self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if owned_group:
                subprocess.run(["sudo", "-n", "kill", "-KILL", "--", "-" + str(self.process.pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()
