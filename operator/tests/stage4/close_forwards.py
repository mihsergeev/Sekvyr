#!/usr/bin/env python3
"""Stop only port-forwards carrying an exact validated test kubeconfig path."""

import argparse
import os
from pathlib import Path
import signal
import subprocess

from authority import Authority


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    args = parser.parse_args()
    task = Authority.safe_task(args.task_dir)
    expected = str(task / "kubeconfig").encode()
    stopped = 0
    for process in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            command = process.read_bytes().split(b"\0")
            if b"port-forward" not in command or b"--kubeconfig" not in command:
                continue
            index = command.index(b"--kubeconfig")
            if index + 1 >= len(command) or command[index + 1] != expected:
                continue
            pid = int(process.parent.name)
            try:
                os.kill(pid, signal.SIGTERM)
            except PermissionError:
                subprocess.run(["sudo", "-n", "kill", "-TERM", str(pid)], check=True, capture_output=True)
            stopped += 1
        except (FileNotFoundError, ProcessLookupError):
            continue
    print("PASS isolated port-forward processes closed: " + str(stopped))


if __name__ == "__main__":
    main()
