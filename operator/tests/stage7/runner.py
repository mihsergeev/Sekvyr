#!/usr/bin/env python3
"""Explicit actual matrix entrypoint. Never discovers a production context."""

import argparse
from pathlib import Path
import sys

from coordinator import Coordinator
from plain_cases import PlainCases


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-dir", type=Path, required=True)
    parser.add_argument("--operator-image", required=True)
    parser.add_argument("--helm", type=Path, required=True)
    parser.add_argument("--chart", type=Path, required=True)
    parser.add_argument("--phase", choices=("plain",), required=True)
    args = parser.parse_args()
    c = Coordinator(args.task_dir)
    try:
        c.panel.connect()
        c.panel.login()
        c.panel.unseal()
        cases = PlainCases(c, args.operator_image, args.helm, args.chart)
        for operation in (cases.initial, cases.changed_rollout_off, cases.opt_in,
                          cases.changed_rollout_on, cases.agent, cases.equal):
            operation()
    finally:
        # Interactive invocation retains ONLY this fixture's in-memory lifecycle
        # so a failed guard can be inspected without adopting existing objects.
        if not sys.flags.interactive:
            c.close()
