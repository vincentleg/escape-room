"""Two real demos; success requires two PASS artifacts with distinct run IDs."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-semgrep", action="store_true")
    args = parser.parse_args()
    seen = set()
    for attempt in (1, 2):
        command = [sys.executable, "-m", "engine.demo"]
        if args.require_semgrep:
            command.append("--require-semgrep")
        result = subprocess.run(command, capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1])
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        if result.returncode != 0:
            print("Real demonstration attempt %d did not pass." % attempt, file=sys.stderr)
            return result.returncode
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        final = events[-1]
        if (final["status"] != "PASS" or not final["observed_evidence"].get("three_acts_verified")
                or final["run_id"] in seen):
            return 2
        seen.add(final["run_id"])
    print("Two independent three-act demonstrations passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
