"""Finish only existing-recording telemetry and explicitly confirmed issue publication."""

import getpass
import subprocess
import sys

from .clickhouse import ClickHouseError, Settings, update_credentials
from .intelligence import IntegrationError
from .integrations import main as finish


def main():
    cloud = False
    print("No Docker drill or OpenAI request will run. Existing verified recordings will be reused.")
    print("Corrective action: enter the current SQL database credentials from this existing ClickHouse service, not a Cloud login or management API key.")
    if sys.stdin.isatty():
        try:
            settings = Settings.load()
            user = getpass.getpass("Database username (hidden; Enter keeps the configured username): ") or settings.user
            password = getpass.getpass("Current database password (hidden; Enter skips ClickHouse): ")
            if password:
                update_credentials(user, password)
                cloud = True
                print("Local credentials updated privately. The next upload starts with a real SELECT 1; no automatic authentication retry.")
        except ClickHouseError as exc:
            print("ClickHouse INCONCLUSIVE:", str(exc))
    else:
        print("ClickHouse INCONCLUSIVE: interactive hidden credential input required; no request made.")
    arguments = ["--confirm-publication", "--deploy"]
    if not cloud:
        arguments.append("--skip-cloud")
    return finish(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (IntegrationError, ClickHouseError, OSError, ValueError, subprocess.SubprocessError, EOFError, KeyboardInterrupt):
        print("INCONCLUSIVE: final integration step did not complete; existing evidence preserved.", file=sys.stderr)
        raise SystemExit(2)
