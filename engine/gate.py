"""CI exit codes: 0 pass, 1 observed/policy violation, 2 inconclusive/error."""

import argparse

from .events import FAIL, INCONCLUSIVE, PASS, EventLog
from .policy import SECURE_PATH, diff, load_config
from .probes import Probes
from .process import run_cli
from .runner import InfrastructureError, Runner
from .static import scan

EXIT_CODES = {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}


def evaluate(config, probes=None, *, policy_only=False):
    if diff(config):
        return FAIL
    if policy_only:
        return PASS
    return probes.status if probes is not None else INCONCLUSIVE


def record_gate(log, config, probes=None, *, phase="GATE", policy_only=False):
    status = evaluate(config, probes, policy_only=policy_only)
    log.emit(phase, "security_gate", status, "gate",
             {"exit_code": EXIT_CODES[status],
              "scope": "configuration_only" if policy_only else "configuration_and_runtime",
              "probes": probes.statuses() if probes else None}, config_diff=diff(config))
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(SECURE_PATH))
    parser.add_argument("--policy-only", action="store_true",
                        help="Only assert configuration compliance; no containment claim")
    parser.add_argument("--require-semgrep", action="store_true")
    parser.add_argument("--evidence-dir")
    args = parser.parse_args(argv)
    log = EventLog(args.evidence_dir)
    runner = None
    status = INCONCLUSIVE
    try:
        config = load_config(args.config)
        static = scan(log, (args.config,))
        if diff(config):
            status = record_gate(log, config, policy_only=args.policy_only)
        elif static.status == FAIL:
            status = FAIL
        elif static.status == INCONCLUSIVE and (static.available or args.require_semgrep):
            status = INCONCLUSIVE
        elif args.policy_only:
            status = record_gate(log, config, policy_only=True)
        else:
            with Runner(log) as runner:
                runner.setup()
                observed = Probes(runner, log).run(config, "GATE")
                status = record_gate(log, config, observed)
    except (InfrastructureError, ValueError, OSError) as exc:
        status = INCONCLUSIVE
        log.emit("GATE", "execution_error", INCONCLUSIVE, "engine", {"reason": str(exc)})
    except KeyboardInterrupt:
        status = INCONCLUSIVE
        log.emit("GATE", "interrupted", status, "engine")
    if runner is not None and not runner.cleanup_ok:
        status = INCONCLUSIVE
    log.finish(status, command="gate", exit_code=EXIT_CODES[status],
               scope="configuration_only" if args.policy_only else "configuration_and_runtime")
    return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
