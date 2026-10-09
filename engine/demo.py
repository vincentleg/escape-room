"""Run SECURE -> deliberate DRIFT -> autonomous RECOVERY in disposable Docker."""

import argparse

from .agent import Agent, State
from .events import FAIL, INCONCLUSIVE, PASS, EventLog
from .gate import EXIT_CODES, evaluate, record_gate
from .policy import APPROVED, DRIFT_PATH, SECURE_PATH, load_config
from .probes import Probes
from .process import run_cli
from .runner import InfrastructureError, Runner
from .static import scan, verify_samples


def scenario(log, runner, advisor=None):
    runner.setup()
    probes = Probes(runner, log)
    secure = probes.run(runner.store.read(), "SECURE")
    if record_gate(log, runner.store.read(), secure, phase="SECURE") != PASS:
        return secure.status, {"reason": "Initial containment was not verified"}
    agent = Agent(runner.store, probes, log, advisor=advisor)
    drift = load_config(DRIFT_PATH)
    runner.store.inject_drift(drift)
    log.emit("DRIFT", "deliberate_drift_injected", PASS, "demo",
             {"active": runner.store.read().to_dict(), "synthetic_exercise": True})
    # This is the only external trigger. The state machine does everything after it.
    response = agent.handle("configuration_changed")
    drift_gate = evaluate(drift, response.incident)
    recovered_gate = evaluate(runner.store.read(), response.recovered)
    complete = (response.incident is not None
                and response.incident.statuses() == {"network": FAIL, "secret": FAIL}
                and agent.state == State.RECOVERED
                and drift_gate == FAIL and recovered_gate == PASS)
    status = PASS if complete else INCONCLUSIVE
    if response.recovered is not None and response.recovered.status == FAIL:
        status = FAIL
    return status, {"agent_state": agent.state.value, "three_acts_verified": complete,
                    "secure": secure.statuses(),
                    "drift": response.incident.statuses() if response.incident else None,
                    "recovered": response.recovered.statuses() if response.recovered else None,
                    "drift_gate_exit": EXIT_CODES[drift_gate],
                    "recovered_gate_exit": EXIT_CODES[recovered_gate]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir")
    parser.add_argument("--require-semgrep", action="store_true")
    parser.add_argument("--with-openai", action="store_true", help="Request bounded advice after actual incident confirmation")
    args = parser.parse_args(argv)
    log = EventLog(args.evidence_dir)
    runner = None
    status = INCONCLUSIVE
    summary = {"three_acts_verified": False}
    log.emit("SETUP", "run_started", PASS, "demo",
             {"scope": "Two controlled probes in disposable local Docker infrastructure",
              "status_semantics": "Probe PASS=denied, FAIL=observed access, INCONCLUSIVE=unverified",
              "evidence": "Actual command output; host-specific paths replaced by placeholders"})
    static = scan(log)
    static_check = verify_samples(log, static)
    try:
        if load_config(SECURE_PATH) != APPROVED:
            raise ValueError("secure.yaml does not match the built-in approved baseline")
        with Runner(log) as runner:
            from .intelligence import advise_incident
            status, runtime_summary = scenario(log, runner, advise_incident if args.with_openai else None)
            summary.update(runtime_summary)
    except (InfrastructureError, ValueError, OSError) as exc:
        status = INCONCLUSIVE
        log.emit("SETUP", "execution_error", status, "engine", {"reason": str(exc)})
        summary["reason"] = str(exc)
    except KeyboardInterrupt:
        status = INCONCLUSIVE
        log.emit("SETUP", "interrupted", status, "engine")
    if runner is not None and not runner.cleanup_ok:
        status = INCONCLUSIVE
    if static_check == FAIL:
        status = FAIL
    elif static_check == INCONCLUSIVE and (static.available or args.require_semgrep):
        status = INCONCLUSIVE
    summary.update(semgrep=static_check, semgrep_pending=not static.available,
                   cleanup_complete=runner.cleanup_ok if runner else True,
                   exit_code=EXIT_CODES[status])
    log.finish(status, **summary)
    return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
