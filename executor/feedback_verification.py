"""Fixed two-generation B05 feedback owner-assignment verification."""

import subprocess

from executor.access_fixture import digest
from schemas.access_verification import AccessCheckTrace
from security.access_verification import binding_id


def execute_feedback_check(runtime, action):
    trials = []
    technical_error = None
    reset = False
    fixture_source = digest(runtime.lab.source_files)
    try:
        trials.append(runtime.lab.feedback_step(action.verification_binding.source_snapshot))
        runtime._ready_generation(after_reset=True)
        reset = True
        trials.append(runtime.lab.feedback_step(action.verification_binding.source_snapshot))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        technical_error = "feedback_fixture_failure:" + type(exc).__name__
    finally:
        cleanup = runtime.lab.close()
        intact = runtime.initial_snapshot is not None and runtime.lab._snapshot() == runtime.initial_snapshot
    return AccessCheckTrace(
        check_id="juice-feedback-owner-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="feedback_owner",
        endpoint_id="feedback-create", method="POST", object_ref="feedback-b",
        controls={}, generations=[], exchanges=[], feedback_trials=trials,
        fixture_source_snapshot_digest=fixture_source,
        exchange_count=sum(trial.http_exchanges for trial in trials), request_budget=20,
        reset_complete=reset, cleanup_complete=cleanup, integrity_verified=intact,
        technical_error=technical_error,
    )
