"""Fixed two-generation B05 verification for selected whoami fields."""
import subprocess

from executor.access_fixture import digest
from schemas.access_verification import AccessCheckTrace
from security.access_verification import binding_id


def execute_user_fields_check(runtime, action):
    trials = []
    technical_error = None
    reset = False
    snapshot = digest(runtime.lab.source_files)
    try:
        trials.append(runtime.lab.user_fields_step(action.verification_binding.source_snapshot))
        runtime._ready_generation(after_reset=True)
        reset = True
        trials.append(runtime.lab.user_fields_step(action.verification_binding.source_snapshot))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        technical_error = "user_fields_fixture_failure:" + type(exc).__name__
    finally:
        cleanup = runtime.lab.close()
        intact = runtime.initial_snapshot is not None and runtime.lab._snapshot() == runtime.initial_snapshot
    return AccessCheckTrace(
        check_id="juice-user-private-fields-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="user_private_fields",
        endpoint_id="user-fields", method="GET", object_ref="user-a", mutation_field=None,
        controls={}, generations=[], exchanges=[], user_fields_trials=trials,
        fixture_source_snapshot_digest=snapshot,
        exchange_count=sum(trial.http_exchanges for trial in trials), request_budget=20,
        reset_complete=reset, cleanup_complete=cleanup, integrity_verified=intact,
        technical_error=technical_error,
    )
