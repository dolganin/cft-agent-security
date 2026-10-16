"""Fixed operator review protocol using the canonical B04 lifecycle."""
import subprocess

from executor.access_fixture import digest
from schemas.access_verification import AccessCheckTrace
from security.access_verification import binding_id


def execute_review_check(runtime, action):
    trials = []
    technical_error = None
    reset = False
    snapshot = digest(runtime.lab.source_files)
    try:
        trials.append(runtime.lab.review_step(action.verification_binding.source_snapshot))
        runtime._ready_generation(after_reset=True)
        reset = True
        trials.append(runtime.lab.review_step(action.verification_binding.source_snapshot))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        technical_error = "review_fixture_failure:" + type(exc).__name__
    finally:
        cleanup = runtime.lab.close()
        intact = runtime.initial_snapshot is not None and runtime.lab._snapshot() == runtime.initial_snapshot
    return AccessCheckTrace(check_id="juice-review-own-write-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="review_update",
        endpoint_id="review-write", method="PATCH", object_ref="review-b", mutation_field="message",
        controls={}, generations=[], exchanges=[], review_trials=trials,
        review_source_snapshot_digest=snapshot, exchange_count=sum(t.http_exchanges for t in trials),
        request_budget=26, reset_complete=reset, cleanup_complete=cleanup,
        integrity_verified=intact, technical_error=technical_error)


def execute_review_nosql_check(runtime, action):
    trials = []
    technical_error = None
    reset = False
    snapshot = digest(runtime.lab.source_files)
    try:
        trials.append(runtime.lab.review_step(action.verification_binding.source_snapshot))
        runtime._ready_generation(after_reset=True)
        reset = True
        trials.append(runtime.lab.review_step(action.verification_binding.source_snapshot))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        technical_error = "review_nosql_fixture_failure:" + type(exc).__name__
    finally:
        cleanup = runtime.lab.close()
        intact = runtime.initial_snapshot is not None and runtime.lab._snapshot() == runtime.initial_snapshot
    return AccessCheckTrace(check_id="juice-review-nosql-selector-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="review_nosql_selector",
        endpoint_id="review-write", method="PATCH", object_ref="review-b", mutation_field="message",
        controls={}, generations=[], exchanges=[], review_nosql_trials=trials,
        review_source_snapshot_digest=snapshot, exchange_count=sum(t.http_exchanges for t in trials),
        request_budget=26, reset_complete=reset, cleanup_complete=cleanup,
        integrity_verified=intact, technical_error=technical_error)
