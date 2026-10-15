"""Fixed provider transport with a total request deadline and no orphan requests."""
import http.client
import json
import multiprocessing
import time
import urllib.error
import urllib.request
from math import isfinite

from pipeline.cancellation import check_cancelled

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _request_worker(connection, url, payload, headers, timeout):
    try:
        request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("Provider response exceeds transport byte limit")
                result = json.loads(raw.decode("utf-8"))
                if not isinstance(result, dict):
                    raise TypeError("Provider response is not a JSON object")
                connection.send((True, result))
        except urllib.error.HTTPError as exc:
            body = " ".join(exc.read(1024).decode("utf-8", errors="replace").split())[:350]
            connection.send((False, f"HTTP {exc.code}: {body}"))
    except (OSError, ValueError, TypeError, http.client.HTTPException) as exc:
        connection.send((False, f"network/timeout: {type(exc).__name__}"))
    finally:
        connection.close()


def post_json(url, payload, *, headers, timeout):
    """Terminate the fixed transport even if DNS/TLS/headers/body keep stalling.

    Credentials travel through multiprocessing memory, never command-line arguments.
    Cancellation propagates after the request child is joined; fallbacks cannot leave
    a previous provider request running. Executor processes are not affected.
    """
    check_cancelled()
    if not isfinite(timeout) or timeout <= 0:
        raise TimeoutError("Provider request deadline exhausted")
    deadline = time.monotonic() + timeout
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_request_worker, args=(sender, url, payload, headers, timeout), daemon=True)
    try:
        process.start()
        sender.close()
        while True:
            check_cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("network/timeout: provider total request deadline exhausted")
            if receiver.poll(min(remaining, .05)):
                try:
                    success, result = receiver.recv()
                except EOFError:
                    raise RuntimeError("network/timeout: provider transport exited without a response") from None
                if not success:
                    raise RuntimeError(result)
                return result
    finally:
        sender.close()
        receiver.close()
        if process.pid is not None:
            process.join(timeout=.1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            process.close()
