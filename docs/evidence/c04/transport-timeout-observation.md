# Docker transport timeout observation

An earlier parallel validation process exited 137 without pytest output. This
was not counted as a passing run. Inspection found that both generic Docker
Popen transports inherited the caller's process group, while bounded timeout
cleanup terminates the child's group. That could kill the calling runner.

Both Docker transports now start separate POSIX sessions. Regression tests in
`tests/test_c04_transport.py` exercise actual child timeouts from an isolated
runner, for standalone and sequence transports, and require exit 124 with the
runner surviving. They do not invoke Docker or target code.

After the correction, the real Docker boundary suite was rerun sequentially:
6 passed in 7.51 seconds. Its unmodified output is `docker-boundary.txt`.
The earlier empty output cannot identify the precise cause of exit 137; the
process-group defect was independently reproduced by the regression tests.
