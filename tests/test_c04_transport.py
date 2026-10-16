"""Docker transport timeout must kill its child, never the repair runner group."""
import os
import subprocess
import sys
import textwrap

import pytest


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-group regression')
@pytest.mark.parametrize('mode', ['standalone', 'sequence'])
def test_docker_transport_timeout_preserves_runner(mode):
    # Keep the simulated runner in its own session: a regression may kill this
    # child runner, but cannot kill pytest or its calling repair workflow.
    script = textwrap.dedent('''
        import subprocess
        import sys
        from pathlib import Path
        from executor.sandbox import DockerSandbox, DockerSequenceRuntime, SandboxRequest
        from executor.sandbox_policy import SandboxLimits, SandboxPolicy

        original_popen = subprocess.Popen
        calls = []
        def operator_transport(argv, **kwargs):
            calls.append(kwargs)
            return original_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        subprocess.Popen = operator_transport
        subprocess.run = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, b'', b'')
        policy = SandboxPolicy(backend='docker', sandbox_image='python@sha256:' + 'a' * 64,
                               limits=SandboxLimits(wall_time_seconds=.1))
        request = SandboxRequest(run_id='timeout', tool='safe_noop', base_url='http://juice',
                                 parameters={}, request_timeout_seconds=1)
        if sys.argv[1] == 'standalone':
            runtime = DockerSandbox(policy)
        else:
            runtime = DockerSequenceRuntime(policy, Path('executor/worker.py'), 'owned-network', None)
            runtime._container_name = 'owned-container'
            runtime.runtime_instance_id = 'owned-container'
        result = runtime.run(request)
        assert result.timed_out and result.exit_code == 124, result
        assert calls and all(call['start_new_session'] is True and call['shell'] is False for call in calls)
        print('runner-survived-child-timeout')
    ''')
    completed = subprocess.run([sys.executable, '-c', script, mode], capture_output=True,
                               text=True, timeout=10, start_new_session=True, check=False)
    assert completed.returncode == 0, (completed.returncode, completed.stdout, completed.stderr)
    assert completed.stdout.strip() == 'runner-survived-child-timeout'
