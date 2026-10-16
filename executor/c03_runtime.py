"""C03 adapters extending the existing fix and B06 Docker lifecycles."""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from time import monotonic
from uuid import uuid4

from executor.access_fixture import ROOT, TARGET_IMAGE
from executor.b06_runtime import B06Runtime
from executor.fix_runtime import DockerFixRuntime
from fix_verification.scope import load_scope
from fix_verification.scope_source import expressions
from schemas.b06_verification import FixtureExecutionBinding, profile_digest
from security.verification_binding import digest, source_snapshot

WORKER_IMAGE = 'python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4'

# Operator fixture, identical in every independent generation. No application
# source is edited; only the disposable runtime database is populated.
SEED = """
import sqlite3,json,hashlib
db=sqlite3.connect('/workspace/target/data/juiceshop.sqlite')
assert db.execute('SELECT COUNT(*) FROM Products WHERE id>=9000').fetchone()[0]==0
rows=[(9001,'CFTApple','Fresh red fruit',None),(9002,"CFTFarmer's Pear",'CFTGreen fruit',None),
      (9003,'CFTDeleted Apple','removed','2020-01-01'),(9004,'Zebra CFT','CFTApple description',None),
      (9005,'L'*200,'Long name',None)]
for id,name,description,deleted in rows:
 db.execute('INSERT INTO Products (id,name,description,price,deluxePrice,image,createdAt,updatedAt,deletedAt) VALUES (?,?,?,1,1,?, ?, ?, ?)',
            (id,name,description,'fixture.png','2020-01-01','2020-01-01',deleted))
db.execute('CREATE TABLE EvaluatorSentinel AS SELECT * FROM Products WHERE 0')
db.execute("INSERT INTO EvaluatorSentinel SELECT 999,'private-evaluator-sentinel','not-a-product',price,deluxePrice,image,createdAt,updatedAt,deletedAt FROM Products WHERE id=1")
db.commit()
actual=db.execute('SELECT id,name,description,deletedAt FROM Products WHERE id>=9000 ORDER BY id').fetchall()
assert actual==rows
all_rows=db.execute('SELECT id,name,description,deletedAt IS NOT NULL FROM Products ORDER BY id').fetchall()
baseline=[r[0] for r in db.execute('SELECT id FROM Products WHERE deletedAt IS NULL ORDER BY name').fetchall()]
print(json.dumps({'fixture_sha256':hashlib.sha256(json.dumps(all_rows,separators=(',',':')).encode()).hexdigest(),
                  'rows':len(all_rows),'baseline_ids':baseline}))
db.close()
"""
REDIRECT_SMOKE = """
const http=require('http'),assert=require('assert');
const request=to=>new Promise((resolve,reject)=>{
 const r=http.get('http://127.0.0.1:3000/redirect?to='+encodeURIComponent(to),s=>{
 s.resume();s.on('end',()=>resolve([s.statusCode,s.headers.location]));
 });r.on('error',reject);r.setTimeout(1000,()=>r.destroy(new Error('timeout')));
});
(async()=>{const url='https://github.com/juice-shop/juice-shop';let ready=false;
for(let i=0;i<30;i++){try{assert.deepEqual(await request(url),[302,url]);ready=true;break}
catch(e){await new Promise(r=>setTimeout(r,1000))}}assert(ready,'redirect unavailable');
assert.deepEqual(await request('https://unapproved.invalid'),[406,undefined]);
console.log('redirect controls passed; destinations not followed');
})().catch(e=>{console.error(e.message);process.exit(1)});
"""


class C03FixRuntime(DockerFixRuntime):
    def __init__(self, profile):
        super().__init__(profile)
        if self.config.family not in {'sql-search', 'redirect-allowlist'}:
            raise ValueError('c03_family_required')
        self.observers = []
        self.fixture = None
        self.cleanup_proof = []
        self.reporter_path = Path(__file__).with_name('c03_test_reporter.mjs')

    def _observer(self, image, command, mounts=(), network='none'):
        name = 'cft-c03-observer-' + uuid4().hex[:20]
        self.observers.append(name)
        argv = ['docker', 'run', '--pull=never', '--name', name, '--network', network,
                '--read-only', '--user=65532:65532', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--cpus=1', '--memory=256m',
                '--pids-limit=32', '--log-driver=none', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'CFT_C03_WORKER=1']
        for src, dst in mounts:
            argv += ['--mount', f'type=bind,source={src},target={dst},readonly']
        try:
            remaining = self.deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError('c03_budget_exhausted')
            return self._control([*argv, '--entrypoint', command[0], image, *command[1:]], min(50, remaining))
        finally:
            self._control(['docker', 'rm', '-f', '-v', name])

    def run(self, request):
        stage = request.parameters.get('stage')
        if (request.tool != 'fix_target_stage'
                or request.parameters != {'adapter': self.config.adapter, 'stage': stage}):
            raise ValueError('c03_stage_parameters_invalid')
        if stage == 'smoke' and self.config.family == 'redirect-allowlist':
            return self._control(['docker', 'exec', '--workdir', '/workspace/target', self.id,
                                  'node', '-e', REDIRECT_SMOKE], min(40, max(.1, self.deadline-monotonic())))
        if stage == 'c03_fixture':
            if not self.connected or self.closed:
                raise ValueError('c03_fixture_requires_started_target')
            result = self._control(['docker', 'exec', self.id, 'python3', '-c', SEED], 10)
            if result.exit_code == 0:
                self.fixture = json.loads(result.stdout)
            return result
        if stage == 'c03_http':
            if not self.connected or self.closed:
                raise ValueError('c03_observer_requires_started_target')
            with tempfile.TemporaryDirectory(prefix='cft-c03-http-') as temporary:
                inputs = Path(temporary)
                if self.config.family == 'sql-search' and self.fixture is None:
                    raise ValueError('c03_fixture_not_ready')
                (inputs / 'fixture.json').write_text(json.dumps(self.fixture), encoding='utf-8')
                return self._observer(WORKER_IMAGE, ['python', '/observer.py', self.config.family],
                    [(ROOT / 'executor/c03_http_worker.py', '/observer.py'), (inputs, '/input')], self.network)
        if stage == 'c03_source':
            load_scope()
            with tempfile.TemporaryDirectory(prefix='cft-c03-evaluator-') as temporary:
                inputs = Path(temporary)
                (inputs / 'expressions.json').write_text(json.dumps(expressions(self.profile.repository_path)), encoding='utf-8')
                result = self._observer(TARGET_IMAGE, ['/nodejs/bin/node', '/evaluator.cjs'],
                    [(inputs, '/input'), (ROOT / 'contracts/c01/evaluator.cjs', '/evaluator.cjs')])
                # The frozen C01 oracle exercises both families. Only this
                # family's complete test set applies to a one-file proposal.
                parsed = json.loads(result.stdout)
                prefix = 'sql-' if self.config.family == 'sql-search' else 'redirect-'
                tests = [t for t in parsed['tests'] if t['id'].startswith(prefix)]
                count = 6 if prefix == 'sql-' else 7
                good = (not result.timed_out and result.exit_code in {0, 1}
                        and not parsed.get('error') and len(tests) == count
                        and all(t['status'] == 'passed' for t in tests))
                load_scope()
                return replace(result, exit_code=0 if good else 1)
        result = super().run(request)
        if stage == 'tests' and not result.timed_out:
            from fix_verification.native_contract import assess_native, source_test_hashes
            accounting = assess_native(result.stdout, family=self.config.family,
                phase=getattr(self, 'phase', ''), files=source_test_hashes(self.profile.repository_path),
                raw_exit_code=result.exit_code)
            if accounting is not None:
                # Exit 0 means the operator contract passed, never that native
                # assertions passed. Raw exit and failures remain in stdout.
                return replace(result, exit_code=0, stdout=result.stdout + '\nC03 NATIVE CONTRACT '
                               + json.dumps(accounting, separators=(',', ':')))
        return result

    def close(self):
        try:
            clean = super().close()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            clean = False
        for name in self.observers:
            try:
                removed = self._control(['docker', 'rm', '-f', '-v', name])
                clean &= removed.exit_code == 0 or 'No such container' in removed.stderr
            except (OSError, RuntimeError, subprocess.SubprocessError):
                clean = False
        for name, kind in [(self.id, 'container'), (self.network, 'network'),
                           *((name, 'container') for name in self.observers)]:
            command = (['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$'] if kind == 'container'
                       else ['docker', 'network', 'ls', '-q', '--filter', 'name=^' + name + '$'])
            try:
                result = self._control(command)
                absent = result.exit_code == 0 and not result.stdout.strip()
                self.cleanup_proof.append({'kind': kind, 'name': name, 'exit_code': result.exit_code,
                                           'remaining': result.stdout.strip(), 'absent': absent})
                clean &= absent
            except (OSError, RuntimeError, subprocess.SubprocessError):
                clean = False
        return clean


class C03RedirectRuntime(B06Runtime):
    """The B06 protocol over two built C03 generations, never image overlays.

    Generations are provisioned by the same fixed DockerFixRuntime adapter and
    approved fix stages. B06 authorization, observations and verdict stay intact.
    """
    def __init__(self, profile, runtimes, output):
        if len(runtimes) != 2 or len({r.id for r in runtimes}) != 2:
            raise ValueError('c03_requires_independent_generations')
        self.profile = profile
        self.source_files = source_snapshot(profile)[1]
        self.id = 'b06-' + uuid4().hex[:20]
        self.tool = 'verify_redirect_destination'
        self.binding = FixtureExecutionBinding(fixture_id=self.id, session_id=self.id,
            target=profile.id, tool=self.tool, generations=(uuid4().hex[:16], uuid4().hex[:16]),
            source_snapshot=digest(self.source_files), profile_sha256=profile_digest(profile))
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.resources, self.setup, self.preparations = {}, {}, {}
        self.runtimes = dict(zip(self.binding.generations, runtimes, strict=True))
        self.ready, self.consumed, self.action = False, False, None
        self.records = []
        self.worker_cleanup_proofs = []
        self.deadline = min(r.deadline for r in runtimes)

    def open(self):
        try:
            for generation, runtime in self.runtimes.items():
                directory = self.output / generation
                directory.mkdir()
                (directory / 'profile.json').write_text(json.dumps({'generation': generation}), encoding='utf-8')
                worker = 'cft-c03-b06-' + generation
                self.resources[generation] = {'network': runtime.network, 'target': runtime.id, 'worker': worker}
                self.setup[generation] = 0
                self.docker(['run', '-d', '--pull=never', '--name', worker, '--network', runtime.network,
                    '--network-alias=b06-sink', '--user=65532:65532', '--read-only', '--cap-drop=ALL',
                    '--security-opt=no-new-privileges', '--memory=128m', '--cpus=1', '--pids-limit=32',
                    '--log-driver=none', '--tmpfs', '/state:rw,noexec,nosuid,size=1m,uid=65532,gid=65532,mode=0700',
                    '--env', 'CFT_B06_CONTAINER=1', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                    '--mount', f'type=bind,source={directory},target=/input,readonly',
                    '--mount', f'type=bind,source={ROOT / "executor/b06_worker.py"},target=/app/b06.py,readonly',
                    '--entrypoint', 'python', WORKER_IMAGE, '-c', 'import time; time.sleep(1800)'])
            self.ready = True
            return self
        except Exception:
            self.close()
            raise

    def _source_unchanged(self):
        return source_snapshot(self.profile)[1] == self.source_files

    def _close_generation(self, generation):
        previous = self.deadline
        self.deadline = None
        clean = False
        try:
            worker = self.resources[generation]['worker']
            removed = self.docker(['rm', '-f', '-v', worker], check=False)
            clean = removed.returncode == 0 or 'No such container' in removed.stderr
            checked = self.docker(['ps', '-aq', '--filter', 'name=^/' + worker + '$'], check=False)
            absent = checked.returncode == 0 and not checked.stdout.strip()
            self.worker_cleanup_proofs.append({'name': worker, 'exit_code': checked.returncode,
                'remaining': checked.stdout.strip(), 'absent': absent})
            clean &= absent
        except (OSError, RuntimeError, subprocess.SubprocessError):
            clean = False
        finally:
            clean &= self.runtimes[generation].close()
            self.deadline = previous
            self.persist({'phase': 'destroy', 'generation': generation, 'cleanup_complete': clean})
        return clean

    def close(self):
        self.ready = False
        results = []
        for generation in self.resources:
            try:
                results.append(self._close_generation(generation))
            except (OSError, RuntimeError, subprocess.SubprocessError):
                results.append(False)
        return len(results) == 2 and all(results)
