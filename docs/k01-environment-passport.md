# K01 environment passport

Date: 2026-10-11. Branch `codex/s01-integration-contracts`, agent HEAD
`a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e`.
Every value below was read on this machine during this task with read-only commands
(`docker info/version/ps/network ls/image inspect`, `git rev-parse/status`, local file
digests) or copied from sealed run artifacts. No credential value was read, printed or
copied into this document.

## 1. Verified platform scope

Only macOS is verified. Windows and Linux are **not** declared supported: the unit
suite runs there, but no lifecycle run was performed on them.

| Item | Verified value |
|---|---|
| OS / architecture | `macOS-26.5.2-arm64-arm-64bit-Mach-O`, Apple silicon (`aarch64`) |
| Docker client / server | `28.5.2` / `28.5.2`, daemon `os=linux arch=arm64` |
| Interpreter used for this task | `.venv/bin/python` = CPython `3.13.11` (`venv` over `/opt/miniconda3`) |
| Interpreter of the sealed K02 runs | `python3` = `3.11.9` (recorded in both K02 `attempt.json` files) |
| Semgrep | `semgrep 1.173.0` installed in `.venv` (`pip show semgrep`); the sealed K02 runs recorded `1.174.0` from the `python3` route. Both are `WARNING`-level SAST producers, never a CVSS source |
| Node inside the fix image | `NODE_VERSION=24.21.0` (from `docker image inspect` `Config.Env` of `cft-fix-juice`) |
| Node inside the target runtime image | not printed in `Config.Env`; the runtime is only ever started from the pinned image digest below |
| `python3` inside the fix image | present and exercised: the `prepare` and `start` stages run `python3 -c ...` through the image entrypoint and passed in both cycles. The exact patch version is not recorded in any artifact, so it is not claimed here |

The two interpreters are a real environment difference and is reported rather than
hidden: the sealed K02 baseline used `python3` 3.11.9, this session's lifecycle re-run
used `.venv/bin/python` 3.13.11. All tests, Ruff and both checks below were run with
`PYTHONDONTWRITEBYTECODE=1`.

## 2. Agent source identity

| Item | Value |
|---|---|
| Commit | `a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e` |
| Branch | `codex/s01-integration-contracts` (unchanged by this task, nothing committed) |
| Dirty worktree source digest | `46de52ca368d2bb81ba2dc1f10801a3053a64a22367acec6507dc1379031c157` (`evaluation.benchmark_harness.source_digest(".")`, i.e. all tracked and untracked `*.py` under the code packages plus `pyproject.toml`) |
| K02 baseline dirty digest (history) | `3ee000400c47529097b0f0a2405ed4c7a837a895e27c0757ef5333a861b4c692` — differs because the K02/K01 diagnostic code and tests added afterwards are part of the worktree, not because the target or runtime changed |

The commit alone cannot identify uncommitted code, so the digest is recorded next to it.
The worktree is intentionally not clean: another contributor's K02/R01 results, local
plan documents, unrelated `.pyc` files, `tmp/`, `output/pdf/` and `ultra-os/` are kept
as they are.

## 3. Target identity and source bytes

Both Stage 1 cycles used the same operator-provisioned, clean, LF-only clone:
`artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop`.

| Item | Value |
|---|---|
| Commit | `5658473cf8814459bf89000ce373b20ed0b4eb37` (Juice Shop v20.2.0) |
| `git status --porcelain --untracked-files=all` | empty, before and after both cycles |
| `routes/search.ts` | `sha256:de09bfc4040fc88073dbb85a7d1ef0171388abb4775eedc78578a48167853057` |
| `routes/login.ts` | `sha256:cf11d682edff6744bcb54339bce4b2dd6da5e80f9038facd7605df857b0a0b7b` |
| `routes/basket.ts` | `sha256:89dc1768e5e5b7c34ae22b753140cfe4ba529903d4d743e7fc5ef28be5b49dd3` |
| `routes/basketItems.ts` | `sha256:be2cd01e41b4fc4e2d17c661ddb32d8c2ff9be49dfa13a9c43cc872c413d90e6` |
| `server.ts` | `sha256:1774fac7f05f9f78fad0b4f82a10eaf0d2ef5b2522ddbe75133e65e423c0a90b` |
| Full snapshot tree digest | `72d28625be8887357e9c53de485f96fe3ea6c5e8719253b9318d755b4fc9a753` in both cycles |
| Operator Compose input | `docker-compose.presentation.yml` == `docs/demo/compose.yaml`, `sha256:9bc0322495a17325a92cbae3c499d1b5f04280840bc001964e29387331240f8b` |

The five file digests above were re-computed in this session and match the values
sealed in the K02 `attempt.json` exactly, so the second cycle really ran on the same
source bytes.

Separate source copies are mandatory and are used:

| Purpose | Copy | Mutated? |
|---|---|---|
| Stage 2 analysis / benchmark | `artifacts/k02-2026-10-11-stage2-5f6481c9/juice-shop` | read-only source; never patched |
| Stage 1 fix verification original | `artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop` | never patched; `original-before.json` == `original-after.json` |
| Stage 1 patch workspace | `tempfile.TemporaryDirectory(prefix="cft-fix-")` per phase, mounted read-only into the container and copied to container tmpfs | disposable, deleted by teardown |

`docs/demo/fix-verification.Dockerfile` is `sha256:cae1cfdcbdedc089b0a0a23fa8e5145068d5ac75611b9f880c20e655af4bdcef`
(unchanged since the K02 record), `targets/juice-presentation.yaml` is
`sha256:687ea7a6d4f9d9ad067cc53bf219ff012b9c21a503462b23e9a2938d2be9b0e1` (identical to
the `target_profile_sha256` sealed in the K02 `attempt.json`) and `policies/default.yaml`
is `sha256:311d8155a2b43cc065ac33c2cdea0cfc4023a5d130dce463c12c78fb3b9e3714`; the last
value equals the `policy_sha256` recorded inside both Stage 1 artifacts, so both cycles
ran under byte-identical policy.

## 4. Actual image IDs and RepoDigests

`docker image inspect` output, not registry guesses:

| Operator input | Image ID | RepoDigests |
|---|---|---|
| `bkimminich/juice-shop@sha256:8739101a…526b` | `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b` | `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b` |
| `python:3.12-alpine` (Stage 1 worker) | `sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4` | `python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4` |
| `cft-fix-juice:stage1` (locally built fix image) | `sha256:cdb8246f10e44595abddec2205aa746cfa174b9cef042e6751e0dc67631dde0d` | `cft-fix-juice@sha256:cdb8246f10e44595abddec2205aa746cfa174b9cef042e6751e0dc67631dde0d` |

`cft-fix-juice` is a local build whose reported RepoDigest equals its image ID; it was
passed to the runtime as `cft-fix-juice@sha256:cdb8246f…de0d`. Nothing was pushed to a
registry and no digest was synthesized.

## 5. Immutable reference rules (K01 prerequisite)

- `TargetFixConfig.image` accepts exactly two shapes: a repository digest
  `name@sha256:<64 lowercase hex>` or a full Docker image ID `sha256:<64 lowercase hex>`.
  Anything else — `name:tag`, `:latest`, a truncated or uppercase digest — fails
  validation before any Docker call.
- `app.stage1_e2e.pinned_image` treats a mutable tag only as operator provisioning
  input: it is resolved by an actual `docker image inspect` into the reported
  RepoDigest, or, for a local build without RepoDigests, into the real image ID. A
  missing image raises from `docker image inspect`; nothing is ever pulled, and the
  runtime always adds `--pull never`.
- The sandbox worker keeps the stricter rule: `digest_pinned_worker_image` requires a
  repository digest, because `SandboxPolicy` demands `@sha256:` in `sandbox_image`.
  A digest-less locally built worker image is therefore still unsupported; that is a
  known limitation, not something the fix silently accepts.
- Preserved security boundaries: `--pull never`, networkless `prepare`/`build`/`tests`,
  read-only source mount, internal target network only for `start`/`smoke`, per-stage
  timeout and wall-clock budget, `--user 1000:1000`, `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--pids-limit 256`, `--memory 2g`, `--cpus 2`,
  tmpfs `/workspace` 2g and `/tmp` 64m.

## 6. Verified lifecycle

Provisioning is separate from every measured cycle. Run these commands from the
agent repository with its development dependencies installed. The output directory
must not exist: reruns use a new name, never overwrite an earlier lab.

```bash
# Fresh machine: clone the exact target into separate analysis/fix copies;
# provision dependencies only inside Docker, before verification.
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.lab_prepare \
  --output artifacts/operator-lab-v20.2.0 --provision-images

# This machine: use the existing source Git database and installed images.
# Separate fresh clones are still created. No build/pull/install is implicit.
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.lab_prepare \
  --output artifacts/operator-lab-cached \
  --source artifacts/presentation-2026-10-08/juice-shop
```

`app.lab_prepare` refuses existing output, verifies the exact commit, copies the
operator Compose and excludes ONLY `/docker-compose.presentation.yml` in each new
clone's `.git/info/exclude`. It does not edit tracked `.gitignore` or ignore other
untracked changes. Both `git status` checks must be empty. `preparation.json` is
created before work and retains failed/ready preparation, source and image refs.
The two command variants above are alternatives, not commands to run over the
same directory. Explicit `--provision-images` may access the network; ordinary
verification never installs dependencies. Target source/scripts do not run on host.

The fresh-clone/cache path was actually tested at acceptance in
`artifacts/k01-acceptance-20261011/preparation.json`; both new clones are clean and
have the same pinned source bytes. A fresh-machine dependency build was performed
earlier in K02, not repeated at this acceptance. Upstream has no lockfile, so a new
build is a NEW image and must be frozen separately, not claimed byte-identical to
the historical image. Transfer of an existing image requires Docker save/load or
a real registry; our local `cft-fix-juice@sha256:…` is not a public registry download.

```bash
# start + health + reset + stop: one self-contained cycle
env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.stage1_e2e \
  --target artifacts/operator-lab-v20.2.0/fix/juice-shop \
  --worker-image python:3.12-alpine --fix-image cft-fix-juice:stage1 \
  --output-dir artifacts/operator-lab-v20.2.0/stage1-runs
```

For the cached preparation command, use `artifacts/operator-lab-cached` instead
of `artifacts/operator-lab-v20.2.0` in the last command. Each invocation creates
its own `stage1-<UUID>` directory, fresh Docker sessions, health checks, reset and
teardown. The same immutable images are reused; target sources remain unchanged.

Within one cycle the runtime sequence is, per phase:

| Step | What actually runs | Verified state |
|---|---|---|
| `prepare` | `python3` copies the read-only `/input` snapshot into tmpfs `/workspace/target`, links pinned `node_modules`, copies `frontend/dist`; the dependency manifest is byte-compared first | passed, network `none` |
| `build` | `tsc` compile in the disposable container | passed, network `none` |
| `tests` | Juice Shop unit tests through the fixed reporter | passed: 415 tests, 413 passed, 2 skipped, 0 failed |
| start (`start`) | `node build/app.js` detached inside the container, log captured to `/workspace/startup.log` | passed, container attached to the internal target network |
| health (`smoke`) | bounded HTTP probe of `/rest/products/search?q=Apple` (>0 results) and `q=cft-functional-no-such-product` (0 results) inside the container | passed |
| original verification | registered `verify_sql_injection` capability through Validator → Executor → persisted Evidence | BEFORE `confirmed`, AFTER `rejected` |
| reset / stop | `docker rm --force <session>`, `docker network rm <session>-net`; next cycle always starts a new container from the same immutable image and a fresh snapshot | `cleanup_complete=true` |

Health is an in-container HTTP check with a 1 s retry loop up to 30 attempts; startup
failure output is captured from the last 4 KiB of `startup.log` and reported as a stage
failure, never as a security verdict.

### Reset proof

`security_verified=true` already requires `original_unchanged=true` and
`cleanup_complete=true`, and each cycle re-runs the original operator SQL case from a
fresh container. Cycle 1 (sealed K02, `cft-fix-d43abb50db394d2fb61d`) and cycle 2
(`cft-fix-16c62cb3d2b94fc9bfb0`) both started from the same image ID and the same tree
digest and both returned `confirmed` for the unpatched source, which is the operator
check that state was restored after the previous teardown. This proves reproducibility
of this one verifier case, not of the whole benchmark.

## 7. Own resources and leftover check

Every resource created by this project uses a `cft-` prefix, so leftovers are easy to
detect without touching foreign containers:

| Resource | Prefix / name |
|---|---|
| Fix runtime container | `cft-fix-<20 hex>` |
| Fix runtime network (internal) | `cft-fix-<20 hex>-net` |
| Sandbox container | `cft-sandbox-<run id>`, compose project `cft-sandbox-<12 hex>` |
| Sandbox helper images/containers | `cft-target-<12 hex>`, `cft-framework-<12 hex>`, `cft-readiness-<12 hex>` |
| Shared internal network name | `cft_internal_security_net` |
| Disposable host workspaces | `cft-fix-*`, `cft-baseline-*`, `cft-sandbox-session-*` |

Read-only verification after a cycle:

```bash
docker ps -a --format '{{.ID}} {{.Names}} {{.Status}}' | grep cft-fix
docker network ls --format '{{.Name}}' | grep cft-fix
```

Both returned nothing after the second cycle, and the network list still contains no
`cft-*` network at all. `docker rm`, `docker stop` and any prune of resources that this
run did not create are out of scope: the pre-existing `cft-sandbox-sequence-*`
containers in `Created` state and `cft-sandbox-31200f14d4a6-juice-1` were already
present before this task started and were deliberately left untouched.

Logs and artifacts of each cycle are retained, never overwritten: `images.json`,
`target-profile.json`, `original-before.json`, `original-after.json`,
`confirmed-report.json`, `patch-review.json`, `fix-verification.json`,
`baseline-environment.json`, plus per-phase `evidence/execution-*.json` and
`audit.jsonl`. Old sealed directories are separate output roots and are not appended to.

Budgets: per-stage `timeout_seconds=300`, run `wall_clock_budget_seconds=1800`
(`TargetFixConfig` defaults, both unchanged), one attempt per stage inside an attempt
directory, and the Executor's own limits from `policies/default.yaml`
(`max_iterations: 5`, `memory_mb: 256`, `max_processes: 8`, `max_output_bytes: 16384`,
`max_runs_per_action: 1`, `max_concurrent_runs: 1`) still apply to sandbox capabilities.

## 8. Three different "preflight" meanings

1. Infrastructure preflight: `docker info`, `docker image inspect` of every pinned
   image, exact target commit and empty `git status`. Failure here is a
   preflight/technical state, never a security finding.
2. Neutral model probe (application adapter, no key printed):
   `env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m app.llm_probe`.
   Run on 2026-10-11: route `nsu/qwen3.8-flash-next`, `status=ready`, `ok (578ms)`.
   It asks only for a reachability note. Benchmark ground truth is never sent to a
   model.
3. Application startup: the `start` + `smoke` stages described above, inside Docker only.

The Stage 2 harness additionally has `app.stage2_benchmark --preflight-only`, which
writes `preflight.json` separating `target`, `docker`, `sast` and model errors.

## 9. Repeated lifecycle record (K01 evidence)

| Cycle | Run ID | Fix ID | BEFORE session / run | AFTER session / run | Verifier duration |
|---|---|---|---|---|---|
| 1 (sealed, K02) | `stage1-a5b899ec304240b79fae53411adcb0ec` | `fix-b762400054fb4b33bf717f60a65a8ab8` | `cft-fix-d43abb50db394d2fb61d` / `31c841d869bc47748875d5a030c3e79f` | `cft-fix-cf03cfae158846aeadb6` / `923e4f03caee4ad4b5b955a31382d7a1` | 50 544 ms |
| 2 (new, this task) | `stage1-379c3d3dd66c471bb54f722d59607dd8` | `fix-de15979160ef460f9b4fdf10ebf132da` | `cft-fix-16c62cb3d2b94fc9bfb0` / `233ecb8075b94371856950058695dd66` | `cft-fix-743144c056f3462b973b` / `3940496ecd8b476e8ca872ad8b9f5898` | 48 499 ms |

Frozen across both: target commit, tree digest, `routes/search.ts` digest, worker and fix
image references, `policies/default.yaml` digest, `targets/juice-presentation.yaml`
digest. Different by design: output directory, run/fix IDs, all six Docker sessions and
all per-stage execution/run IDs. Both: 10/10 stages passed, BEFORE `confirmed`,
AFTER `rejected`, `applied=true`, `original_unchanged=true`, `cleanup_complete=true`.

Cycle 2 spanned `07:14:42.415Z` → `07:15:53.968Z` in its own artifacts: original
confirmation `23 048 ms` (session `cft-fix-20efccd5b5154819b546`, run
`2bbb11e6706241dd90de7fb5ef1c09fb`) plus Fix Verification `48 499 ms`.

## 10. Not verified / not promised

Acceptance follow-up: the main agent prepared two new clean clones through
`app.lab_prepare` and ran Stage1 on the full immutable fix image ID. Run
`stage1-15d8f4f23b504c5d8646209d7062cec7` returned FIXED with all ten stages,
BEFORE confirmed, AFTER rejected, original unchanged and cleanup complete.
See [acceptance record](k01-k02-acceptance-2026-10-11.md). Tables above preserve
the earlier Qwen passport snapshot; they are not silently rewritten as a new run.

- Windows and Linux lifecycle support (unit tests only).
- A locally built **worker** image without RepoDigests (sandbox policy still requires a
  repository digest).
- Registry push of `cft-fix-juice`; the image is distributed by digest from this machine.
- Repeatability of the whole benchmark from one verifier case.
- Model patch generation: the Stage 1 patch is the operator `IntegrationPatchClient`,
  reviewed by strict PatchReview and verified by the real verifier.
