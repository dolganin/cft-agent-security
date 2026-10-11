# K02 — baseline replay and loss diagnostics

Date: 2026-10-11
Branch / agent HEAD at start: `codex/s01-integration-contracts` / `a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e`
Result: the requested single Stage 2 v1 run and Stage 1 verification both completed. This is one v1 sample, not the earlier three-run series and not a project-wide recall claim.

## Attempts

| Attempt ID | Official run ID | Result | Duration | Evidence |
|---|---|---|---:|---|
| `k02-2026-10-11-stage2-5f6481c9` | `run-001` | sealed, `completed`, exit 0 | harness 335.573 s; wrapper 341.509 s | [`manifest.json`](../artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output/run-001/manifest.json), [`scorecard.json`](../artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output/scorecard.json), [`diagnostic journal`](../artifacts/k02-2026-10-11-stage2-5f6481c9/current-v1-diagnostic.json) |
| `k02-2026-10-11-stage1-cd97a2e4` | `stage1-a5b899ec304240b79fae53411adcb0ec` | `FIXED`, `security_verified=true`, exit 0 | 80.234 s total; 50.544 s Fix Verification | [`fix-verification.json`](../artifacts/k02-2026-10-11-stage1-cd97a2e4/stage1-output/stage1-a5b899ec304240b79fae53411adcb0ec/fix-verification.json), [`Stage 1 diagnostic journal`](../artifacts/k02-2026-10-11-stage1-cd97a2e4/stage1-diagnostic.json) |

Attempt metadata was created before the official entrypoints ran. It retains the commands, timestamps, exit codes, durations, safe configuration, and redacted stdout/stderr: [`Stage 2 attempt`](../artifacts/k02-2026-10-11-stage2-5f6481c9/attempt.json), [`Stage 1 attempt`](../artifacts/k02-2026-10-11-stage1-cd97a2e4/attempt.json). Neither was a preflight-only result.

## Environment and frozen inputs

- Host: macOS 26.5.2 arm64; Python 3.11.9; Docker client/server 28.5.2; Semgrep 1.174.0.
- Both target clones were made from the existing `artifacts/presentation-2026-10-08/juice-shop` Git database, without using its untracked Compose file as source. Both resolve to Juice Shop commit `5658473cf8814459bf89000ce373b20ed0b4eb37`, are clean, and report `i/lf w/lf` for the benchmark source anchors. The presentation checkout remained untouched.
- Compose was copied from `docs/demo/compose.yaml` into each isolated target clone and locally excluded from its Git status as the operator-owned input required by the benchmark. The Compose SHA-256 is `9bc0322495a17325a92cbae3c499d1b5f04280840bc001964e29387331240f8b`.
- Dataset: `juice-shop-v20.2.0-v1`; one run; config digest `1c1a7ae13d87ef13ff28ab0cf9993915c05357dc68725ec402fe7d4271de65d9`; run seal `2871e0c5219a0f0f088e7baa8e3f0de2999488536510c6b63ce6f9ffb9fbf67a`. Target source manifest digest: `473c98c701bde5c31e91430dc8b21399502ac878c9aea41eae301743de99418b`. Benchmark YAML SHA-256: `fdd5182aa12aa245d10381f81c760888c2a693214357430afe53f77ff42642a4`; dataset lock SHA-256: `e8958085ca01af5168da9983a3414e2b2f047de613fb1e412a10839dc3c37362`; ground truth SHA-256: `3a13a0a41d5fd86d4ab75e23dbc7a61cc81439f034a574b9341a369c82b1aafe`; Semgrep rules SHA-256: `4df0e29cbf20a34323e07961824ff9d511980f72954e9bd7c891e64d9a699965`.
- Stage 2 model route/settings: `nsu:Qwen3.8-27B`, low reasoning, 8192 output tokens, 55 s request timeout, 2 Scout turns, 4 candidates, 2 agent iterations. Preflight had no errors; its neutral probe returned ready on `nsu/Qwen3.8-27B`. No credential value is present in the attempt or benchmark artifacts.
- Juice Shop image: `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`, image ID with the same digest. Worker: `python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`.
- Provisioning was separate from measurement and used Docker only: `docker pull python:3.12-alpine`; `docker build --pull -f docs/demo/fix-verification.Dockerfile -t cft-fix-juice:stage1 artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop`. The local fix image has the actual inspect-returned RepoDigest `cft-fix-juice@sha256:cdb8246f10e44595abddec2205aa746cfa174b9cef042e6751e0dc67631dde0d` (image ID `sha256:cdb8246f10e44595abddec2205aa746cfa174b9cef042e6751e0dc67631dde0d`); it was passed and executed by digest. No digest was synthesized. Stage 1 cleanup completed, and a subsequent read-only Docker inventory found no remaining Stage 1 container or network.
- Stage 2 manifest binds Pentester commit `a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e` and dirty worktree digest `3ee000400c47529097b0f0a2405ed4c7a837a895e27c0757ef5333a861b4c692`, plus target, profile, rules, policy, architecture, image, and runtime settings digests.

The complete per-file target source hashes and image metadata are preserved in the two `attempt.json` files. No source checkout, prior result, shared schema, policy, or runtime was modified by provisioning.

## Stage 2 v1 result

The official harness completed and sealed `run-001`. It made 46 real LLM requests, all `ok` through the configured NSU route, with no fallback notifications; 12 bounded tool actions were recorded. This run detected 5 of the 10 selected positive cases and matched no negative controls incorrectly:

| Metric | Result |
|---|---:|
| TP / FP / FN / TN | 5 / 0 / 5 / 2 |
| Precision / recall / F1 | 1.00 / 0.50 / 0.667 |
| Detected positives with supported confirmation | 4 / 5 |
| Verified recall within v1 positives | 0.40 |
| False confirmations | 0 |
| Final reports | 10: 4 `confirmed`, 6 `inconclusive` |

Recall is relative only to the frozen, non-exhaustive v1 set. The 5 false negatives are `JS-ACCESS-001`, `JS-ACCESS-002`, `JS-AUTH-001`, `JS-CODE-001`, and `JS-REDIRECT-001`. The frozen Semgrep profile contains the SQL interpolation and directory-listing rules; those five cases have no matching raw SAST result, and Scout did not add a matching candidate. This is observed rule/candidate coverage for this configuration, not a Validator or Executor denial.

The other five unmatched observations are two directory anchors outside the labeled positives (`server.ts:268`, `:292`) and three Scout candidates (`forgot-password` email disclosure, client-supplied role at `routes/verify.ts:52`, and JWT `none` algorithm at `routes/verify.ts:86`). They remain outside ground truth, not false positives.

### SQL and directory lineage

The diagnostic journal groups raw Semgrep records with normalized findings by exact file/line anchors, carries source provenance aliases, and joins approved action summaries to audit, execution, persisted Evidence, and reports. `missing` means the corresponding artifact was not present; it does not assert that a workflow node never ran.

| Finding | Binding and action | Validator / execution / Evidence | Final result |
|---|---|---|---|
| `routes/search.ts:23` | `/rest/products/search`; `action-sequelize-injection.presentation:routes-search.ts:23-ff78e2e4b9d5671e-1` | approved; execution `execution-96b80b6bd2084ad0b8985ced1ada1ff3`, run `03f9c9c450e64e479028df755084068b`, session `eb424b31ca9b43c4b128508f73649fe9`; persisted high-reliability runtime Evidence | `confirmed`, `JS-SQL-001` |
| `server.ts:288` | `/ftp`; `action-directory-listing.presentation:server.ts:288-c5fa181ec4e54a0e-1` | approved; execution `execution-96c417bb26a144858246292617137777`, run `fb6e47ece42441dbb80007a6cf9248d0`, same benchmark session; Evidence confirms names only, no file contents read | `confirmed`, `JS-FILE-001` |
| `server.ts:296` | `/encryptionkeys`; `action-directory-listing.presentation:server.ts:296-459027fbd3defc5c-1` | approved; execution `execution-bf8f73645cd347229b079864624f1aab`, run `8231d0919fe24d84885c22e2c96eeda7`; Evidence confirms filename enumeration only | `confirmed`, `JS-FILE-002` |
| `server.ts:268` | source artifact bound to `server.ts:268`; metadata-only action `action-directory-listing.presentation:server.ts:268-e90345d0fd929ff1-1` | approved; execution `execution-a4f0a674329646ad9e4a5d5f196d0ea9`; Evidence states `runtime_verified=false` | `inconclusive`; no endpoint runtime proof |
| `server.ts:292` | `/.well-known`; runtime check saw a directory listing but no sensitive names; iteration 2 was source metadata only | approved; persisted execution/Evidence; no timeout or policy denial | `inconclusive`, `insufficient_evidence` |
| `server.ts:300` | `/support/logs`; runtime check saw a directory listing but no sensitive names; iteration 2 was source metadata only | approved; persisted execution/Evidence; no timeout or policy denial | `inconclusive`, `insufficient_evidence` |

The six inconclusive reports all state `insufficient_evidence`; none is a technical timeout or Validator denial. Three are Scout-only candidates whose registered `inspect_javascript_security` action returned source metadata, which the report explicitly does not treat as proof of exploitability. For `server.ts:292` and `:300`, the bounded runtime observation was not truncated and read no file contents; it found no sensitive filenames, so it correctly did not claim `rejected` or `confirmed`. These are evidence/capability limits, not permission failures.

For all SQL/file lineages, the saved artifacts contain action summaries and action IDs but do not contain a standalone canonical `ActionProposal` with its full fields (`iteration`, parameters, purpose, expected evidence, service and endpoint). The journal therefore marks the ActionProposal artifact `missing`; it does not reconstruct one from executor command output. This is an unresolved artifact/provenance gap, not proof that Validator was bypassed: the associated audit entries show approved actions and the Executor records show the matching executions. See `current-v1-diagnostic.json` for every observation and file link.

## Stage 1 result and limits

The Stage 1 attempt used a second clean LF clone and the existing `app.stage1_e2e` command. It returned `FIXED`, `security_verified=true`, `applied=true`, `original_unchanged=true`, and `cleanup_complete=true`. All ten required stages passed: prepare, build, tests, start, and smoke both BEFORE and AFTER.

- Stage1 workflow run: `stage1-a5b899ec304240b79fae53411adcb0ec`.
- Fix artifact: `fix-b762400054fb4b33bf717f60a65a8ab8`.
- Original confirmation action/run/session: `baseline-5f3c672b10c94c609514426a3dc35876-before-security` / `6860519882774755850dca8704898418` / `cft-fix-14a3a5c8b6c548289d6b`.
- Fix BEFORE: `fix-b762400054fb4b33bf717f60a65a8ab8-before-security`, confirmed, session `cft-fix-d43abb50db394d2fb61d`, run `31c841d869bc47748875d5a030c3e79f`.
- Fix AFTER: `fix-b762400054fb4b33bf717f60a65a8ab8-after-security`, rejected, session `cft-fix-cf03cfae158846aeadb6`, run `923e4f03caee4ad4b5b955a31382d7a1`.
- Original source SHA-256 before/after: `de09bfc4040fc88073dbb85a7d1ef0171388abb4775eedc78578a48167853057`; tree SHA-256 before/after: `72d28625be8887357e9c53de485f96fe3ea6c5e8719253b9318d755b4fc9a753`; both Git status strings are empty.
- The proposal came from the entrypoint's operator `IntegrationPatchClient`, passed through strict PatchReview, then the real verifier. It was not generated by an LLM. This run establishes that the Stage 1 verifier can validate this operator SQL patch; it says nothing about model patch-generation ability.

The Stage 1 diagnostic journal finds the report, trusted endpoint/source binding, validator audit, execution records, and persisted BEFORE/AFTER Evidence. Raw SAST input and a serialized canonical ActionProposal are absent from this Stage1 artifact set: its original finding is an explicit `integration_fixture`. That is consistent with Stage1's verifier integration scope, not a missing live verifier step.

## Archived Evidence compatibility check

The four existing files under `artifacts/security-pipeline/reports/` each contain one Evidence object that fails current `schemas.evidence.Evidence` validation. Each omits required `source`, `hypothesis_id`, `action`, `observation`, and `scope`, and includes forbidden `details`. Their referenced execution JSON paths are absent. The diagnostic recorded four schema failures and did not migrate or fabricate action, approval, session, or Evidence fields. This is an archived schema mismatch, not a failure from either new live run. The machine-readable results are in [`legacy-reports-diagnostic.json`](../artifacts/k02-2026-10-11-stage2-5f6481c9/legacy-reports-diagnostic.json).

## Reproduction commands

Provisioning, already completed separately:

```bash
git -c core.autocrlf=false clone --no-local --branch v20.2.0 --depth 1 \
  artifacts/presentation-2026-10-08/juice-shop \
  artifacts/k02-2026-10-11-stage2-5f6481c9/juice-shop
cp docs/demo/compose.yaml \
  artifacts/k02-2026-10-11-stage2-5f6481c9/juice-shop/docker-compose.presentation.yml
docker pull python:3.12-alpine
```

Stage 2 v1 replay:

```bash
env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 python3 -m app.stage2_benchmark \
  --dataset juice-shop-v20.2.0-v1 --runs 1 \
  --target artifacts/k02-2026-10-11-stage2-5f6481c9/juice-shop \
  --output artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output
PYTHONDONTWRITEBYTECODE=1 python3 benchmarks/juice-shop-v20.2.0/scorecard.py \
  --output artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output
```

Stage 1 provisioning and verification:

```bash
git -c core.autocrlf=false clone --no-local --branch v20.2.0 --depth 1 \
  artifacts/presentation-2026-10-08/juice-shop \
  artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop
cp docs/demo/compose.yaml \
  artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop/docker-compose.presentation.yml
docker build --pull -f docs/demo/fix-verification.Dockerfile \
  -t cft-fix-juice:stage1 artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop
env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 python3 -m app.stage1_e2e \
  --target artifacts/k02-2026-10-11-stage1-cd97a2e4/juice-shop \
  --worker-image python:3.12-alpine --fix-image cft-fix-juice:stage1 \
  --output-dir artifacts/k02-2026-10-11-stage1-cd97a2e4/stage1-output
```

The diagnostic CLI is read-only except for its explicitly selected JSON output. For example:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m app.baseline_diagnostics diagnose \
  --artifacts artifacts/k02-2026-10-11-stage2-5f6481c9/stage2-output/run-001 \
  --target juice-shop-v20.2.0 \
  --output artifacts/k02-2026-10-11-stage2-5f6481c9/current-v1-diagnostic.json
```

## Checks and remaining limits

- `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/test_baseline_diagnostics.py -q`: **16 passed**. The fixtures are synthetic and do not count as Juice Shop runs.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m ruff check evaluation/baseline_diagnostics.py app/baseline_diagnostics.py tests/test_baseline_diagnostics.py`: passed.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m app.baseline_diagnostics --help`: passed; `git diff --check`: passed.
- No blocker prevented either requested real replay. The benchmark is one run by instruction; stability across repeated v1 runs remains unmeasured. Five defined positive cases were not detected, six observations ended inconclusive, and full project recall is not inferred. The standalone ActionProposal serialization gap remains unresolved and is reported rather than repaired in shared runtime.

## Follow-up hardening and artifact re-check (same day)

The claims above were re-verified directly against the sealed artifacts, not rewritten:

- `run-001/seal.json` contains exactly 47 file digests; `run-001/pipeline/reports/`
  contains exactly 10 reports; `scorecard.json` keeps `tp/fp/fn/tn = 5/0/5/2`,
  detection `recall = 0.5`, `verified_positives = 4` and `verified_recall = 0.4`.
  Recall by confirmation is `0.4`, never `0.5`.
- The Stage 1 artifact set still reports `status=FIXED`, `security_verified=true`,
  `applied=true`, `original_unchanged=true`, `cleanup_complete=true`, ten `passed`
  stages, BEFORE `confirmed` / AFTER `rejected`, and
  `original-before.json == original-after.json`.
- A secret-shaped-text scan over both `attempt.json` files and their captured
  stdout/stderr found nothing to redact. No historical report, attempt or seal was
  modified; the missing canonical `ActionProposal` stays `missing`.

Two diagnostic-code gaps were closed in `evaluation/baseline_diagnostics.py`:

1. `subprocess.Popen` used to raise straight through `run_attempt_stage`, leaving the
   event and the whole attempt in `RUNNING` with no journal. A missing executable, an
   inaccessible `cwd` or any other process-creation `OSError` is now recorded with its
   own timestamp, duration and redacted error text, `exit_code=null`, a separate
   `launch_failure=true` flag and the explicit `FAILED` / `PREFLIGHT_FAILED` status, so
   it is neither a timeout nor a security result. The `run` CLI exits non-zero (2) for
   it and no attempt is left in `RUNNING`.
2. `--stage` is now validated as a plain file-name token (no `/`, `\`, `..`, absolute
   path, whitespace, and at most 64 characters) before anything is written, so stage
   stdout/stderr cannot escape the attempt directory. Recorded attempt configuration is
   passed through recursive redaction, including credential-named fields, in addition to
   the existing command/output redaction.

This stays an operator-owned diagnostic wrapper around existing entrypoints: it is not
registered in the Executor, is not reachable from the reasoning model, and validates no
security decision.

Targeted re-run after the change:
`PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/test_baseline_diagnostics.py -q` →
**30 passed** (synthetic fixtures only). K01 lifecycle re-verification and the
environment passport are recorded in
[`k01-environment-passport.md`](k01-environment-passport.md); the second real Stage 1
cycle is `stage1-379c3d3dd66c471bb54f722d59607dd8`.
