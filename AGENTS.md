# AGENTS.md

## 0. Purpose

This file is the canonical implementation context for coding agents and contributors working on `cft-security-agent`.

Before changing shared schemas, `LangGraph`, the reasoning layer, scoring, `Validator`, `Executor`, Evidence handling, tools or SberLab integration, read this file.

Priority of truth:

```text
working code + tests
→ current Miro architecture / workflow
→ AGENTS.md
→ README.md
```

If implementation and documentation diverge, preserve the security invariants first, then synchronize documentation.

---

# 1. Project goal

Task:

**«ИИ-агент для поиска уязвимостей в ПО в CI/CD-контуре».**

The system combines:

1. contextual vulnerability scoring;
2. a bounded agent workflow for controlled verification.

High-level flow:

```text
Developer / PR
→ CI/CD
→ SAST
→ contextual scoring
→ pentest agent
→ Validator
→ Executor
→ Evidence
→ FinalReport
→ CI/CD decision
```

---

# 2. Miro is the visual architecture reference

Board:

```text
https://miro.com/app/board/uXjVHztE6Mg=/
```

Architecture frame v0.2:

```text
https://miro.com/app/board/uXjVHztE6Mg=/?moveToWidget=3458764680317736055
```

Agent workflow frame v0.1:

```text
https://miro.com/app/board/uXjVHztE6Mg=/?moveToWidget=3458764680324185356
```

Kanban:

```text
https://miro.com/app/board/uXjVHztE6Mg=/?moveToWidget=3458764680554208524
```

README diagrams under `docs/diagrams/` must preserve the same logical blocks and connections as these Miro frames. Styling may differ; topology must not.

---

# 3. Exact architecture represented in Miro v0.2

## 3.1. Main pipeline

```text
Разработчик / PR
→ CI/CD-пайплайн
→ SAST-анализ
→ Контекстная оценка
→ Агент-пентестер
→ Валидатор
```

Validator branches:

```text
APPROVE
→ Исполнитель
→ Доказательства / результаты
→ Агент-пентестер
```

and:

```text
DENY
→ Отклонено политикой
→ Финальный отчёт
```

Evidence/results also go to:

```text
Доказательства / результаты
→ Финальный отчёт
```

Final output:

```text
Финальный отчёт
→ Решение для CI/CD
→ CI/CD-пайплайн
```

## 3.2. Supporting inputs

```text
Архитектурный граф
→ Контекстная оценка
```

```text
Репозиторий / код
→ Агент-пентестер
```

```text
Политика разрешений
→ Валидатор
```

## 3.3. Architecture labels

The Miro architecture currently contains these named blocks:

```text
Архитектурный граф
Репозиторий / код
Политика разрешений
Разработчик / PR
CI/CD-пайплайн
SAST-анализ
Контекстная оценка
Агент-пентестер
Валидатор
Исполнитель
Доказательства / результаты
Отклонено политикой
Финальный отчёт
Решение для CI/CD
```

Do not silently add another execution path that bypasses this structure.

---

# 4. Exact agent workflow represented in Miro v0.1

Main sequence:

```text
Состояние агента
→ 1. Загрузка контекста
→ 2. Анализ и приоритизация
→ 3. Формирование гипотезы
→ 4. План проверки
→ 5. Валидатор
```

Approved branch:

```text
5. Валидатор
→ APPROVE
→ 6. Исполнение
→ 7. Сбор evidence
→ 8. Переоценка
→ 9. Стоп-условие?
```

Stop condition:

```text
ДА, завершить
→ Финальный отчёт
```

or:

```text
ещё одна итерация
→ 3. Формирование гипотезы
```

Denied branch:

```text
5. Валидатор
→ DENY
→ Policy blocked
→ Финальный отчёт
```

Tool inputs:

```text
Инструменты чтения
→ 1. Загрузка контекста
```

```text
Инструменты оценки
→ 2. Анализ и приоритизация
```

```text
Инструменты проверки
→ 6. Исполнение
```

---

# 5. Miro ↔ implementation mapping

The code does not need to use the same human-facing labels, but it must preserve the same semantics.

| Miro step | Current implementation |
|---|---|
| Состояние агента | `AgentState` |
| 1. Загрузка контекста | `load_context` |
| 2. Анализ и приоритизация | `score_finding` + `analyse` |
| 3. Формирование гипотезы | `form_hypothesis` |
| 4. План проверки | `propose_action` |
| 5. Валидатор | `validate_action` |
| 6. Исполнение | `execute_action` / graph node `execute` |
| 7. Сбор evidence | `collect_evidence` |
| 8. Переоценка | `reevaluate` |
| 9. Стоп-условие | conditional edge after `reevaluate` |
| Финальный отчёт | `build_report` / graph node `report` |
| Policy blocked | `status="policy_blocked"` → `report` |

Current graph implementation may loop from `reevaluate` to `analyse`; the conceptual Miro loop points to hypothesis formation. When the reasoning nodes become real LLM-backed components, keep the logical behavior aligned: a new iteration must reconsider the hypothesis/proposal using accumulated evidence.

---

# 6. Core security invariants

The architecture is built around one rule:

```text
Agent думает
Validator разрешает
Executor выполняет
Evidence определяет результат
```

Mandatory invariants:

1. Raw command execution is allowed only through `sandbox_command` inside the disposable Docker lab, never on the host.
2. Agent never directly invokes an execution capability.
3. Every active `ActionProposal` passes through `Validator`.
4. `Validator` decisions are deterministic code/policy, not prompt-only rules.
5. `Executor` can run only registered capabilities; `sandbox_command` is the intentionally broad capability whose safety boundary is Docker isolation rather than a concrete command allowlist.
6. Generic sandbox commands have no arbitrary network access; target network observations use trusted runtime capabilities.
7. `confirmed` requires Evidence.
8. Agent cannot expand target scope.
9. Active checks run only against approved local / sandbox / staging environments.
10. The workflow has step and wall-clock limits.
11. Production target access is out of scope for the MVP.

---

# 7. Shared contracts

Canonical project models:

```text
Finding
ArchitectureContext
CVSSResult
ContextPriority
AnalysisResult
Hypothesis
ActionProposal
ValidationResult
ExecutionResult
Evidence
ReevaluationResult
FinalReport
AgentState
```

They live in `schemas/`.

Do not create component-local duplicates of these contracts.

If a component needs additional data, first check whether the existing contract can express it. Shared schema changes must consider every consumer.

---

# 8. AgentState

Current state fields:

```text
finding
code_context
architecture_context

cvss
context_priority

analysis
hypothesis
dynamic_plan
plan_history
proposed_action

validation
execution
evidence
action_history
decision_history

status
stop_reason
iteration_count
max_steps
started_at
wall_clock_budget_seconds
sandbox_session_id

final_report
```

`AgentState` is the shared memory of a single workflow run.

Do not store provider-specific live SDK objects or non-serializable runtime handles in state.

---

# 9. Current LangGraph implementation

Current executable topology:

```text
START
→ load_context
→ score_finding
→ analyse
→ form_hypothesis
→ propose_action
→ validate_action
```

Validation branch:

```text
approved
→ execute
→ collect_evidence
→ reevaluate
```

```text
denied
→ report
→ END
```

Re-evaluation branch:

```text
continue
→ budget guard
→ analyse accumulated Evidence
→ fresh hypothesis / DynamicPlan
```

```text
terminal status
→ report
→ END
```

Terminal statuses:

```text
confirmed
rejected
inconclusive
policy_blocked
```

The code is a testable implementation of the Miro workflow. Human-facing README diagrams mirror Miro; implementation names remain code-oriented.

---

# 10. Reasoning layer

`agent/model.py` defines the `AgentReasoningModel` protocol.

Methods:

```text
analyse(state) -> AnalysisResult

form_hypothesis(
    state,
    analysis,
) -> Hypothesis

propose_action(
    state,
    analysis,
    hypothesis,
) -> ActionProposal

reevaluate(state) -> ReevaluationResult
```

Current implementations:

```text
DeterministicAgentModel
FallbackLLMAgentModel
```

`DeterministicAgentModel` remains the default for local tests. `FallbackLLMAgentModel`
uses a provider-diverse API route chain and validates every model response against
the existing Pydantic schemas before it reaches LangGraph. Target, environment,
action id and iteration remain deterministic application fields. A provider or model
failure may trigger fallback, but no provider can bypass Validator or Executor policy.

Do not rewrite LangGraph nodes around a provider SDK.

RepositoryScout additionally performs bounded read-only source exploration before
the finding workflows. It reads numbered application-source windows from the trusted
Discovery inventory, follows model-selected read/literal-search requests and reports
its coverage and stopping reason. Candidates must anchor read lines and read-file
provenance. They merge into the canonical Finding queue and remain unverified until
the existing Validator/Executor/Evidence workflow. See `docs/source-scout.md` for
budgets, exclusions and the standalone source-exploration command.

---

# 11. System prompt

`agent/prompts.py` defines behavioral rules for the reasoning model.

It must contain:

- mission;
- allowed information sources;
- separation of facts vs assumptions;
- hypothesis requirements;
- `ActionProposal` requirements;
- no direct execution;
- scope/policy constraints;
- Evidence requirements;
- stop conditions;
- terminal output rules.

The prompt is not a security boundary.

Security boundaries are:

```text
Validator
Policy
Executor registry
Docker sandbox isolation
Network/scope rules
Runtime limits
```

---

# 12. Scoring

## 12.1. CVSS 4.0

Purpose:

```text
technical severity
```

Final implementation must return:

```text
vector
score
severity
reasoning
```

The final numeric score must be produced by deterministic code/library.

The LLM may help propose justified metric values, but it must not invent the final score.

Current scoring integration v0.1:

```text
Docker missing-user hardening finding -> CVSS N/A, score=null
other findings without explicit metrics -> UNASSESSED
Semgrep ERROR/WARNING -> never converted directly into CVSS
```

The generic numeric CVSS calculator is still pending explicit metric inputs.

## 12.2. Context Priority

Purpose:

```text
importance of the finding in this architecture
```

Current Miro design by Лёха considers signals such as:

```text
public exposure
asset criticality
database access
path to critical services
authentication / privileges
blast radius
```

Keep CVSS and Context Priority separate.

Do not add them together into a synthetic score.

Context Priority v0.1 is now deterministic code. It scores explicit architecture
facts using the current project weights and records each contribution in
`ContextPriority.reasons`. Unknown authentication/blast-radius facts remain explicit
and contribute zero rather than being guessed.

---

# 13. Validator

Expected input:

```text
ActionProposal
```

Expected output:

```text
ValidationResult
```

The final Validator should enforce at least:

```text
target allowlist
tool allowlist
environment restrictions
scope
required parameters
time limits
iteration / run limits
logging requirements
blocked action classes
```

The starter validator currently proves the interface and deny path; Рома's policy work should replace/extend it without changing the graph boundary.

---

# 14. Executor

Executor responsibilities:

```text
receive approved ActionProposal
verify approval matches action_id
resolve registered capability
execute inside allowed environment
return structured ExecutionResult
```

Executor must not:

```text
plan
reinterpret the goal
execute sandbox_command outside the Docker security boundary
execute unknown tools
bypass Validator
```

Current implementation keeps `safe_noop` as a deterministic graph stub and exposes
operational runtime checks plus three reusable source-verification capability classes:

```text
observe_http_surface
sandbox_command
inspect_dockerfile_user
inspect_python_password_assignment
inspect_react_dangerous_html_flow
```

`inspect_dockerfile_user` covers both backend and frontend Dockerfile findings through
operator-owned artifact ids. `inspect_python_password_assignment` uses bounded Python AST
inspection and never emits password literal values. `inspect_react_dangerous_html_flow`
performs a static source-flow check only; it does not execute browser content.

Source-verification capabilities accept stable artifact ids rather than repository paths.
`targets/sberlab.yaml` owns the id -> relative-path mapping, Executor passes that trusted
registry to the fixed worker, and the worker re-validates path containment before reading.

The implementation also binds approval to a digest of the complete
ActionProposal, checks the configured target environment and launches only the
fixed `executor/worker.py` in a disposable working directory. Linux/WSL runs
receive wall-time, CPU, memory, file-size and process-count limits. Output is
bounded, every decision gets persistent JSON evidence and a JSONL audit event,
and exact `action_id` replay/concurrent runs are limited. It still does not accept
arbitrary URLs or host paths from the agent. `sandbox_command` is the deliberate
exception for generic argv: it is Docker-only, networkless, bounded and receives the
target repository read-only at `/target`.

---

# 15. Evidence

Evidence is the bridge from execution back to reasoning.

Expected terminal logic:

```text
confirmed     -> sufficient supporting evidence
rejected      -> sufficient contradicting evidence
inconclusive  -> evidence remains insufficient
policy_blocked -> required action was denied
```

Capability-specific Evidence may carry a deterministic `verdict` plus structured details.
For the first Dockerfile case, `confirmed` means only that the reported source condition is
present; it does not claim that runtime UID 0 was observed.

An LLM conclusion alone is not Evidence.

---

# 16. Target v1: SberLab

SberLab is the first controlled target.

Agent and target remain separate:

```text
workspace/
├── cft-security-agent/
└── sberlab-target/
```

Rules:

1. Do not move agent logic into SberLab.
2. Do not intentionally inject vulnerabilities for the demo.
3. Active checks are local/test only.
4. Runtime stabilization should not rewrite security-sensitive application behavior unnecessarily.
5. Target metadata belongs in `targets/`.

---

# 17. Current Miro Kanban snapshot

Miro is the source of truth for current team status.

## Done

### Ставр

```text
Создать skeleton cft-security-agent
Описать AgentState и LangGraph workflow
Системный промпт агента
```

### Лёха

```text
Разобраться с CVSS 4.0
Спроектировать Context Priority
```

### Общее

```text
Зафиксировать SberLab как Target v1
```

## In progress

### Кирилл

```text
Стабильно поднять SberLab в Docker
```

## To do / blocked by dependencies

### Ставр

```text
Зафиксировать контракты tools
Собрать один сквозной демо-проход
```

### Рома

```text
Спроектировать Validator / permission policy
Определить критерии Evidence
Составить список security tools
```

### Кирилл

```text
Набросать CI/CD интеграцию
```

### Лёха

```text
Разобрать 3–5 findings из SberLab
```

### Общее

```text
Выбрать 1 finding для end-to-end сценария
Собрать Architecture v0.3 в Miro
```

Dependency notes:

```text
SberLab Docker
→ first SAST
→ 3–5 real findings
→ choose demo finding
→ integrate scoring / validator / executor
→ end-to-end
→ Architecture v0.3
```

---

# 18. Team ownership

```text
Ставр
  AgentState
  LangGraph
  reasoning/model layer
  shared integration
  tool contracts after security inputs are known

Лёха
  CVSS 4.0
  Context Priority
  scoring examples on real findings
  later scoring implementation

Рома
  Validator permission policy
  Evidence criteria
  security tool list

Кирилл
  SberLab Docker/runtime
  Executor
  execution limits/logging
  CI/CD sketch
```

---

# 19. Git workflow

`main` is the stable shared base.

Flow:

```text
main
→ feature/<task>
→ implementation
→ tests
→ Pull Request
→ review
→ merge
→ main
```

Rules:

1. New branches start from up-to-date `main`.
2. Do not keep completed feature branches unmerged without reason.
3. Run the full test suite before merge.
4. Changes to shared schemas require awareness of downstream consumers.
5. Each contributor should deliver their component through the shared contracts rather than inventing a parallel interface.

---

# 20. Tests

Local checks:

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

The exact test count changes as features are added. A merge requires the full
suite, Ruff and `python -m app.main` to pass; platform-only skips must be listed.

Covered behavior:

```text
safe Executor roundtrip
missing approval denial
denied validation cannot create approval
proposal mutation after approval denial
approval/action id mismatch denial
unknown tool denial
production environment denial
generic allowlisted HTTP runtime observation
arbitrary parameter denial
execution evidence persistence
separate disposable working directory
wall timeout with process-group termination
POSIX CPU/memory/file/process limits
stdout/stderr/exit-code collection
per-action and concurrent run limits
JSONL audit logging
agent readback of persisted evidence
timeout recovery without pipeline failure
repeated failure clean stop at iteration limit
confirmed workflow
rejected workflow
policy_blocked workflow
inconclusive loop
structured deterministic analysis
deterministic ActionProposal
system prompt security boundaries
```

Manual graph check:

```bash
python3 -m app.main
```

---

# 21. Next development order

Current MVP delivery order (11 October 2026) is maintained in
`docs/mvp-three-stage-plan-2026-10-11.md` and its linked Miro A/B/C cards:
benchmark and baseline metrics first, improved detection/verification second,
model-generated independently verified fixes third. Each stage produces a
standalone report; completion of all historical role-based tasks is not required
before the first metrics delivery. The historical SberLab order below remains
background context, not the active team queue. Security invariants still apply.

Current search/verification work is specialized for the pinned Juice Shop corpus
at the user's direction: `docs/juice-shop-metrics-maximization-plan-2026-10-15.md`.
Its J01–J10 sequence supersedes generic research expansion for this stage.
Cross-project generalization is secondary. Frozen matching, proof scope and actual
Evidence remain required; the known corpus is a development target, not an unseen
holdout. Fix automation/MTTR follows measured detection and verification progress.

Current correct order:

```text
1. Keep merged Agent/LangGraph/model work stable in main.
2. Finish SberLab Docker/runtime.
3. Finish Validator policy, Evidence criteria and security tool list.
4. Run first SAST against SberLab.
5. Review 3–5 real findings.
6. Keep Context Priority v0.1 and CVSS applicability semantics stable.
7. Use the backend Docker missing-user finding as the first controlled E2E candidate.
8. Keep capability-specific Evidence semantics stable: source checks must not overclaim runtime proof.
9. Use reusable capability classes rather than one-off finding-specific tools.
10. Run all four current SberLab findings through the mapped bounded verification strategies.
11. Exercise and tune the real multi-provider LLM adapter behind AgentReasoningModel.
12. Update Architecture v0.3 in Miro from the working system.
```

Do not invent new architecture work merely to fill waiting time. Integrate only when the required component is ready.

---

# 22. Explicit non-goals for the MVP

Do not add without a concrete need:

```text
multi-agent architecture
GNN
Kubernetes
vector database
large RAG pipeline
large pentest tool catalog
arbitrary code execution
production attack automation
production target access
```

The MVP is one understandable, reproducible, safe end-to-end case.

---

# 23. Definition of Done

The MVP is complete when one real SberLab finding passes:

```text
SAST
→ Finding
→ Code Context
→ Architecture Context
→ CVSS
→ Context Priority
→ AnalysisResult
→ Hypothesis
→ ActionProposal
→ ValidationResult
→ ExecutionResult
→ Evidence
→ Re-evaluation
→ FinalReport
```

and:

```text
every active action passed Validator
Executor used only registered capabilities
terminal result is supported by Evidence
the run is reproducible
every step is explainable during the demo
```

---

# 24. Service API v1 (T23)

The service API is an orchestration layer around the canonical CI pipeline, not a second implementation.

Invariant:

```text
POST /runs
→ registered TargetProfile
→ app.ci_pipeline.run_ci_pipeline
→ existing artifacts / FinalReport / Gate
→ SQLite metadata index
```

Rules:

1. API callers select only a registered `target_id`; they cannot supply arbitrary repository/profile paths.
2. Trusted profile paths stay under the configured `targets/` root.
3. SQLite stores Run/Project/Finding/Evidence metadata; large logs, telemetry and report artifacts stay on disk.
4. API responses must not leak local artifact-directory paths.
5. Security Gate semantics remain unchanged: exit `1` is a completed security/policy failure, exit `2` is a technical pipeline failure.
6. T23 deliberately uses one background worker. Parallel runs, cancellation and shared sandbox quotas belong to T29.
7. UI work in T24 consumes this API; it must not bypass the canonical pipeline or read executor internals directly.

---

# 25. Fix Verification — Stage 1

`FixVerificationService` verifies only evidence-backed confirmed findings and
strict `PatchReviewArtifact` proposals. It freezes inputs, binds source/proposal
digests, creates a bounded disposable snapshot, reproduces the original runtime
capability, applies the reviewed patch only in the snapshot, and repeats build,
required tests, startup/smoke and the exact original verification binding.

`fix_target_stage` is a registered deterministic capability. Validator allows
only operator-owned adapter/stage identifiers; model argv, URLs and host paths
are not accepted. Its Docker adapter mounts the snapshot read-only and creates
the writable application copy in container tmpfs. Build/tests are networkless;
startup and original runtime verification use an internal target network.

`security_verified=true` requires BEFORE confirmed, AFTER explicitly rejected,
all required stages passed, matching persisted execution/audit Evidence,
original integrity and successful cleanup. Absence of confirmation alone is
inconclusive. Fix artifacts never mutate the original report or CI Gate.

Real Juice Shop SQL integration: `python -m app.stage1_e2e`. Prerequisites and
operator config are in `docs/demo/README.md`; final results and limitations are
in `docs/stage1-fix-verification-report.md`. The opt-in Docker integration test
in `tests/test_stage1_e2e.py` runs two independent cycles. Benchmark, DAST, new
security capabilities and PR automation remain outside this stage.

Operator provisioning: `python -m app.lab_prepare` creates separate pinned
analysis/fix clones, excludes only the operator Compose in Git's local excludes,
and records preparation before measurement. Docker pull/build requires the
explicit `--provision-images` option; target scripts never run on the host.
Fix images accept installed repository digests or full immutable Docker image
IDs; mutable tags are resolved before runtime. Sandbox worker policy still
requires repository digests. See `docs/k01-environment-passport.md`.

`docs/r01-verification-specifications.md` and `contracts/examples/r01/` define
future capability acceptance criteria and synthetic examples, NOT newly enabled
tools or runtime Evidence. They cannot expand target or execution permissions.

---

# 26. B01 operator verification binding

Stage B uses `targets/juice-verification.yaml` and its typed `verification_routes`.
Keep historical A01–A08 profiles, settings and locks unchanged. Routes/handler IDs
and caller/helper selectors are operator inputs, never model-generated permission.
`security/verification_binding.py` resolves canonical paths and actual TypeScript/TSX
AST ranges, rejects ambiguity as inconclusive and only relocates an archived finding
through its unique exact read anchor. Never choose the first ambiguous route.

`ActionProposal.verification_binding` is application-owned provenance. Validator
and Executor recompute it; approval covers it. RuntimeServiceMap binds the source
inventory of the managed session. Source/map mutations or a snapshot mismatch
must not produce confirmed/rejected Evidence. Persisted Evidence binds the approved
action digest, snapshot and endpoint; FinalReport exposes binding diagnostics.
This is not independent binary/source attestation or permission to expand scope.

`python -m app.binding_acceptance --output <new-directory>` is the fixed opt-in
Docker acceptance: existing search/login SQL and FTP capabilities, before/after
line insertion, immutable target, raw source snapshots, audit and cleanup checks.
No target code runs on the host and no LLM is required. Scope, test results and
B01 limitations are in `docs/b01-reliable-verification-binding.md`.

---

# 27. B04 operator-owned access fixtures

`targets/juice-access-fixture.yaml` defines two customer roles, five explicitly owned
objects and owner-only read/update expectations. `AccessFixtureLab` is operator
provisioning, not an agent tool or a replacement verification pipeline. Never store
its live broker or session material in AgentState. The public `AccessFixtureContext`
in `schemas/access_fixture.py` contains only registry IDs and redacted server facts.

The fixed Docker-only worker proves server identity through whoami, verifies object
ownership through independent owner reads, and brackets reads with identity checks.
The separate negative-control object must remain owner-readable before and after
the other role's denial. HTTP 200 without the expected identity, lost/swapped session,
unknown ownership or failed controls must remain inconclusive, never a safe verdict.

Passwords/tokens remain in non-root worker private tmpfs. No model credentials,
URLs, preparation operations or arbitrary writes are accepted. Reset destroys and
audits this lab's containers/anonymous volumes/network and rotates its generation.
Stale handles are blocked; unknown cleanup prevents reset. Do not claim global JWT
revocation outside the destroyed lab or silently change Juice Shop authentication.

`python -m app.access_fixture_acceptance --output <new-directory>` runs two real
independent generations and tests loss/swap, repeatable baselines, stale handles,
source integrity and cleanup. B05 must still register its own approved capability,
bind actual probes to B01 and account for every identity/control HTTP exchange.
See `docs/b04-access-fixtures.md` for scope, budgets, evidence and test results.

---

# 28. B06 controlled runtime verification

`targets/juice-b06-verification.yaml` and `policies/b06.yaml` enable the fixed
redirect and own-password reauthentication protocols. Never modify historical
default policy or A01-A08 locks to enable these actions. The ordinary pipeline
uses B06GraphLab only for this explicit profile; model/state never holds a live broker.

Two independent Docker generations are prepared before approval. The complete
ordered pair, source/profile digests and session are bound by ActionProposal's
application-owned fixture_binding. Validator requires the current operator registry;
Executor rechecks it and source/runtime identity. The fixed worker uses B04 setup
and public controls while credentials remain private in tmpfs. No setup/reset or
arbitrary URLs/credentials are model capabilities.

Evidence recomputes the verdict from typed controls, two trials, server identities,
credential readback, owner-object integrity, ledger and verified cleanup. It also
requires the matching persisted audit. Redirect follows no destination and its
local sink must observe zero requests. Auth proves only omitted reauthentication
for changing the authenticated user's own password.

The pinned Juice Shop image disables usernameXssChallenge in Docker with auto
safety mode. Code evaluation is unsupported_runtime, not rejected. Do not enable
the disabled branch merely to pass B06. Source/image provenance is operator binding,
not independent binary attestation.

`python -m app.b06_acceptance --output artifacts/<fresh-directory>` performs the
original/safe Docker acceptance. `app.b06_replay` verifies sealed persisted data
without Docker or LLM; `app.b06_handoff` creates the portable evidence ZIP.
Scope and results: `docs/b06-runtime-report-2026-10-14.md`.

# 29. B08 evidence-grounded scoring

`app.pipeline_run --scoring-reviews` accepts an operator-owned JSON list of
`ScoringReview` inputs, never model-generated permissions or benchmark labels.
Each review binds the finding observation, source file SHA256/ranges and explicit
metric/impact references. Recheck binding before FinalReport; stale source means
UNASSESSED. The semantic review remains operator responsibility, not proof that
a hash validates CVSS assumptions. Runtime Evidence inputs are not enabled here.

CVSS 4.0/B uses pinned `cvss==3.6` only for complete explicit justified base
metrics. Keep numeric CVSS, `source-impact.a04.v1` ordinal severity, scanner
severity and Context Priority separate. None creates a confirmed verdict.
Architecture unknown_inputs survive serialization; partial CP is provisional.
Do not stop research for missing scores or change historical A04 labels/locks.

`evaluation.scoring_b08` is evaluator-only and compares compatible schemes using
reviewed mappings. Report coverage separately from assessed accuracy. A04 has no
independent CP labels; CP accuracy remains N/A. `app.b08_acceptance` run/replay/
package is synthetic scoring acceptance, NOT new Juice Shop benchmark metrics.
See `docs/b08-scoring-progress.md` for trust boundaries, usage and acceptance.

# 30. R00–R03 opt-in research tools

`policies/research.yaml`, `schemas/research.py`, `tools/research.py` and the
operator-owned `ResearchRuntime` provide bounded source/workspace/script/HTTP
observations through canonical ActionProposal → Validator → SafeExecutor → Evidence.
The runtime must be bound explicitly; historical policies do not enable these tools.
ActionProposal.research_binding is application-owned. Absent bindings preserve the
historical wire shape and approval digest. State never contains the live broker.

The model sees only a redacted source projection with original/visible hashes.
Networkless Python/Node scripts run in a persistent per-run Docker tmpfs workspace,
never on the host. Locally built research images may use a verified full immutable
image ID; historical SandboxPolicy image requirements are unchanged.
Approval covers the script digest and full operator scope. Detached child processes,
timeouts, cancellation, source/script mutation and cleanup are enforced.

`target_http` uses a separate fixed worker on a registered internal network.
Requests bind a container/image generation, local service, path/method and optional
opaque role handle. Credentials stay private to the operator broker; model scripts
cannot access the transport or arbitrary network. Writes need exact operator grants.
Research observations always remain inconclusive until independent R06 review.

`app.research_plan` is the operator CLI. `app.research_acceptance` runs real Docker
transport tests; `app.research_juice_smoke` observes ordinary pinned Juice Shop search.
Neither is a benchmark or an LLM quality measurement. R04 autonomous tool selection
is now opt-in; the private B04 fixture bridge remains future integration. R00 replay and R01
static source audit do not change historical A04/B09 results. See
`docs/research-foundation-report-2026-10-15.md` for artifacts and reproduction.

# 30. B07 finding workflow recovery

LangGraph nodes use `agent.recovery.protected_node` to preserve finding-local
failures as `inconclusive` reports with typed `workflow_errors`. Operator
cancellation still propagates. Approved proposals enter action history before
Executor; collect_evidence updates the same record with its execution, evidence,
error and per-action session. Never fabricate execution/Evidence after a failure.
The pipeline retains a report row and trace for escaped bootstrap/cleanup errors;
failed cleanup cannot preserve a confirmed/rejected claim. Technical workflow
errors feed the existing CI Gate exit 2, independently of security verdicts.

Each iteration proposes one action, then replans from accumulated Evidence.
Operation fingerprints exclude proposal IDs/descriptions and fixture generations;
used IDs or exact operations cannot be replayed. B05/B06 approved candidate and
runtime permissions remain unchanged. Distinguish missing capability, unsupported
runtime, binding failure, candidate exhaustion, model failure and policy denial.

Wall-clock checks precede new reasoning, validation and execution. LLM attempts,
route fallbacks and correction retries share a runtime-only remaining deadline;
it is not stored in AgentState. In-flight protocols retain bounded timeouts and
mandatory cleanup; do not describe the cooperative deadline as a hard process kill.
Model fallback diagnostics are serialized separately from terminal Evidence.
FinalReport rechecks sufficient Evidence against action/tool/target/environment/run.
Historical `safe_noop` stays a synthetic graph stub, never benchmark proof.

See `docs/b07-workflow-recovery.md` and `docs/b07-validation-2026-10-14.json`.
B07 regression tests do not constitute new B05/B06 Docker acceptance or B09 metrics.

# 31. R04 opt-in research loop

`app.research_run` installs a per-run `ResearchAgentModel` behind the canonical
LangGraph and a live operator-bound research scope/Executor. One schema-validated
turn proposes one action or stops. It cannot execute or add permissions. Source,
workspace and HTTP results are read back from persisted execution plus matching
audit before entering the serializable ledger. A research scope in state alone
does not enable this mode. Historical A/B profiles and policies stay unchanged.

Expected script failures may inform the next experiment; policy denial, invalid
scope and lost persistence cannot be bypassed. Calls, IO byte reservations,
context, actions, writes and observations are bounded; IO reservations are not
provider token billing. Model interpretations never become confirmed/rejected:
R06 independent claim protocols are opt-in and property-specific. Checkpoints are diagnostics,
not resumable Docker sessions/approvals. See `docs/research-loop-r04.md`.

# 32. R05–R07 research integration

`app.research_campaign` combines canonical scanner/model candidates and unexamined
surface questions, with shared call/action/wall/byte budgets. Surface questions and
read coverage are not vulnerability counts or Recall. Model candidates must bind
actual source reads, ranges and exact anchors. Directory search expands only frozen
approved projected files. Provider correction validates persisted observation IDs
before acceptance; it cannot add permissions or bypass Validator.

Independent R06 protocols currently cover explicit weak digest source calls and
operator-owned confidential marker disclosure. Source confirmation is not runtime
exploitability. HTTP replay uses two fresh generations, owner/negative controls,
matching execution/audit and verified cleanup; arbitrary HTTP 200 is insufficient.
Unsupported proofs remain pending. Marker/credentials stay operator-private; no
private runtime handles enter state. Preserve historical A/B locks and policies.

`app.research_dev_acceptance` is a bounded live functional DEV campaign, explicitly
calibrated for implemented protocol coverage. It is not full benchmark metrics,
reproducibility measurement or automatic fixes. Preserve unsuccessful starts and
their seals; never treat them as successful repetitions. See
`docs/research-integration-r05-r07.md` for results, limitations and handoff.

# 33. R07 recovery / R08 browser

Research campaigns retain model-failed questions and continue with remaining shared
budgets. Reports expose `degraded` and `model_failures`; never hide incomplete
questions as successful/rejected. Authentication/payment/rate-limit/model-route
failures stop the campaign. Three consecutive model failures stop by default.
One bounded correction still validates the same schemas and observation provenance.

`browser_interact` is opt-in through an immutable browser image and trusted worker
digest in ResearchScope. It passes canonical Validator/Executor/approval/audit.
Chromium runs non-root/read-only in Docker with network=none; a separate fixed HTTP
worker transports only independently scope-validated requests to the pinned target
container/image/IP/network. Source scripts cannot access this channel. UI input is
data, never model evaluate/JavaScript/CDP. Fresh anonymous contexts do not expose
credentials, cookies or storage state. DOM/dialogs/screenshots remain inconclusive
observations until an appropriate independent protocol exists.

All redirects are blocked; require explicit approved navigation. Browser HTTP
requests, including page resources, consume the same runtime/campaign network quota.
Default opt-in browser quota is 128 per question, 64 per action; campaign defaults
to 256 total. Resource/byte/action/time limits and cleanup remain mandatory.
Before R09 configure operator scope excluding evaluator oracle/scoreboard routes.
HttpServiceScope.denied_prefixes overrides grants; the worker never gets to expand
it. Empty exclusions preserve the previous serialized scope shape.
Do not equate rendered UI, PNG or dialog with vulnerability confirmation/coverage.
See `docs/research-r07-recovery-r08-browser.md` and the fixed recovery/browser/juice
smoke acceptance CLIs. These are not R09/R10 benchmark measurements.

# 34. R09 diagnostic repairs

Research proposal preflight returns bounded serialized feedback for unavailable
paths/methods and already attempted operations. It does not execute, approve or
create Evidence. Up to two proposal corrections share the original model-call,
byte and wall budgets; exhausted corrections are `proposal_corrections_exhausted`,
not provider failure. Canonical Validator denials and live scope/integrity failures
remain authoritative. Source/search operation fingerprints normalize typed defaults;
raising a complete search's match limit is not progress.

Research-only source selection includes application templates/styles and selected
JSON manifests, with 1024 files/12 MiB limits. Historical RepositoryScout selection
remains 256 files/4 MiB. Secret/oracle/test exclusions and projection redaction remain.
Campaign memory is bounded navigation/interpretation, never reusable approval or
current-session read provenance. Fair channel scheduling prefers server handlers
and available registered verification paths, not evaluator labels.

`pipeline.research_verification` exports source-bound handoffs. With explicit
operator profiles and an immutable verification worker image it can run existing
B01 SQL/directory protocols through Validator/Executor/persisted Evidence, within
the current research method/path grant. It cannot enable POST or private fixtures
merely because a verification route exists. Shared target identity checks bracket
execution; matching audit, source integrity and cleanup precede final reporting.
Original research reports remain preserved beside independent final reports.
Fixed protocol network reservations are separate from observed research requests
but consume the same campaign quota. Explicit typed operator grants now enable
only B05 own-read and the two registered B06 redirect/re-authentication protocols
through their existing canonical Validator/Executor/Audit/Evidence paths. B05
writes and other B05/B06 checks remain unavailable. Readiness, complete lifecycle
HTTP reservation, protocol wall budget, source/fixture binding and cleanup are
enforced. `tests/test_research_fixture_campaign.py` is the real-Docker acceptance;
its scripted research step does not measure model quality or benchmark metrics.
See `docs/research-private-fixture-campaign-2026-10-15.md` and
`docs/research-r09-diagnostic-repairs.md`.

# 35. Research campaign finalization

Provider HTTP requests have a total deadline in a fixed disposable transport
process. Campaign and question deadlines can only shorten it; cancellation joins
the transport child. This does not interrupt Executor cleanup or enable host
execution of target code. Credentials are not command-line arguments.

Question/campaign/diagnostic runner interruptions persist partial accounting,
`completed=false` and an explicit cause before propagating cancellation. Atomic
JSON checkpoints preserve the previous snapshot. A partial seal proves saved
bytes, not successful measurement or sufficient Evidence. Target cleanup is
verified against the exact operator-created container/network.

ResearchQueue may group identical source anchors, families and column spans for
scheduling only. Preserve all canonical Finding/raw observations and expose
`grouped` plus representative IDs; do not copy security verdicts to those rows.
Different sinks and unbound observations remain independent. Existing historical
benchmark labels, policies and scorer contracts remain unchanged.

`app.research_saved_report` writes a separate operational readout and input seal;
it does not modify original artifacts, revalidate security Evidence or calculate
benchmark metrics. See `docs/research-run-recovery-2026-10-15.md`.

# 36. Research measurement and fixed login grant

`ResearchVerificationGrant(protocol="b01.login-sql.v1", route_id="juice-login")`
authorizes only the existing fixed four-request B01 login SQL protocol. It does
not add POST to model HTTP grants. Exact profile/route/tool/check/method/endpoint,
source binding, Validator, Executor and persisted execution/audit remain required.

Scanner observations do not mark a whole handler as explored. ResearchQueue keeps
a separate surface question for a file with scanner candidates. The finite source
artifact registry prioritizes files referenced by operator verification routes so
unrelated findings cannot crowd out an existing verifier such as `/ftp`.

`app.research_score --run <sealed-run> --output <fresh-evaluation>` replays saved
canonical runtime protocols and applies the unchanged frozen A04 matcher. It uses
no model or target requests. Archived audit paths are resolved within the verified
local result directory for offline portability; original action/record bytes are
not rewritten. Source-condition MD5 proofs remain separate from runtime Recall.
Degraded/budget-limited research is diagnostic evidence, not clean acceptance or
an independent held-out evaluation. See `docs/research-latest-results-2026-10-15.md`.

# 37. C01 bounded fix scope

`contracts/c01/families.json` selects only SQL search and redirect allowlist repair
families from the sealed valid B09. `app.fix_scope` replays persisted execution,
audit and approved traces; missing proof is explicitly failed, unselected families
are ineligible. This is not automatic repair or a new confirmed/FIXED verdict.

`fix_verification.scope.validate_candidate` checks the protected evaluator/baseline
lock, source digest and an exact single existing application file allowlist.
C02/C03 must call it before patch application and recheck locks after verification.
Never allow patches to evaluator tests, frozen original baseline, manifests or
dependencies. The evaluator must stay outside the writable patched target.

`app.fix_scope_acceptance` qualifies 13 independent source-level tests in fixed,
networkless, non-root disposable Docker containers: original fails cause-specific
tests, operator reference passes, deny-all and probe-only shortcuts fail. It does
not replace full build/tests/start/smoke or B01-bound runtime verification in C03.
Do not treat target stdout or the source evaluator as independent runtime Evidence.
See `docs/c01-fix-scope.md` for eligibility, budgets, protected inputs and limitations.

# 38. C02 real LLM patch proposals

`app.patch_propose` uses the real ProviderFailoverClient for one operator-selected
C01 family/route. It replays original B09 proof, binds the complete clean pinned
source snapshot, projects only bounded AST source and redacted Evidence facts,
and receives a strict ProposedPatch subclass. No IntegrationPatchClient/reference
diff, model tool call, target execution or application is used in this path.

Check exact paths, byte/line budgets, source digest/window and C01 scope before
accepting. SQL query structure/parameter API and strict redirect equality shapes
are deterministic operator gates; do not widen them on model request. Evaluator,
baseline, credentials, dependencies and unrelated protections cannot be patched.
Secret responses are discarded; successful raw responses and canonical reviews
have separate digests. Recheck full source/C01 integrity after generation.

Persist ready/rejected/failed/ineligible explicitly. A real provider attempt is
required for ready, but is not proof of remediation. PatchReviewArtifact remains
applied=false/security_verified=false until independent C03 verification; never
reinterpret model rationale or adapter telemetry as security Evidence. See
`docs/c02-llm-patch-proposals.md` for budgets, real runs and reproduction.

# 39. C03 independent patch verification

`app.independent_fix` specializes the existing isolated FixVerificationService.
C01 scope, frozen B09 source, B01 binding, Validator, SafeExecutor and persisted
execution/audit are mandatory. Patches cannot modify the evaluator or native
tests. Fixed readonly runners execute all native unit files; separate source and
HTTP checks cannot substitute for the original canonical runtime hypothesis.

FIXED requires fresh BEFORE confirmed, explicit AFTER rejected, all required
successful stages, original integrity and verified owned-resource cleanup.
Offline replay checks receipts, stage inventory and source/patch digests; it
cannot upgrade an inconclusive verifier result. No missing response, endpoint
or model conclusion proves rejection. Reference engineering runs are not C02
LLM generation claims.

All upstream tests still execute unchanged. Roman subsequently authorized a
protected security-contract replacement only for the two exact redirect
assertions requiring vulnerable behavior. contracts/c03/native-security-contract.json
pins their source hashes, names, assertion lines and false-vs-true outcomes.
Raw native failures/exit 1 remain persisted; they permit continuation only after
the exact contract is independently rechecked. No other failure/skip is accepted.
Independent source/HTTP tests and canonical AFTER rejected remain mandatory;
the exception itself never creates FIXED. Historical REGRESSION evidence stays
unchanged. See docs/c03-independent-patch-verification.md.

# 40. C04 bounded repair loop

`app.repair` composes real C02 generation with independent C03 verification for
the existing C01 SQL/redirect families. Each proposal uses a newly verified copy
of the original commit and a new verifier instance. Always pass the generated
review explicitly: C03's reference-patch default is never a C04 fallback.

Raw/canonical diff and resulting-file duplicates stop the campaign. Attempts,
provider/stage deadlines, typed feedback, execution/audit Evidence, integrity,
cleanup and terminal reasons remain persisted. Feedback is a bounded registered
projection, not raw private tests, secrets, stderr or instructions to change policy.
Feedback v2 identifies the failed AFTER build/native-test stage without claiming
its cause. The next request includes only the previous validated diff projected
through the same source redaction as C02, bound to its canonical patch digest;
never forward rationale, evaluator annotations or raw test output. Replay checks
the prior-attempt binding, and legacy bundles retain their original contract.
Shared work deadlines cannot prevent bounded cleanup. Transport process groups
must be isolated before cancellation can terminate a child.

FIXED requires persisted C03 replay plus matching model-response/proposal/source
bindings, original integrity and cleanup. C04 NOT_FIXED is an unsuccessful repair
campaign, not independently confirmed vulnerability persistence. Interruptions and
technical failures preserve partial sealed history without success claims.

`app.repair --replay <directory>` validates saved C04/C03 artifacts without target,
Docker or LLM. Keep complete local evidence and any redacted/partial public
readout distinct. Never modify original target files or merge automatically.
See `docs/c04-bounded-repair-loop.md` and `docs/evidence/c04/README.md`.
