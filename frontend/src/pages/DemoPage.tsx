import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { createRun, getGate, getRunProgress, listProjects, listRuns } from "../api/client";
import { formatDuration, gateLabel, runStatusLabel, stageDetailLabel } from "../lib/format";
import { PatchProposalPanel } from "../components/demo/PatchProposalPanel";

const TARGET_ID = "juice-presentation";
const STEPS = ["Код проекта", "Статический поиск", "Контекстный приоритет", "Гипотеза агента", "Валидатор", "Проверка в Docker", "Доказательства", "Решение для CI"];

export function DemoPage() {
  const queryClient = useQueryClient();
  const projects = useQuery({ queryKey: ["projects"], queryFn: listProjects });
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => listRuns(200), refetchInterval: 3_000 });
  const run = runs.data?.find((item) => item.target_id === TARGET_ID) ?? null;
  const active = run !== null && ["queued", "running", "cancelling"].includes(run.status);
  const gate = useQuery({
    queryKey: ["gate", run?.id],
    queryFn: () => getGate(run!.id),
    enabled: run?.status === "completed",
  });
  const progress = useQuery({
    queryKey: ["progress", run?.id], queryFn: () => getRunProgress(run!.id),
    enabled: run !== null, refetchInterval: active ? 3_000 : false,
  });
  const scoutStage = progress.data?.stages.filter((stage) => stage.stage === "scout").at(-1);
  const available = projects.data?.some((project) => project.id === TARGET_ID && project.repository_available) ?? false;
  const start = useMutation({
    mutationFn: () => createRun({ target_id: TARGET_ID, agent_mode: "llm", max_iterations: 2,
      analysis_request: "Демонстрационный проход: SQL, списки файлов и ограниченный поиск по исходникам. Не полный бенчмарк." }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["runs"] }),
  });
  const error = start.error ?? runs.error ?? projects.error ?? gate.error ?? progress.error;

  return (
    <main className="demo-page">
      <header className="demo-hero">
        <span className="demo-eyebrow">CFT SECURITY AGENT · РАБОЧИЙ ПРОТОТИП</span>
        <h1>От подозрительного кода<br />к проверяемому выводу.</h1>
        <p>Агент для анализа безопасности в CI/CD: собирает находки, исследует исходники,
          выбирает разрешенную проверку и объясняет результат через доказательства.</p>
      </header>

      <section className="demo-flow" aria-label="Путь от кода к решению">
        {STEPS.map((step, index) => (
          <div key={step}><small>{String(index + 1).padStart(2, "0")}</small><strong>{step}</strong></div>
        ))}
      </section>

      <section className="demo-live">
        <div className="demo-live-heading">
          <div><span className="demo-eyebrow">НАСТОЯЩИЙ ЛОКАЛЬНЫЙ ПРОГОН</span><h2>OWASP Juice Shop 20.2.0</h2></div>
          <span className={`debug-status ${run?.status ?? "queued"}`}>{run ? runStatusLabel(run.status) : "Еще не запущен"}</span>
        </div>
        <p>Выбранные проверки SQL-интерполяции и публикации списков файлов, плюс ограниченное
          исследование исходников моделью. Это демонстрация процесса, не оценка полного покрытия.</p>
        {gate.data ? (
          <div className="demo-facts" aria-label="Измеренные результаты прогона">
            <div><strong>{gate.data.confirmed}</strong><span>подтверждено</span></div>
            <div><strong>{gate.data.inconclusive}</strong><span>недостаточно данных</span></div>
            <div><strong>{gate.data.technical_errors}</strong><span>технических ошибок</span></div>
            <div><strong>{run ? formatDuration(run.started_at, run.finished_at) : "—"}</strong><span>время прогона</span></div>
          </div>
        ) : <p className="demo-data-note">{active ? "Результаты появятся после завершения. Уже можно открыть этапы анализа." : "Числа появятся только после завершенного реального запуска."}</p>}
        {run?.error ? <p role="alert" className="demo-error">{run.error.message}</p> : null}
        {scoutStage ? <p className="demo-data-note">Поиск модели: {stageDetailLabel(scoutStage.detail, scoutStage.status)}.</p> : null}
        {error ? <p role="alert" className="demo-error">{error instanceof Error ? error.message : "Не удалось получить данные"}</p> : null}
        <div className="demo-actions">
          {run ? <Link className="demo-primary" to={`/runs/${run.id}`}>Открыть действия и доказательства →</Link> : null}
          <button type="button" disabled={!available || active || start.isPending} onClick={() => start.mutate()}>
            {start.isPending ? "Запускаем…" : active ? "Анализ выполняется" : "Новый демонстрационный прогон"}
          </button>
          {gate.data ? <span>Решение CI: {gateLabel(gate.data.decision)}</span> : null}
        </div>
        {!projects.isPending && !available ? <p className="demo-data-note">Для этого сценария запусти сервер: <code>python -m app.demo</code></p> : null}
      </section>

      {run?.status === "completed" && gate.data?.confirmed ? <PatchProposalPanel key={run.id} runId={run.id} /> : null}

      <div className="demo-columns">
        <section>
          <span className="demo-eyebrow">ЧТО ПОКАЗЫВАЕМ СЕЙЧАС</span>
          <h2>Проверка, которую можно объяснить</h2>
          <ul>
            <li>Статический анализ и дополнительные гипотезы по исходникам.</li>
            <li>План проверки с привязкой к разрешенному локальному окружению.</li>
            <li>Детерминированный валидатор и изолированное исполнение.</li>
            <li>Вызовы инструментов, вывод, доказательства и итоговый статус.</li>
          </ul>
        </section>
        <section>
          <span className="demo-eyebrow">СЛЕДУЮЩИЙ ЭТАП, НЕ ГОТОВЫЕ ФУНКЦИИ</span>
          <h2>От проверки к исправлению</h2>
          <ul>
            <li>Расширить классы проверяемых проблем и межфайловые связи.</li>
            <li>Патч в отдельной копии, тесты и повтор исходной проверки.</li>
            <li>Передача проверенного исправления разработчику на ревью.</li>
            <li>Повторные сопоставимые прогоны и измерение качества.</li>
          </ul>
        </section>
      </div>
      <footer className="demo-footer">Модель формирует гипотезы. Валидатор разрешает действия. Доказательства определяют результат.
        Production не проверяем. Автоматическое исправление в этом демо не включено.</footer>
    </main>
  );
}
