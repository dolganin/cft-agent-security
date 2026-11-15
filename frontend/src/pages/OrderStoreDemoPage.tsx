import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { createRun, getGate, getOrderStoreDemoStatus, getReports, getRunProgress, listProjects, listRuns } from "../api/client";
import { formatDuration, gateLabel, runStatusLabel, stageDetailLabel } from "../lib/format";
import "../styles/order-store-demo.css";

const TARGET_ID = "demo-order-store";
const PIPELINE = ["Магазин", "Поиск находок", "Гипотеза", "Валидатор", "Проверка в Docker", "Доказательства", "Отчёт"];

export function OrderStoreDemoPage() {
  const queryClient = useQueryClient();
  const preview = useQuery({ queryKey: ["order-store-demo-status"], queryFn: getOrderStoreDemoStatus, refetchInterval: 5_000 });
  const projects = useQuery({ queryKey: ["projects"], queryFn: listProjects });
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => listRuns(200), refetchInterval: 2_000 });
  const run = runs.data?.find((item) => item.target_id === TARGET_ID) ?? null;
  const active = run !== null && ["queued", "running"].includes(run.status);
  const gate = useQuery({ queryKey: ["gate", run?.id], queryFn: () => getGate(run!.id), enabled: run?.status === "completed" });
  const reports = useQuery({ queryKey: ["reports", run?.id], queryFn: () => getReports(run!.id), enabled: run?.status === "completed" });
  const progress = useQuery({ queryKey: ["progress", run?.id], queryFn: () => getRunProgress(run!.id), enabled: run !== null, refetchInterval: active ? 1_500 : false });
  const start = useMutation({
    mutationFn: () => createRun({ target_id: TARGET_ID, agent_mode: "llm", max_iterations: 1,
      analysis_request: "Проверь только четыре зарегистрированных учебных сценария: SQL-инъекцию в поиске и при входе, доступ к чужому заказу и открытый список имён файлов." }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["runs"] }),
  });
  const available = (projects.data?.some((project) => project.id === TARGET_ID && project.repository_available) ?? false)
    && preview.data?.status === "ready";
  const latestStage = progress.data?.stages.at(-1);
  const usedFallback = reports.data?.some((report) => report.reasoning_events?.some((event) => event.status === "fallback")) ?? false;
  const error = start.error ?? projects.error ?? runs.error ?? gate.error ?? reports.error ?? progress.error ?? preview.error;

  return (
    <main className="order-demo-page">
      <header className="order-demo-heading">
        <div><span className="demo-eyebrow">CFT SECURITY AGENT · ЖИВОЙ СЦЕНАРИЙ</span>
          <h1>Проверяем настоящий<br /><em>магазин заказов.</em></h1>
          <p>Небольшое веб-приложение с каталогом, поиском, входом, личными заказами и списком файлов. Агент проверяет четыре учебных сценария внутри Docker и сохраняет решения валидатора, действия и доказательства.</p>
        </div>
        <div className="order-demo-badge"><b>4</b><span>проверяемых<br />сценария</span></div>
      </header>

      <section className="order-demo-flow" aria-label="Этапы проверки">
        {PIPELINE.map((step, index) => <div key={step}><small>{String(index + 1).padStart(2, "0")}</small><strong>{step}</strong></div>)}
      </section>

      <section className="order-demo-workspace">
        <div className="order-demo-store">
          <div className="order-demo-store-title"><div><span className="demo-eyebrow">ЦЕЛЕВОЕ ПРИЛОЖЕНИЕ</span><h2>Тихий дом</h2></div><a href={`${preview.data?.url ?? "http://127.0.0.1:8090"}/`} target="_blank" rel="noreferrer">Открыть отдельно ↗</a></div>
          {preview.data?.status === "ready" ? (
            <iframe title="Демонстрационный магазин заказов" src={`${preview.data.url}/`} />
          ) : (
            <div className="order-demo-preview-state" role="status">
              <strong>{preview.data?.status === "starting" ? "Запускаем магазин" : "Предпросмотр недоступен"}</strong>
              <span>{preview.data?.message ?? "Запустите Docker и перезапустите сервер демо."}</span>
            </div>
          )}
          <p className="order-demo-note">Локальные тестовые аккаунты находятся в форме входа. Приложение доступно только на этом компьютере.</p>
        </div>

        <div className="order-demo-run">
          <div className="order-demo-run-head"><div><span className="demo-eyebrow">ПРОВЕРКА</span><h2>Что проверяет агент</h2></div><span className={`debug-status ${run?.status ?? "queued"}`}>{run ? runStatusLabel(run.status) : "Готов к запуску"}</span></div>
          <div className="order-demo-case"><span className="case-number">01</span><div><b>SQL-инъекция в поиске</b><p>Сравнивает повторные контрольные запросы и безопасный булев запрос по числу результатов.</p></div></div>
          <div className="order-demo-case"><span className="case-number">02</span><div><b>Чтение чужого заказа</b><p>Сверяет доступ владельца, доступ другого аккаунта и контроль несуществующего заказа.</p></div></div>
          <div className="order-demo-case"><span className="case-number">03</span><div><b>SQL-инъекция при входе</b><p>Проверяет, меняет ли контролируемый ввод результат аутентификации.</p></div></div>
          <div className="order-demo-case"><span className="case-number">04</span><div><b>Раскрытие списка файлов</b><p>Проверяет открытый каталог и имена файлов без загрузки содержимого.</p></div></div>
          {run ? <div className="order-demo-metrics">
            {gate.data ? <>
              <div><b>{gate.data.confirmed}</b><span>подтверждено</span></div>
              <div><b>{gate.data.inconclusive}</b><span>неопределённых</span></div>
              <div><b>{formatDuration(run.started_at, run.finished_at)}</b><span>длительность</span></div>
              <div><b>{gateLabel(gate.data.decision)}</b><span>решение CI</span></div>
            </> : <p>{latestStage ? `${stageDetailLabel(latestStage.detail, latestStage.status)}.` : "Ожидаем этапы анализа…"}</p>}
          </div> : <p className="order-demo-note">Это узкий показ возможностей агента, а не полный аудит и не замер recall.</p>}
          {usedFallback ? <p className="order-demo-llm-note" role="status">Запросы к языковой модели не прошли; в этом запуске сработал детерминированный резервный режим.</p> : null}
          {error ? <p className="order-demo-error" role="alert">{error instanceof Error ? error.message : "Не удалось получить состояние прогона"}</p> : null}
          <div className="order-demo-actions">
            {run ? <Link className="demo-primary" to={`/runs/${run.id}`}>Открыть действия и доказательства →</Link> : null}
            <button type="button" disabled={!available || active || start.isPending} onClick={() => start.mutate()}>
              {start.isPending ? "Запускаем…" : active ? "Проверка выполняется" : "Запустить проверку"}
            </button>
          </div>
          {!projects.isPending && !preview.isPending && !available ? <p className="order-demo-note">Запустите Docker, затем сервер демо: <code>python -m app.demo</code></p> : null}
        </div>
      </section>
      <footer className="demo-footer">Демо-аккаунты и данные вымышлены. Проверки обращаются только к зарегистрированным локальным маршрутам.</footer>
    </main>
  );
}
