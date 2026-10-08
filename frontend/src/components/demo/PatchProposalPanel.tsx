import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getFixVerification, getPatchProposal, proposePatch, verifyFix } from "../../api/client";

export function PatchProposalPanel({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const queryKey = ["patch-proposal", runId];
  const saved = useQuery({ queryKey, queryFn: () => getPatchProposal(runId), retry: false });
  const generate = useMutation({
    mutationFn: () => proposePatch(runId),
    onSuccess: (artifact) => queryClient.setQueryData(queryKey, artifact),
  });
  const artifact = saved.data;
  const fixKey = ["fix-verification", runId];
  const fix = useQuery({ queryKey: fixKey, queryFn: () => getFixVerification(runId), retry: false });
  const verify = useMutation({ mutationFn: () => verifyFix(runId),
    onSuccess: (result) => queryClient.setQueryData(fixKey, result) });
  const error = verify.error ?? generate.error ?? saved.error ?? fix.error;
  const download = artifact?.status === "ready_for_review"
    ? `data:text/plain;charset=utf-8,${encodeURIComponent(artifact.proposal.unified_diff)}` : null;

  return (
    <section className="demo-patch" aria-label="Предложение исправления">
      <span className="demo-eyebrow">ОТ НАХОДКИ К ПРЕДЛОЖЕНИЮ ПАТЧА</span>
      <h2>Исправление SQL-запроса для ревью</h2>
      <p>Модель предлагает минимальный diff для подтвержденной находки в поиске товаров.
        Проверяем файл и соответствие исходнику. Отдельная проверка исправления выполняет сборку,
        тесты и повтор исходной security-проверки в одноразовой Docker-копии.</p>
      {artifact ? (
        <>
          <p className="demo-data-note">{artifact.status === "ready_for_review" ? "Готово для ревью" : "Предложение отклонено"}
            {artifact.model ? ` · ${artifact.model}` : ""}</p>
          {artifact.status === "ready_for_review" ? <p><span className="demo-data-note">Объяснение модели, не результат тестов: </span>{artifact.proposal.rationale}</p> : null}
          <p className="demo-data-note">{artifact.validation_detail}</p>
          {download ? (
            <details className="demo-patch-diff">
              <summary>Посмотреть diff · {artifact.file}</summary>
              <pre>{artifact.proposal.unified_diff}</pre>
            </details>
          ) : null}
          <ul>{artifact.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
          {download ? <a className="demo-primary" href={download} download="security-fix-proposal.patch">Скачать патч для ревью</a> : null}
          {artifact.status === "ready_for_review" ? (
            <button type="button" disabled={verify.isPending} onClick={() => verify.mutate()}>
              {verify.isPending ? "Сборка и проверка в Docker…" : "Проверить исправление в изолированной копии"}
            </button>
          ) : null}
          {fix.data ? <div aria-label="Результат проверки исправления">
            <p>{fix.data.status} · Security verified: {String(fix.data.security_verified)}</p>
            <p>Patch applied in isolated workspace: {String(fix.data.applied)}</p>
            <p>Before: {fix.data.before_evidence?.verdict ?? "unavailable"} · After: {fix.data.after_evidence?.verdict ?? "unavailable"}</p>
            <ul>{fix.data.stages.map((stage) => <li key={`${stage.phase}-${stage.stage}`}>
              {stage.phase} · {stage.stage}: {stage.status}
            </li>)}</ul>
            <p>{fix.data.explanation}</p>
            <p>Original unchanged: {String(fix.data.original_unchanged)} · Cleanup: {String(fix.data.cleanup_complete)}</p>
          </div> : <p>Applied: false · Security verified: false</p>}
          {artifact.status === "rejected" ? (
            <button type="button" disabled={generate.isPending} onClick={() => generate.mutate()}>
              {generate.isPending ? "Повторное ревью…" : "Повторить ревью предложения"}
            </button>
          ) : null}
        </>
      ) : (
        <button type="button" disabled={saved.isPending || generate.isPending || Boolean(saved.error)} onClick={() => generate.mutate()}>
          {generate.isPending ? "Модель готовит патч…" : "Предложить исправление"}
        </button>
      )}
      {error ? <p role="alert" className="demo-error">{error instanceof Error ? error.message : "Не удалось подготовить патч"}</p> : null}
    </section>
  );
}
