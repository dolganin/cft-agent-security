import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getPatchProposal, proposePatch } from "../../api/client";

export function PatchProposalPanel({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const queryKey = ["patch-proposal", runId];
  const saved = useQuery({ queryKey, queryFn: () => getPatchProposal(runId), retry: false });
  const generate = useMutation({
    mutationFn: () => proposePatch(runId),
    onSuccess: (artifact) => queryClient.setQueryData(queryKey, artifact),
  });
  const artifact = saved.data;
  const error = generate.error ?? saved.error;
  const download = artifact?.status === "ready_for_review"
    ? `data:text/plain;charset=utf-8,${encodeURIComponent(artifact.proposal.unified_diff)}` : null;

  return (
    <section className="demo-patch" aria-label="Предложение исправления">
      <span className="demo-eyebrow">ОТ НАХОДКИ К ПРЕДЛОЖЕНИЮ ПАТЧА</span>
      <h2>Исправление SQL-запроса для ревью</h2>
      <p>Модель предлагает минимальный diff для подтвержденной находки в поиске товаров.
        Проверяем файл и соответствие исходнику. Патч не применяется, код не выполняется.</p>
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
