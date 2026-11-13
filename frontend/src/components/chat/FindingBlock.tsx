import {
  CaretRight,
  CheckCircle,
  Question,
  ShieldWarning,
  XCircle,
} from "@phosphor-icons/react";
import type { FinalReport } from "../../api/types";
import {
  evidenceSummary,
  findingStatusLabel,
  findingTitle,
  severityLabel,
  severityTone,
} from "../../lib/format";

export function FindingBlock({ report }: { report: FinalReport }) {
  const currentCvss = report.cvss?.assessment_status === "assessed"
    && report.cvss.scheme === "CVSS:3.1/B"
    && report.cvss.vector?.startsWith("CVSS:3.1/");
  const location = [
    report.finding.file,
    report.finding.line_start ? String(report.finding.line_start) : null,
  ]
    .filter(Boolean)
    .join(":");

  return (
    <details className={`finding-block ${report.status}`}>
      <summary>
        <CaretRight size={14} className="details-caret" />
        <span className="finding-status-icon">{statusIcon(report.status)}</span>
        <span className="finding-main">
          <span className="finding-kicker">{findingStatusLabel(report.status)}</span>
          <strong>{findingTitle(report.finding.rule_id, report.finding.title)}</strong>
          <small>
            Доказательств: {report.evidence.length}
            {location ? ` · ${location}` : ""}
          </small>
        </span>
        <span title="Уровень исходного сканера, не CVSS" className={`severity ${severityTone(report.finding.severity)}`}>
          {severityLabel(report.finding.severity)}
        </span>
      </summary>

      <div className="finding-details">
        <section>
          <span>Серьезность и приоритет</span>
          <p className="score-row">CVSS 3.1: <span className={`score-badge ${currentCvss ? severityTone(report.cvss!.severity) : "none"}`}>
            {currentCvss
              ? `${report.cvss!.score} · ${severityLabel(report.cvss!.severity)}`
              : report.cvss?.assessment_status === "not_applicable" ? "Не применимо" : "Не оценено"}</span></p>
          {report.technical_severity ? <p className="score-row">Оценка по исходникам: <span className={`score-badge ${severityTone(report.technical_severity.level)}`} title={report.technical_severity.scheme}>
            {report.technical_severity.level === "UNASSESSED" ? "Не оценено" : severityLabel(report.technical_severity.level)}</span></p> : null}
          <p className="score-row">Контекстный приоритет: <span className={`score-badge ${severityTone(report.context_priority?.level)}`}>
            {severityLabel(report.context_priority?.level)}</span>
            {report.context_priority?.assessment_status !== "assessed" ? <span className="score-badge provisional">Предварительный</span> : null}</p>
          {report.context_priority?.unknown_inputs?.length ? <p>Неизвестные данные: {report.context_priority.unknown_inputs.map(key => ({criticality: "критичность актива", authentication: "аутентификация", blast_radius: "масштаб последствий", public_exposure: "публичная доступность", databases: "доступ к базам данных", critical_paths: "критические связи"} as Record<string, string>)[key] ?? key).join(", ")}</p> : null}
        </section>
        {report.analysis_summary ? <p>{report.analysis_summary}</p> : null}
        {report.hypothesis ? (
          <section>
            <span>Гипотеза</span>
            <p>{report.hypothesis}</p>
          </section>
        ) : null}
        <section>
          <span>Вывод на основе доказательств</span>
          <p>{evidenceSummary(report.explanation)}</p>
        </section>
        {report.limitations.length > 0 ? (
          <section>
              <span>Ограничения</span>
            <ul>
              {report.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </section>
        ) : null}
        <section>
          <span>Следующий шаг</span>
          <p>{report.next_step}</p>
        </section>
      </div>
    </details>
  );
}

function statusIcon(status: FinalReport["status"]) {
  switch (status) {
    case "confirmed":
      return <ShieldWarning size={18} weight="duotone" />;
    case "rejected":
      return <CheckCircle size={18} weight="duotone" />;
    case "policy_blocked":
      return <XCircle size={18} weight="duotone" />;
    default:
      return <Question size={18} weight="duotone" />;
  }
}
