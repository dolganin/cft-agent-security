import { ArrowSquareOut, ShieldCheck } from "@phosphor-icons/react";
import { Link } from "react-router-dom";
import type { ApiRun, FinalReport, GateResult } from "../../api/types";
import { findingTitle, gateLabel, severityLabel, severityTone } from "../../lib/format";
import { groupReports } from "../../lib/report-groups";

export function GateBlock({
  gate,
  reports,
  run,
}: {
  gate: GateResult;
  reports: FinalReport[];
  run: ApiRun;
}) {
  const technicalFailure = run.status === "technical_failure" || gate.exit_code === 2;
  const grouped = groupReports(reports);
  const counts = grouped.reduce((result, item) => {
    result[item.report.status] += 1;
    return result;
  }, { confirmed: 0, rejected: 0, inconclusive: 0, policy_blocked: 0 });
  const confirmed = grouped
    .filter((item) => item.report.status === "confirmed")
    .sort((left, right) => severityRank(right.report.finding.severity) - severityRank(left.report.finding.severity));

  return (
    <article className={`analysis-summary gate-${technicalFailure ? "error" : gate.decision}`}>
      <div className="analysis-summary-head">
        <span className="summary-icon">
          <ShieldCheck size={19} weight="duotone" />
        </span>
        <div>
          <span>{technicalFailure ? "Анализ остановлен" : "Анализ завершен"}</span>
          <strong>{technicalFailure ? "ТЕХНИЧЕСКАЯ ОШИБКА" : gateLabel(gate.decision)}</strong>
        </div>
      </div>

      {!technicalFailure ? <div className="summary-counts" aria-label="Число уникальных находок">
        <span className="count-confirmed"><strong>{counts.confirmed}</strong> подтверждено</span>
        <span className="count-rejected"><strong>{counts.rejected}</strong> опровергнуто</span>
        <span className="count-inconclusive"><strong>{counts.inconclusive}</strong> недостаточно данных</span>
        {counts.policy_blocked > 0 ? (
          <span><strong>{counts.policy_blocked}</strong> заблокировано политикой</span>
        ) : null}
      </div> : null}

      {confirmed.length > 0 ? (
        <div className="top-findings">
          <span>Подтверждённые находки</span>
          <ol>
            {confirmed.map(({ report, duplicates }) => (
              <li key={report.finding_id}>
                <span className={`severity ${severityTone(report.finding.severity === "ERROR" ? "HIGH" : report.finding.severity === "WARNING" ? "MEDIUM" : report.finding.severity)}`}>
                  {severityLabel(report.finding.severity)}
                </span>
                <span>{findingTitle(report.finding.rule_id, report.finding.title)}
                  <small className="summary-finding-path">{report.finding.file}:{report.finding.line_start}</small>
                  {duplicates.length > 0 ? <small className="summary-finding-duplicates">Объединено записей: {duplicates.length + 1}</small> : null}
                </span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      <Link className="summary-link" to={`/runs/${run.id}`}>
        Открыть полный отчет
        <ArrowSquareOut size={15} />
      </Link>
    </article>
  );
}

function severityRank(severity: string | null | undefined): number {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    default:
      return 0;
  }
}
