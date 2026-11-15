import type { GroupedReport } from "../../api/types";
import { findingStatusLabel } from "../../lib/format";
import { FindingBlock } from "./FindingBlock";

export function GroupedFindingBlock({ group }: { group: GroupedReport }) {
  const reports = [group.report, ...group.duplicates];
  const sources = [...new Set(reports.map((report) => sourceLabel(report.finding.source)))];
  const verdicts = [...new Set(reports.map((report) => findingStatusLabel(report.status)))];

  return (
    <div className="grouped-finding">
      <FindingBlock report={group.report} />
      {reports.length > 1 ? (
        <details className="finding-merge-note">
          <summary>
            Сведено в одну карточку: {reports.length} отчёта · Источники: {sources.join(", ")}
          </summary>
          <ul>
            {reports.map((report) => (
              <li key={report.finding_id}>
                {sourceLabel(report.finding.source)}: {findingStatusLabel(report.status)}
                {report.finding.rule_id ? ` · ${report.finding.rule_id}` : ""}
              </li>
            ))}
            {verdicts.length > 1 ? (
              <li>В исходных отчётах есть разные вердикты; объединённый статус показан по общим доказательствам.</li>
            ) : null}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function sourceLabel(source: string): string {
  const normalized = source.toLowerCase().replaceAll("-", "_");
  if (normalized === "semgrep" || normalized === "sast") return "статический анализ";
  if (normalized === "model_scout" || normalized === "repository_scout") return "разведчик кода";
  return source;
}
