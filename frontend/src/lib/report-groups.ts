import type { FinalReport, FindingStatus, GroupedReport } from "../api/types";

/**
 * Group findings tied to the same snapshot/file/family and an exact line or
 * uniquely bound operator route with overlapping ranges. Unbound reports stay separate.
 */
export function groupReports(reports: FinalReport[]): GroupedReport[] {
  const anchored = new Map<string, FinalReport[]>();
  const unanchored: FinalReport[][] = [];

  for (const report of reports) {
    const key = sourceKey(report);
    if (!key) {
      unanchored.push([report]);
      continue;
    }
    const bucket = anchored.get(key) ?? [];
    bucket.push(report);
    anchored.set(key, bucket);
  }

  const groups = [...unanchored];
  for (const bucket of [...anchored.values()].flatMap(splitSourceBucket)) {
    const preciseColumns = new Set(
      bucket.map(columnKey).filter((value): value is string => value !== null),
    );
    if (preciseColumns.size > 1) {
      // Two distinct sinks on the same line are separate issues. A report
      // without a column cannot safely be assigned to either one.
      const byColumn = new Map<string, FinalReport[]>();
      for (const report of bucket) {
        const column = columnKey(report);
        const groupKey = column ?? `unmapped:${report.finding_id}`;
        byColumn.set(groupKey, [...(byColumn.get(groupKey) ?? []), report]);
      }
      groups.push(...byColumn.values());
    } else {
      groups.push(bucket);
    }
  }

  return groups.map(makeGroup).sort((left, right) => {
    const a = left.report.finding;
    const b = right.report.finding;
    return a.file.localeCompare(b.file)
      || (a.line_start ?? 0) - (b.line_start ?? 0)
      || a.id.localeCompare(b.id);
  });
}

function sourceKey(report: FinalReport): string | null {
  const finding = report.finding;
  const provenance = finding.provenance;
  if (!provenance?.file_sha256 || finding.line_start == null) return null;
  const family = canonicalFamily(finding.rule_id, provenance.family);
  const resolution = report.binding_resolution;
  const binding = resolution?.status === "bound" ? resolution.binding : null;
  const location = binding?.source_file === finding.file
    ? ["route", binding.route_id, binding.source_snapshot, binding.map_sha256].join(":")
    : `line:${finding.line_start}`;
  return [
    provenance.file_sha256,
    finding.service ?? "",
    provenance.normalized_file || finding.file,
    family,
    location,
  ].join("\u001f");
}

function splitSourceBucket(bucket: FinalReport[]): FinalReport[][] {
  const scanners = bucket.filter((item) => item.finding.source !== "model_scout");
  if (scanners.length === 1) {
    const primary = scanners[0];
    const matches = bucket.filter((item) => {
      const a = primary.finding;
      const b = item.finding;
      return Math.max(a.line_start!, b.line_start!)
        <= Math.min(a.line_end ?? a.line_start!, b.line_end ?? b.line_start!);
    });
    return [matches, ...bucket.filter((item) => !matches.includes(item)).map((item) => [item])];
  }
  // Do not let a broad model window choose among multiple scanner sinks.
  const byStart = new Map<number, FinalReport[]>();
  for (const item of bucket) {
    const start = item.finding.line_start!;
    byStart.set(start, [...(byStart.get(start) ?? []), item]);
  }
  return [...byStart.values()];
}

function canonicalFamily(ruleId: string, recordedFamily: string): string {
  const rule = ruleId.toLowerCase().replaceAll("_", "-");
  // Specific vulnerability types take precedence over broad labels such as
  // authentication (some historical scanner rules contain both words).
  if (/nosql[-_. ]?injection|nosql[-_. ]?where/.test(rule)) return "nosql-injection";
  if (/sql[-_. ]?injection|sequelize[-_. ]?injection|\bsqli\b/.test(rule)) return "sql-injection";
  if (/\bidor\b|access[-_. ]?control|broken[-_. ]?authorization/.test(rule)) return "access-control";
  if (/directory[-_. ]?listing|file[-_. ]?exposure|sensitive[-_. ]?directory/.test(rule)) return "file-exposure";
  return recordedFamily.toLowerCase().replaceAll("_", "-");
}

function columnKey(report: FinalReport): string | null {
  const spans = new Set(
    (report.finding.provenance?.observations ?? [])
      .filter((item) => item.column_start != null)
      .map((item) => `${item.column_start}:${item.column_end ?? ""}`),
  );
  return spans.size === 1 ? [...spans][0] : null;
}

function makeGroup(reports: FinalReport[]): GroupedReport {
  const primary = [...reports].sort((left, right) => {
    const statusDiff = statusRank(right.status) - statusRank(left.status);
    return statusDiff || right.evidence.length - left.evidence.length
      || left.finding_id.localeCompare(right.finding_id);
  })[0];
  const status = combinedStatus(reports.map((item) => item.status));
  const evidence = uniqueBy(reports.flatMap((item) => item.evidence), (item) => item.id);
  const actions = uniqueBy(reports.flatMap((item) => item.sandbox_actions), (item) => item.action_id);
  const verificationTypes = [...new Set(reports.flatMap((item) => item.verification.evidence_types))];

  return {
    report: {
      ...primary,
      status,
      evidence,
      sandbox_actions: actions,
      verification: {
        ...primary.verification,
        evidence_count: evidence.length,
        evidence_types: verificationTypes,
      },
    },
    duplicates: reports.filter((item) => item.finding_id !== primary.finding_id),
  };
}

function combinedStatus(statuses: FindingStatus[]): FindingStatus {
  const values = new Set(statuses);
  if (values.has("confirmed") && values.has("rejected")) return "inconclusive";
  if (values.has("confirmed")) return "confirmed";
  if (values.has("inconclusive")) return "inconclusive";
  if (values.has("rejected")) return "rejected";
  return "policy_blocked";
}

function statusRank(status: FindingStatus): number {
  return { confirmed: 4, rejected: 3, inconclusive: 2, policy_blocked: 1 }[status];
}

function uniqueBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const value = key(item);
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}
