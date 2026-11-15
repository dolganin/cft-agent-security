import { describe, expect, it } from "vitest";
import type { FinalReport } from "../api/types";
import { groupReports } from "./report-groups";

function report(id: string, source: string, start: number, end: number): FinalReport {
  return {
    finding_id: id,
    finding: { id, source, rule_id: "idor", title: "Order access", file: "routes/orders.js",
      line_start: start, line_end: end, service: "store", provenance: {
        family: "access-control", normalized_file: "routes/orders.js", file_sha256: "a".repeat(64),
        anchor_sha256: "b".repeat(64), anchor_status: "source_bound", aliases: [id], observations: [],
      } },
    binding_resolution: { status: "bound", binding: { route_id: "orders", source_file: "routes/orders.js",
      source_snapshot: "c".repeat(64), map_sha256: "d".repeat(64) } },
    status: "confirmed", evidence: [], sandbox_actions: [],
    verification: { validator_decision: "approved", evidence_count: 0, evidence_types: [], decision_basis: "evidence" },
  } as unknown as FinalReport;
}

describe("groupReports", () => {
  it("combines a broad scout window with one overlapping bound scanner sink", () => {
    const groups = groupReports([report("sast", "semgrep", 12, 16), report("scout", "model_scout", 10, 17)]);
    expect(groups).toHaveLength(1);
    expect(groups[0].duplicates).toHaveLength(1);
  });

  it("retains disjoint source windows and different operator snapshots", () => {
    const primary = report("sast", "semgrep", 12, 16);
    const other = report("scout", "model_scout", 10, 17);
    other.binding_resolution!.binding!.source_snapshot = "e".repeat(64);
    expect(groupReports([primary, other])).toHaveLength(2);
    expect(groupReports([primary, report("disjoint", "model_scout", 20, 22)])).toHaveLength(2);
  });

  it("does not let a model window choose between two scanner sinks", () => {
    expect(groupReports([report("a", "semgrep", 12, 12), report("b", "semgrep", 15, 15),
      report("scout", "model_scout", 10, 17)])).toHaveLength(3);
  });
});
