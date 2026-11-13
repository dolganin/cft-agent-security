import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FinalReport } from "../../api/types";
import { FindingBlock } from "./FindingBlock";

describe("B08 scoring presentation", () => {
  it.each([
    ["CVSS:3.1/B", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS 3.1: 9.8 · КРИТИЧЕСКАЯ"],
    ["CVSS:3.0/B", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS 3.1: Не оценено"],
  ])("displays only the current scheme as a current numeric score", (scheme, vector, expected) => {
    const report = {
      finding: { id: "fixture", file: "example.ts", title: "Fixture", rule_id: "fixture" },
      status: "inconclusive", evidence: [], limitations: [], explanation: "Not verified", next_step: "Review",
      cvss: { score: 9.8, severity: "CRITICAL", vector, scheme, assessment_status: "assessed" },
    } as unknown as FinalReport;
    render(<FindingBlock report={report} />);
    expect(screen.getByText((_, element) => element?.tagName === "P" && element.textContent === expected)).toBeTruthy();
  });
  it("distinguishes partial priority, ordinal impact and missing CVSS", () => {
    const report = {
      finding: { id: "fixture", file: "example.ts", severity: "ERROR", title: "Fixture", rule_id: "fixture" },
      status: "inconclusive", evidence: [], limitations: [], explanation: "Not verified", next_step: "Review",
      cvss: { score: null, severity: "UNASSESSED", vector: "UNASSESSED", assessment_status: "unassessed" },
      context_priority: { level: "HIGH", score: 7, assessment_status: "partial", unknown_inputs: ["authentication"] },
      technical_severity: { level: "HIGH", scheme: "source-impact.a04.v1", assessment_status: "assessed" },
    } as unknown as FinalReport;
    render(<FindingBlock report={report} />);
    expect(screen.getByText("Не оценено").closest("p")?.textContent).toBe("CVSS 3.1: Не оценено");
    expect(screen.getByText("Предварительный").closest("p")?.textContent).toBe("Контекстный приоритет: ВЫСОКАЯПредварительный");
    expect(screen.getByText("Неизвестные данные: аутентификация")).toBeTruthy();
    expect(screen.getByTitle("Уровень исходного сканера, не CVSS")).toBeTruthy();
    expect(screen.getByTitle("source-impact.a04.v1").closest("p")?.textContent).toBe("Оценка по исходникам: ВЫСОКАЯ");
  });
});
