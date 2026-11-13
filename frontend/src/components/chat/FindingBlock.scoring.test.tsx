import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FinalReport } from "../../api/types";
import { FindingBlock } from "./FindingBlock";

describe("B08 scoring presentation", () => {
  it("distinguishes partial priority, ordinal impact and missing CVSS", () => {
    const report = {
      finding: { id: "fixture", file: "example.ts", severity: "ERROR", title: "Fixture", rule_id: "fixture" },
      status: "inconclusive", evidence: [], limitations: [], explanation: "Not verified", next_step: "Review",
      cvss: { score: null, severity: "UNASSESSED", vector: "UNASSESSED", assessment_status: "unassessed" },
      context_priority: { level: "HIGH", score: 7, assessment_status: "partial", unknown_inputs: ["authentication"] },
      technical_severity: { level: "HIGH", scheme: "source-impact.a04.v1", assessment_status: "assessed" },
    } as unknown as FinalReport;
    render(<FindingBlock report={report} />);
    expect(screen.getByText("Не оценено").closest("p")?.textContent).toBe("CVSS 4.0: Не оценено");
    expect(screen.getByText("Предварительный").closest("p")?.textContent).toBe("Контекстный приоритет: ВЫСОКАЯПредварительный");
    expect(screen.getByText("Неизвестные данные: аутентификация")).toBeTruthy();
    expect(screen.getByTitle("Уровень исходного сканера, не CVSS")).toBeTruthy();
    expect(screen.getByTitle("source-impact.a04.v1").closest("p")?.textContent).toBe("Оценка по исходникам: ВЫСОКАЯ");
  });
});
