import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRun, getGate, getRunProgress, getPatchProposal, listProjects, listRuns } from "../api/client";
import type { ApiRun, GateResult, RunProgress } from "../api/types";
import { DemoPage } from "./DemoPage";

vi.mock("../api/client", () => ({
  createRun: vi.fn(), getGate: vi.fn(), getRunProgress: vi.fn(),
  listProjects: vi.fn(), listRuns: vi.fn(),
  getPatchProposal: vi.fn(), proposePatch: vi.fn(),
}));

const run: ApiRun = {
  id: "real-demo-run", target_id: "juice-presentation", status: "completed",
  agent_mode: "llm", max_iterations: 2, analysis_request: null,
  created_at: "2026-10-08T09:00:00Z", started_at: "2026-10-08T09:00:00Z",
  finished_at: "2026-10-08T09:01:00Z", exit_code: 1, gate_decision: "fail", error: null,
};
const gate: GateResult = {
  schema_version: "1.0", decision: "fail", exit_code: 1, decision_basis: "security_policy",
  reports_total: 7, confirmed: 4, rejected: 0, inconclusive: 3, policy_blocked: 0,
  technical_errors: 0, reasons: [], findings: [],
};
const progress: RunProgress = {
  stages: [{ stage: "scout", status: "done", detail: "0 candidates; reviewed files 0; stop model_unavailable", at: null }],
  activities: [], finding_events: [], findings_total: 7, findings_done: 7, current_finding: null,
};

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><DemoPage /></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(listProjects).mockResolvedValue([{ id: "juice-presentation", name: "Demo",
    environment: "sandbox", services: ["juice"], repository_available: true }]);
  vi.mocked(listRuns).mockResolvedValue([run]);
  vi.mocked(getGate).mockResolvedValue(gate);
  vi.mocked(getRunProgress).mockResolvedValue(progress);
  vi.mocked(getPatchProposal).mockResolvedValue(null);
});
afterEach(cleanup);

describe("presentation page", () => {
  it("shows real run results and does not hide a failed source search", async () => {
    show();
    expect(await screen.findByLabelText("Измеренные результаты прогона")).toBeTruthy();
    expect(await screen.findByText(/Поиск модели:.*модель недоступна/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /Открыть действия/ }).getAttribute("href")).toBe("/runs/real-demo-run");
    expect(createRun).not.toHaveBeenCalled();
  });

  it("does not invent counts for an active run", async () => {
    vi.mocked(listRuns).mockResolvedValue([{ ...run, status: "running", finished_at: null }]);
    show();
    const button = await screen.findByRole("button", { name: "Анализ выполняется" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByLabelText("Измеренные результаты прогона")).toBeNull();
    expect(getGate).not.toHaveBeenCalled();
  });

  it("does not substitute an old completed run for the newest technical failure", async () => {
    vi.mocked(listRuns).mockResolvedValue([{ ...run, id: "new-failure", status: "technical_failure",
      error: { code: "TIMEOUT", layer: "pipeline", message: "Target did not start", retryable: true } }, run]);
    show();
    expect(await screen.findByText("Target did not start")).toBeTruthy();
    expect(screen.queryByLabelText("Измеренные результаты прогона")).toBeNull();
    expect(getGate).not.toHaveBeenCalled();
  });
});
