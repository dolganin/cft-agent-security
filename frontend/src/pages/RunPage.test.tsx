import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getGate, getReports, getRun, getRunProgress } from "../api/client";
import type { ApiRun, GateResult } from "../api/types";
import { GateBlock } from "../components/chat/GateBlock";
import { RunPage } from "./RunPage";

vi.mock("../api/client", () => ({
  getGate: vi.fn(), getReports: vi.fn(), getRun: vi.fn(), getRunProgress: vi.fn(),
  runEventsUrl: () => "",
}));

const run: ApiRun = {
  id: "run-1", target_id: "demo", status: "completed", agent_mode: "llm",
  max_iterations: 1, analysis_request: null, created_at: "2026-11-15T00:00:00Z",
  started_at: "2026-11-15T00:00:00Z", finished_at: "2026-11-15T00:01:00Z",
  exit_code: 0, gate_decision: "pass", error: null,
};
const gate: GateResult = {
  schema_version: "1.0", decision: "pass", exit_code: 0,
  decision_basis: "no_blocking_condition", reports_total: 0, confirmed: 0,
  rejected: 0, inconclusive: 0, policy_blocked: 0, technical_errors: 0,
  reasons: [], findings: [],
};

beforeEach(() => {
  vi.mocked(getRun).mockResolvedValue(run);
  vi.mocked(getReports).mockResolvedValue([]);
  vi.mocked(getGate).mockResolvedValue(gate);
  vi.mocked(getRunProgress).mockResolvedValue({
    stages: [], activities: [], finding_events: [], findings_total: 0,
    findings_done: 0, current_finding: null,
  });
});

function show(path: string, state?: unknown) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>
    <MemoryRouter initialEntries={[{ pathname: path, state }]}>
      <Routes>
        <Route path="/chats/:sessionId" element={<GateBlock gate={gate} reports={[]} run={run} />} />
        <Route path="/runs/:runId" element={<RunPage />} />
      </Routes>
    </MemoryRouter>
  </QueryClientProvider>);
}

describe("chat report navigation", () => {
  it("returns to the originating chat after opening its full report", async () => {
    show("/chats/chat-123");
    await userEvent.click(screen.getByRole("link", { name: "Открыть полный отчет" }));
    const back = await screen.findByRole("link", { name: "Вернуться в чат" });
    expect(back.getAttribute("href")).toBe("/chats/chat-123");
    await userEvent.click(back);
    expect(screen.queryByRole("link", { name: "Вернуться в чат" })).toBeNull();
    expect(screen.getByRole("link", { name: "Открыть полный отчет" })).toBeTruthy();
  });

  it("falls back to chats for an external or unrecognized return location", async () => {
    show("/runs/run-1", { returnToChat: "https://example.invalid" });
    const back = await screen.findByRole("link", { name: "К чатам" });
    expect(back.getAttribute("href")).toBe("/");
    expect(screen.queryByRole("link", { name: "Прогоны и диагностика" })).toBeNull();
  });
});
