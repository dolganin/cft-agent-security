import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getFixVerification, getPatchProposal, proposePatch, verifyFix } from "../../api/client";
import type { PatchReviewArtifact } from "../../api/types";
import { PatchProposalPanel } from "./PatchProposalPanel";

vi.mock("../../api/client", () => ({ getPatchProposal: vi.fn(), proposePatch: vi.fn(), getFixVerification: vi.fn(), verifyFix: vi.fn() }));
const artifact: PatchReviewArtifact = {
  schema_version: "1.0", id: "p1", run_id: "r1", finding_id: "f1", file: "routes/search.ts",
  status: "ready_for_review", source_sha256: "source", proposal_sha256: "patch",
  model: "test/model", generated_at: "2026-10-08T10:00:00Z", applied: false, security_verified: false,
  proposal: { finding_id: "f1", rationale: "Параметризация запроса", unified_diff: "--- a/routes/search.ts\n+++ b/routes/search.ts\n" },
  validation_detail: "Область проверена", limitations: ["Патч не применялся"],
};
function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><PatchProposalPanel runId="r1" /></QueryClientProvider>);
}
beforeEach(() => { vi.resetAllMocks(); vi.mocked(getPatchProposal).mockResolvedValue(null); vi.mocked(getFixVerification).mockResolvedValue(null); });
afterEach(cleanup);

describe("patch proposal panel", () => {
  it("shows the complete fix result separately from the proposal", async () => {
    vi.mocked(getPatchProposal).mockResolvedValue(artifact);
    vi.mocked(verifyFix).mockResolvedValue({ id: "fix1", run_id: "r1", status: "FIXED",
      applied: true, security_verified: true, original_unchanged: true, cleanup_complete: true,
      explanation: "Original bounded SQL probe repeated", before_evidence: { verdict: "confirmed" },
      after_evidence: { verdict: "rejected" }, stages: [{ phase: "after", stage: "tests", status: "passed", duration_ms: 1 }] });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Проверить исправление в изолированной копии" }));
    expect(await screen.findByText("FIXED · Security verified: true")).toBeTruthy();
    expect(screen.getByText("Before: confirmed · After: rejected")).toBeTruthy();
    expect(screen.getByText("Original unchanged: true · Cleanup: true")).toBeTruthy();
    expect(verifyFix).toHaveBeenCalledExactlyOnceWith("r1");
  });
  it("requires a user action and clearly separates a proposal from a verified fix", async () => {
    vi.mocked(proposePatch).mockResolvedValue(artifact);
    show();
    const button = await screen.findByRole("button", { name: "Предложить исправление" });
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    expect(proposePatch).not.toHaveBeenCalled();
    fireEvent.click(button);
    expect(await screen.findByText("Параметризация запроса")).toBeTruthy();
    expect(screen.getByText("Патч не применялся")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Скачать патч для ревью" }).getAttribute("download")).toBe("security-fix-proposal.patch");
    expect(proposePatch).toHaveBeenCalledExactlyOnceWith("r1");
  });
  it("never offers a rejected proposal for download", async () => {
    vi.mocked(getPatchProposal).mockResolvedValue({ ...artifact, status: "rejected" });
    show();
    expect(await screen.findByText(/Предложение отклонено/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Скачать патч для ревью" })).toBeNull();
  });
  it("shows a model failure without claiming a fix", async () => {
    vi.mocked(proposePatch).mockRejectedValue(new Error("Модель недоступна"));
    show();
    const button = await screen.findByRole("button", { name: "Предложить исправление" });
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(button);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Модель недоступна");
    expect(screen.queryByRole("link", { name: "Скачать патч для ревью" })).toBeNull();
  });
});
