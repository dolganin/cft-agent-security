import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ConversationTimelineItem } from "../../lib/timeline";
import { Conversation } from "./Conversation";

const stage = (id: string, detail: string): ConversationTimelineItem => ({
  id, runId: "run-1", at: "2026-11-13T00:00:00Z", sortTime: 0, sortRank: 30,
  kind: "stage", stage: { stage: "source_scout", status: "running", detail, at: null },
});

describe("compact run activity", () => {
  it("replaces repeated progress and collapses on the final answer, retaining details", () => {
    Element.prototype.scrollIntoView = vi.fn();
    const props = { runActive: true, streamState: "live" as const, transientError: null,
      onRetry: vi.fn(), onSuggestedAction: vi.fn() };
    const items = [stage("s1", "first progress"), stage("s2", "latest progress")];
    const { rerender } = render(<Conversation {...props} items={items} />);
    expect(screen.queryByText("first progress")).toBeNull();
    expect(screen.getByText("latest progress")).toBeTruthy();
    const summary = { ...items[0], id: "summary", kind: "message", message: {
      id: "m1", role: "assistant", kind: "summary", content: "Итоговый ответ",
      created_at: "2026-11-13T00:01:00Z", run_id: "run-1",
    } } as ConversationTimelineItem;
    rerender(<Conversation {...props} runActive={false} items={[...items, summary]} />);
    expect(screen.getByText("Итоговый ответ")).toBeTruthy();
    expect(screen.queryByText("latest progress")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Ход проверки/ }));
    expect(screen.getByText("latest progress")).toBeTruthy();
  });
});
