import { useEffect, useRef, useState } from "react";
import { ArrowDown, CaretRight, CircleNotch, ListChecks, WifiSlash } from "@phosphor-icons/react";
import type { SseState } from "../../hooks/useSse";
import type { ConversationTimelineItem } from "../../lib/timeline";
import { AssistantMessage } from "./AssistantMessage";
import { EvidenceBlock } from "./EvidenceBlock";
import { FindingBlock } from "./FindingBlock";
import { GateBlock } from "./GateBlock";
import {
  AgentDecisionBlock,
  DiscoveryBlock,
  FindingProgressBlock,
  RunStartBlock,
  StageBlock,
  TechnicalErrorBlock,
} from "./TimelineEvent";
import { ToolCall } from "./ToolCall";
import { UserMessage } from "./UserMessage";
import { SuggestedActions } from "./SuggestedActions";

export function Conversation({
  items,
  runActive,
  streamState,
  transientError,
  onRetry,
  onSuggestedAction,
}: {
  items: ConversationTimelineItem[];
  runActive: boolean;
  streamState: SseState;
  transientError: string | null;
  onRetry: () => void;
  onSuggestedAction: (prompt: string) => void;
}) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const followRef = useRef(true);
  const mountedRef = useRef(false);
  const [unread, setUnread] = useState(false);

  useEffect(() => {
    if (followRef.current) {
      bottomRef.current?.scrollIntoView({
        behavior: mountedRef.current ? "smooth" : "auto",
        block: "end",
      });
      setUnread(false);
    } else if (mountedRef.current) {
      setUnread(true);
    }
    mountedRef.current = true;
  }, [items.length, transientError]);

  const displayItems = groupRunActivity(items);

  const jumpToLatest = () => {
    followRef.current = true;
    setUnread(false);
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  };

  return (
    <div className="conversation-shell">
      <div
        ref={viewportRef}
        className="conversation-scroll"
        onScroll={(event) => {
          const element = event.currentTarget;
          const nearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 120;
          followRef.current = nearBottom;
          if (nearBottom) setUnread(false);
        }}
      >
        <div className="conversation-feed" aria-live="polite">
          {items.length === 0 && !runActive ? (
            <SuggestedActions onSelect={onSuggestedAction} />
          ) : null}
          {displayItems.map((entry) => entry.kind === "activity_group" ? (
            <RunActivity key={entry.id} items={entry.items} finished={entry.finished} onRetry={onRetry} />
          ) : (
            <div className={`timeline-entry ${entry.kind}`} key={entry.id}>
              <TimelineContent item={entry} onRetry={onRetry} />
            </div>
          ))}

          {runActive && streamState === "error" ? (
            <div className="stream-status">
              <WifiSlash size={15} />
              Соединение прервано. Переподключаемся…
            </div>
          ) : null}

          {transientError ? (
            <div className="inline-notice technical" role="alert">
              <strong>Сообщение не отправлено</strong>
              <span>{transientError}</span>
            </div>
          ) : null}
          <div ref={bottomRef} className="conversation-bottom" />
        </div>
      </div>

      {unread ? (
        <button type="button" className="jump-latest" onClick={jumpToLatest}>
          <ArrowDown size={15} />
          Новые события
        </button>
      ) : null}
    </div>
  );
}

function TimelineContent({
  item,
  onRetry,
}: {
  item: ConversationTimelineItem;
  onRetry: () => void;
}) {
  switch (item.kind) {
    case "message":
      return item.message.role === "user" ? (
        <UserMessage message={item.message} />
      ) : (
        <AssistantMessage message={item.message} />
      );
    case "run_start":
      return <RunStartBlock run={item.run} />;
    case "stage":
      return <StageBlock stage={item.stage} />;
    case "discovery":
      return <DiscoveryBlock discovery={item.discovery} />;
    case "finding_progress":
      return <FindingProgressBlock event={item.event} />;
    case "decision":
      return <AgentDecisionBlock decision={item.decision} report={item.report} />;
    case "tool":
      return <ToolCall tool={item.tool} />;
    case "evidence":
      return <EvidenceBlock evidence={item.evidence} />;
    case "finding":
      return <FindingBlock report={item.report} />;
    case "technical_error":
      return <TechnicalErrorBlock run={item.run} onRetry={onRetry} />;
    case "gate":
      return <GateBlock gate={item.gate} reports={item.reports} run={item.run} />;
  }
}

interface ActivityGroup {
  kind: "activity_group";
  id: string;
  items: ConversationTimelineItem[];
  finished: boolean;
}

function groupRunActivity(items: ConversationTimelineItem[]): (ConversationTimelineItem | ActivityGroup)[] {
  const groups = new Map<string, ActivityGroup>();
  const result: (ConversationTimelineItem | ActivityGroup)[] = [];
  for (const item of items) {
    const isActivity = item.runId && item.kind !== "gate" && item.kind !== "technical_error"
      && (item.kind !== "message" || (item.message.role !== "user" && item.message.kind === "status"));
    if (!isActivity || !item.runId) {
      result.push(item);
      continue;
    }
    let group = groups.get(item.runId);
    if (!group) {
      group = { kind: "activity_group", id: `activity:${item.runId}`, items: [], finished: false };
      groups.set(item.runId, group);
      result.push(group);
    }
    group.items.push(item);
  }
  for (const [runId, group] of groups) {
    group.finished = items.some(item => item.runId === runId && (
      item.kind === "gate" || item.kind === "technical_error"
      || (item.kind === "message" && item.message.kind === "summary")
      || (item.kind === "run_start" && !["queued", "running"].includes(item.run.status))
    ));
  }
  return result;
}

function RunActivity({ items, finished, onRetry }: {
  items: ConversationTimelineItem[];
  finished: boolean;
  onRetry: () => void;
}) {
  const [expanded, setExpanded] = useState(!finished);
  useEffect(() => { if (finished) setExpanded(false); }, [finished]);
  const latest = new Map<string, string>();
  for (const item of items) {
    if (item.kind === "stage") latest.set(`stage:${item.stage.stage}`, item.id);
    if (item.kind === "finding_progress") latest.set(`finding:${item.event.finding_id}`, item.id);
  }
  const hasDiscovery = items.some(item => item.kind === "discovery");
  const compact = items.filter(item => {
    if (item.kind === "run_start" || item.kind === "message") return false;
    if (item.kind === "stage") return !(hasDiscovery && item.stage.stage === "discovery")
      && latest.get(`stage:${item.stage.stage}`) === item.id;
    if (item.kind === "finding_progress") return latest.get(`finding:${item.event.finding_id}`) === item.id
      && !items.some(other => other.kind === "finding" && other.report.finding_id === item.event.finding_id);
    return true;
  });
  return (
    <section className={`run-activity ${finished ? "finished" : "active"}`}>
      <button type="button" className="run-activity-toggle" aria-expanded={expanded}
        onClick={() => setExpanded(value => !value)}>
        {finished ? <ListChecks size={18} /> : <CircleNotch size={18} className="spin" />}
        <span><strong>Ход проверки</strong><small>{finished ? "Действия и доказательства" : "Агент проверяет проект"}</small></span>
        <CaretRight size={16} className={expanded ? "rotated" : ""} />
      </button>
      {expanded ? <div className="run-activity-body">
        {compact.length ? compact.map(item => <div className={`timeline-entry ${item.kind}`} key={item.id}>
          <TimelineContent item={item} onRetry={onRetry} />
        </div>) : <p className="run-activity-wait">Подготовка анализа…</p>}
      </div> : null}
    </section>
  );
}
