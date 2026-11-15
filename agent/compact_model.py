"""One provider roundtrip per registered verification turn, with normal graph checks.

Opt-in for the small presentation target. Cached reasoning is private to this
adapter and bound to the complete input and candidate set, never reused across
findings, source snapshots or Evidence iterations. Execution is still sequential.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import copy_context
from hashlib import sha256

from pydantic import BaseModel, ConfigDict

from agent.budget import reasoning_budget
from agent.llm import LLMUnavailableError
from agent.llm_model import FallbackLLMAgentModel, _public_candidate, _reasoning_context
from agent.prompts import SYSTEM_PROMPT
from agent.verification import verification_candidates
from pipeline.cancellation import check_cancelled
from schemas.agent_outputs import AnalysisResult
from schemas.hypothesis import Hypothesis
from schemas.llm import LLMRegisteredDynamicPlanChoice


class RegisteredReasoningTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis: AnalysisResult
    hypothesis: Hypothesis
    plan: LLMRegisteredDynamicPlanChoice | None


class CompactRegisteredAgentModel(FallbackLLMAgentModel):
    def __init__(self, client):
        super().__init__(client)
        self._turns = {}

    def _inputs(self, state):
        context = _reasoning_context(state)
        # Diagnostics grow between graph nodes but do not change the reasoning
        # input. Evidence, iteration, source, profile and runtime remain in key.
        context.pop("reasoning_events", None)
        candidates = verification_candidates(state)
        payload = {"state": context, "registered_candidates": [
            _public_candidate(candidate) for candidate in candidates
        ]}
        trusted = {"payload": payload, "candidates": [
            {key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
             for key, value in candidate.items()} for candidate in candidates
        ]}
        key = sha256(json.dumps(trusted, sort_keys=True, default=str).encode()).hexdigest()
        return key, payload, candidates

    def _request_turn(self, state):
        key, payload, candidates = self._inputs(state)
        payload["task"] = (
            "Analyse the supplied finding, then form one testable hypothesis and "
            "choose exactly one supplied registered candidate in a one-step plan. "
            "Keep facts, assumptions, hypothesis and observations explicit. Write "
            "all human-facing text in Russian, concisely without repeating the input. "
            "plan.max_steps MUST be 1 with exactly one step. If there are no "
            "registered candidates, return plan=null and explain the verification "
            "gap. This is planning only: never claim a confirmed or rejected verdict."
        )
        check_cancelled()
        with reasoning_budget(state):
            turn = self.client.complete_model(
                output_model=RegisteredReasoningTurn, system_prompt=SYSTEM_PROMPT,
                user_payload=payload, operation="registered_reasoning_turn",
            )
        if candidates:
            if turn.plan is None or turn.plan.max_steps != 1 or len(turn.plan.steps) != 1:
                raise ValueError("Expected one registered next step")
            if turn.plan.steps[0].candidate_id not in {c["candidate_id"] for c in candidates}:
                raise ValueError("Unknown registered candidate")
        elif turn.plan is not None:
            raise ValueError("Plan must be absent without a registered candidate")
        return key, turn

    def analyse(self, state):
        turn = self._cached(state)
        if turn is not None:
            return turn.analysis.model_copy(deep=True)
        try:
            key, turn = self._request_turn(state)
            self._turns[key] = turn
            return turn.analysis.model_copy(deep=True)
        except (LLMUnavailableError, ValueError) as exc:
            self._record_application_event("registered_reasoning_turn", "fallback", type(exc).__name__)
            # Retain the existing full adapter when a compact answer is invalid.
            return super().analyse(state)

    def _cached(self, state):
        key, _, _ = self._inputs(state)
        return self._turns.get(key)

    def prefetch(self, states, *, workers=2):
        """Only model requests overlap; each thread owns its provider client.

        Context includes cancellation and deadlines. The parent alone merges
        completed responses; no approvals, HTTP probes or target code run here.
        """
        from app.config import settings

        def request(state):
            child = type(self).from_settings(settings)
            child.client.diagnostics_path = self.client.diagnostics_path
            return child._request_turn(state)

        with ThreadPoolExecutor(max_workers=min(2, max(1, workers))) as pool:
            futures = [pool.submit(copy_context().run, request, state) for state in states]
            try:
                for future in as_completed(futures):
                    check_cancelled()
                    try:
                        key, turn = future.result()
                    except (LLMUnavailableError, ValueError):
                        # Canonical graph retries via its existing adapter path.
                        continue
                    self._turns[key] = turn
            finally:
                for future in futures:
                    future.cancel()

    def form_hypothesis(self, state, analysis):
        turn = self._cached(state)
        if turn is not None and turn.analysis == analysis:
            return turn.hypothesis.model_copy(deep=True)
        return super().form_hypothesis(state, analysis)

    def _choose_plan(self, state, **kwargs):
        turn = self._cached(state)
        if (turn is not None and turn.plan is not None
                and turn.analysis == state.get("analysis")
                and turn.hypothesis == state.get("hypothesis")):
            # Base build_plan rechecks IDs, reconstructs trusted parameters and
            # produces the ordinary DynamicPlan for Validator/Executor.
            return turn.plan.model_copy(deep=True)
        return super()._choose_plan(state, **kwargs)
