"""Lossless scanner/model import and fair exploration scheduling; no benchmark labels."""
from hashlib import sha256

from discovery.scout import merge_scout_candidates
from sast.identity import deduplicate_findings, normalize_finding, rule_family
from schemas.finding import Finding
from schemas.research_campaign import ResearchQuestion, RuntimeScannerObservation


class ResearchQueue:
    def __init__(self, *, profile, source_map, source_files, preferred_families=(), verification_paths=()):
        self.profile, self.source_map = profile, source_map
        self.source_files = set(source_files)
        self.raw = []
        self.findings = []
        self.questions = []
        self.rejections = []
        self.aliases_researched = set()
        self.cursor = 0
        self.origins = {}
        self.runtime_signals = {}
        self.preferred_families = set(preferred_families)
        self.verification_paths = set(verification_paths)
        self.grouped_questions = {}
        self.completed_work = {}

    @staticmethod
    def work_key(finding):
        """Coalesce only identical source anchors/families, preserving all findings.

        The explicit research adapter aliases are routing vocabulary, not evidence.
        Different lines/column sinks, unbound observations and different properties
        remain independent work. No confirmation is copied to a grouped observation.
        """
        from pipeline.research_verification import verification_finding

        p = finding.provenance
        if p is None or p.anchor_status != "source_bound":
            return (finding.id,)
        columns = {(o.column_start, o.column_end) for o in p.observations if o.column_start is not None}
        return (finding.service, finding.file, finding.line_start, finding.line_end or finding.line_start,
                p.file_sha256, p.anchor_sha256, rule_family(verification_finding(finding).rule_id),
                tuple(sorted(columns, key=lambda span: (span[0], span[1] or 0))))

    def related_observations(self, question):
        key = self.work_key(question.finding)
        return [q.finding.model_dump(mode="json") for q in self.questions
                if q.is_candidate and self.work_key(q.finding) == key][:16]

    def import_findings(self, findings, origin):
        if origin not in {"sast", "dast"}:
            raise ValueError("Explicit scanner origin is required")
        accepted = []
        for item in findings:
            self.raw.append({"origin": origin, "finding": item.model_dump(mode="json")})
            try:
                runtime = None
                if isinstance(item, RuntimeScannerObservation):
                    if origin != "dast" or item.service not in self.profile.services:
                        raise ValueError("Runtime scanner references an unknown service")
                    runtime = item
                    identifier = "runtime-" + sha256((item.source + item.id).encode()).hexdigest()[:24]
                    item = Finding(id=identifier, source=runtime.source, rule_id=runtime.rule_id, title=runtime.title,
                        description=runtime.description + "\nObserved endpoint: " + runtime.endpoint,
                        file="_runtime/" + identifier, service=runtime.service)
                normalized = normalize_finding(item, repository_root=self.profile.repository_path,
                    service_resolver=(lambda _path, value=runtime: value.service) if runtime else self._service)
                if runtime is not None:
                    normalized = normalized.model_copy(update={"service": runtime.service})
                    self.runtime_signals[normalized.id] = runtime
                elif normalized.file not in self.source_files:
                    raise ValueError("Finding outside projected application inventory")
                accepted.append(normalized)
                self.origins[item.id] = origin
            except ValueError as exc:
                self.rejections.append({"id": item.id, "reason": str(exc)})
        self.findings, _ = deduplicate_findings([*self.findings, *accepted])
        self._refresh()

    def import_candidates(self, candidates):
        candidates = list(candidates)
        self.raw.extend({"origin": "model", "candidate": x.model_dump(mode="json")} for x in candidates)
        safe = []
        for item in candidates:
            if item.file not in self.source_files or not set(item.provenance_paths) <= self.source_files:
                self.rejections.append({"id": item.rule_id, "reason": "Candidate provenance outside source inventory"})
            else:
                safe.append(item)
        self.findings, _ = merge_scout_candidates(self.findings, safe,
            repository_root=self.profile.repository_path, service_resolver=self._service)
        self._refresh()

    def _service(self, path):
        for finding_id, signal in self.runtime_signals.items():
            if path == "_runtime/" + finding_id:
                return signal.service
        return self.profile.resolve_service(path)

    def _refresh(self):
        previous = {x.id: x for x in self.questions}
        questions = []
        for finding in self.findings:
            aliases = set(finding.provenance.aliases) if finding.provenance else {finding.id}
            sources = {x.source for x in finding.provenance.observations} if finding.provenance else {finding.source}
            origin = "model" if sources == {"model_scout"} else "dast" if any(self.origins.get(alias) == "dast" for alias in aliases) else "sast"
            questions.append(ResearchQuestion(id=finding.id, finding=finding, origin=origin, is_candidate=True,
                runtime_observation=self.runtime_signals.get(finding.id),
                status="researched" if aliases & self.aliases_researched else previous.get(finding.id, ResearchQuestion(
                    id=finding.id, finding=finding, origin=origin, is_candidate=True)).status))
        covered = {x.finding.file for x in questions}
        for route in self.source_map.routes:
            path = next((p for p in route.handler_files if p in self.source_files), route.file)
            if path not in self.source_files or path in covered:
                continue
            identifier = "surface-" + sha256(path.encode()).hexdigest()[:20]
            finding = Finding(id=identifier, source="surface_question", rule_id="unexamined-handler",
                title="Investigate an unexamined application handler", description="Explore independently; no vulnerability is asserted",
                file=path, line_start=1, service=self.profile.resolve_service(path))
            questions.append(ResearchQuestion(id=identifier, finding=finding, origin="surface", is_candidate=False,
                route_ids=[r.id for r in self.source_map.routes if path in r.handler_files or path == r.file],
                status=previous[identifier].status if identifier in previous else "pending"))
            covered.add(path)
        if not questions:
            for path in sorted(self.source_files)[:32]:
                identifier = "source-gap-" + sha256(path.encode()).hexdigest()[:20]
                questions.append(ResearchQuestion(id=identifier, origin="surface", is_candidate=False,
                    finding=Finding(id=identifier, source="surface_question", rule_id="unexamined-source",
                    title="Explore application source", description="No vulnerability is asserted", file=path, line_start=1),
                    status=previous[identifier].status if identifier in previous else "pending"))
        self.questions = questions
        for question in self.questions:
            representative = self.completed_work.get(self.work_key(question.finding)) if question.is_candidate else None
            if representative is not None and representative != question.id and question.status == "pending":
                question.status = "grouped"
                self.grouped_questions[question.id] = representative

    def next_question(self):
        channels = ("model", "sast", "surface", "dast")
        for offset in range(4):
            channel = channels[(self.cursor + offset) % 4]
            options = [x for x in self.questions if x.status == "pending" and x.origin == channel]
            if options:
                self.cursor = (self.cursor + offset + 1) % 4
                return min(options, key=self.priority)
        return None

    def priority(self, question):
        """Scheduling signals, NOT security severity or benchmark answers."""
        finding = question.finding
        preferred = bool(finding.provenance and finding.provenance.family in self.preferred_families)
        handler = finding.file.startswith(("routes/", "controllers/", "api/", "middleware/"))
        reachable = any(finding.file in r.handler_files or finding.file == r.file
                        for r in self.source_map.routes)
        signal = (finding.rule_id + " " + (finding.provenance.family if finding.provenance else "")).lower()
        direct_impact = any(word in signal for word in (
            "sql", "injection", "access", "traversal", "ssrf", "authentication", "command"))
        return (not preferred, not handler, finding.file not in self.verification_paths, not reachable, not direct_impact,
                finding.file, question.id)

    def complete(self, question, *, failed=False):
        question.status = "failed" if failed else "researched"
        if not failed:
            self.aliases_researched.update(question.finding.provenance.aliases
                if question.finding.provenance else [question.finding.id])
            if question.is_candidate:
                key = self.work_key(question.finding)
                self.completed_work[key] = question.id
                for related in self.questions:
                    if related.id != question.id and related.is_candidate and related.status == "pending" and self.work_key(related.finding) == key:
                        related.status = "grouped"
                        self.grouped_questions[related.id] = question.id

    def coverage(self, ledgers):
        read = set()
        for ledger in ledgers:
            for item in ledger:
                if item.tool == "read_source" and item.category == "observation":
                    for line in item.observation.get("content", "").splitlines():
                        number, sep, _ = line.partition(": ")
                        if sep and number.isdigit():
                            read.add((item.observation["path"], int(number)))
        files_read = {p for p, _ in read}
        return {"source_files": len(self.source_files), "files_read": len(files_read),
                "read_lines": len(read), "unread_files": sorted(self.source_files - files_read),
                "candidate_count": len(self.findings), "surface_questions_are_not_findings": True,
                "pending_questions": [x.id for x in self.questions if x.status == "pending"],
                "failed_questions": [x.id for x in self.questions if x.status == "failed"],
                "grouped_questions": dict(self.grouped_questions),
                "grouped_observations_have_no_inherited_verdict": True,
                "source_line_coverage_is_not_vulnerability_recall": True}
