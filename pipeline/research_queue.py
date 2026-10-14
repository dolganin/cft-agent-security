"""Lossless scanner/model import and fair exploration scheduling; no benchmark labels."""
from hashlib import sha256

from discovery.scout import merge_scout_candidates
from sast.identity import deduplicate_findings, normalize_finding
from schemas.finding import Finding
from schemas.research_campaign import ResearchQuestion, RuntimeScannerObservation


class ResearchQueue:
    def __init__(self, *, profile, source_map, source_files, preferred_families=()):
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

    def next_question(self):
        channels = ("model", "sast", "surface", "dast")
        for offset in range(4):
            channel = channels[(self.cursor + offset) % 4]
            options = [x for x in self.questions if x.status == "pending" and x.origin == channel]
            if options:
                self.cursor = (self.cursor + offset + 1) % 4
                return min(options, key=lambda q: (q.finding.provenance is None or
                    q.finding.provenance.family not in self.preferred_families, q.finding.file, q.id))
        return None

    def complete(self, question, *, failed=False):
        question.status = "failed" if failed else "researched"
        if not failed:
            self.aliases_researched.update(question.finding.provenance.aliases
                if question.finding.provenance else [question.finding.id])

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
                "source_line_coverage_is_not_vulnerability_recall": True}
