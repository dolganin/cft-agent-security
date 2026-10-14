from cvss import CVSS4
from cvss.exceptions import CVSS4MalformedError, CVSS4MandatoryError

from schemas.architecture import ArchitectureContext
from schemas.finding import Finding
from schemas.scoring import ContextPriority, CVSSAssessmentInput, CVSSResult

_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

_NON_CVSS_RULE_PREFIXES = (
    "dockerfile.security.missing-user",
    "dockerfile.security.last-user-is-root",
)

_CRITICALITY_POINTS = {
    "critical": 2.0,
    "high": 2.0,
    "medium": 1.0,
    "normal": 1.0,
    "low": 0.0,
    "test": 0.0,
    "dev": 0.0,
    "development": 0.0,
    "unknown": 0.0,
}

_AUTHENTICATION_POINTS = {
    "none": 1.0,
    "unauthenticated": 1.0,
    "public": 1.0,
    "user": 0.5,
    "authenticated": 0.5,
    "admin": 0.0,
    "administrator": 0.0,
    "unknown": 0.0,
}

_BLAST_RADIUS_POINTS = {
    "many": 2.0,
    "shared": 2.0,
    "shared_infrastructure": 2.0,
    "several": 1.0,
    "limited": 1.0,
    "isolated": 0.0,
    "unknown": 0.0,
}


class ScoringService:
    def score(
        self,
        finding: Finding,
        context: ArchitectureContext,
        *,
        assessment: CVSSAssessmentInput | None = None,
        trusted_evidence_refs: frozenset[str] = frozenset(),
    ) -> tuple[CVSSResult, ContextPriority]:
        return (
            self.score_cvss(finding, assessment, trusted_evidence_refs=trusted_evidence_refs),
            self.score_context_priority(context),
        )

    def score_cvss(
        self,
        finding: Finding,
        assessment: CVSSAssessmentInput | None = None,
        *,
        trusted_evidence_refs: frozenset[str] = frozenset(),
    ) -> CVSSResult:
        """Вернуть безопасное для доказательств состояние CVSS без выдумывания отсутствующих метрик."""
        rule_id = finding.rule_id.lower()

        # Серьезность Semgrep сама по себе не дает оснований для числового CVSS
        if rule_id.startswith(_NON_CVSS_RULE_PREFIXES):
            return CVSSResult(
                vector="N/A",
                score=None,
                severity="N/A",
                assessment_status="not_applicable",
                reasoning=(
                    "This SAST finding is a container hardening/configuration issue. "
                    "Without a demonstrated vulnerability and justified CVSS 4.0 metrics, "
                    "a numeric base score would create false precision."
                ),
            )

        if assessment is not None:
            return self._calculate_cvss(finding, assessment, trusted_evidence_refs)

        return CVSSResult(
            vector="UNASSESSED",
            score=None,
            severity="UNASSESSED",
            missing_metrics=list(_BASE_METRICS),
            reasoning=(
                "CVSS 4.0 may apply, but explicit justified metric values are not present "
                "in the current workflow input. Semgrep severity is not converted into CVSS."
            ),
        )

    def _calculate_cvss(
        self,
        finding: Finding,
        assessment: CVSSAssessmentInput,
        trusted_refs: frozenset[str],
    ) -> CVSSResult:
        missing = [key for key in _BASE_METRICS if key not in assessment.metrics]
        problem = None
        if assessment.finding_id != finding.id:
            problem = "Metric assessment belongs to a different finding."
        elif set(assessment.metrics) - set(_BASE_METRICS):
            problem = "Only explicit CVSS 4.0 base metrics are supported."
        elif missing:
            problem = "Incomplete base metrics; unknown impact is not zero impact."
        elif any(
            ref not in trusted_refs
            for fact in assessment.metrics.values()
            for ref in fact.evidence_refs
        ):
            problem = "Metric evidence references have not been independently resolved."
        if problem is None:
            vector = "CVSS:4.0/" + "/".join(
                f"{key}:{assessment.metrics[key].value}" for key in _BASE_METRICS
            )
            try:
                calculated = CVSS4(vector)
            except (CVSS4MalformedError, CVSS4MandatoryError):
                problem = "Invalid CVSS 4.0 metric value; no numeric score assigned."
            else:
                return CVSSResult(
                    vector=calculated.clean_vector(),
                    score=calculated.scores()[0],
                    severity=calculated.severities()[0].upper(),
                    assessment_status="assessed",
                    metric_facts=assessment.metrics,
                    reasoning="CVSS 4.0 base score calculated by cvss==3.6 from reviewed facts. "
                    "Metric justification is retained; this is not a vulnerability verdict.",
                )
        return CVSSResult(
            vector="UNASSESSED",
            severity="UNASSESSED",
            reasoning=problem,
            missing_metrics=missing,
        )

    def score_context_priority(
        self,
        context: ArchitectureContext,
    ) -> ContextPriority:
        """Рассчитать Context Priority v0.1 по явным фактам архитектуры."""
        # Приоритет архитектуры не смешивается с технической тяжестью CVSS
        score = 0.0
        reasons: list[str] = []

        exposure_points = 2.0 if context.public_exposure else 0.0
        score += exposure_points
        reasons.append(
            f"public_exposure:{'internet' if context.public_exposure else 'not_public'}:"
            f"+{_format_points(exposure_points)}"
        )

        criticality = context.criticality.strip().lower() or "unknown"
        criticality_points = _CRITICALITY_POINTS.get(criticality, 0.0)
        score += criticality_points
        reasons.append(f"asset_criticality:{criticality}:+{_format_points(criticality_points)}")

        database_points = 2.0 if context.databases else 0.0
        score += database_points
        reasons.append(
            f"database_access:{'direct' if context.databases else 'none'}:"
            f"+{_format_points(database_points)}"
        )

        critical_path_points = 1.0 if context.critical_paths else 0.0
        score += critical_path_points
        reasons.append(
            f"critical_path:{'direct' if context.critical_paths else 'none'}:"
            f"+{_format_points(critical_path_points)}"
        )

        authentication = context.authentication.strip().lower() or "unknown"
        authentication_points = _AUTHENTICATION_POINTS.get(authentication, 0.0)
        score += authentication_points
        reasons.append(f"authentication:{authentication}:+{_format_points(authentication_points)}")

        blast_radius = context.blast_radius.strip().lower() or "unknown"
        blast_radius_points = _BLAST_RADIUS_POINTS.get(blast_radius, 0.0)
        score += blast_radius_points
        reasons.append(f"blast_radius:{blast_radius}:+{_format_points(blast_radius_points)}")

        return ContextPriority(
            level=_priority_level(score),
            score=score,
            reasons=reasons,
            unknown_inputs=(unknown := _unknown_context_inputs(context)),
            assessment_status="partial" if unknown else "assessed",
        )


def _unknown_context_inputs(context: ArchitectureContext) -> list[str]:
    """Defaults are not evidence of absence; preserve legacy numeric contributions."""
    unknown = list(context.unknown_inputs or [])
    categorical = {
        "criticality": _CRITICALITY_POINTS,
        "authentication": _AUTHENTICATION_POINTS,
        "blast_radius": _BLAST_RADIUS_POINTS,
    }
    for name in (
        "public_exposure",
        "criticality",
        "databases",
        "critical_paths",
        "authentication",
        "blast_radius",
    ):
        value = getattr(context, name)
        if name in (context.unknown_inputs or []) or (
            name in categorical
            and (
                value.strip().lower() in {"", "unknown"}
                or value.strip().lower() not in categorical[name]
            )
        ):
            unknown.append(name)
    return list(dict.fromkeys(unknown))


def _priority_level(score: float) -> str:
    if score <= 3.0:
        return "LOW"
    if score <= 6.0:
        return "MEDIUM"
    return "HIGH"


def _format_points(value: float) -> str:
    return str(int(value)) if value.is_integer() else str(value)
