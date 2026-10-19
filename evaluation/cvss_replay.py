"""Read-only CVSS 3.1 verification. Never used to produce new scores.

Reading CVSSResult preserves historical data; only this explicit check establishes
agreement with reviewed source facts and the declared version's calculator.
"""
from math import isfinite

from cvss import CVSS3
from cvss.exceptions import CVSS3Error

from schemas.scoring import CVSSAssessmentInput, CVSSResult

_BASE_METRICS = ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')


def verify_cvss_result(result: CVSSResult, assessment: CVSSAssessmentInput,
                       *, trusted_evidence_refs: frozenset[str]) -> None:
    """Reject mixed versions, incomplete/unbound metrics and forged numeric results."""
    if result.scheme != 'CVSS:3.1/B':
        raise ValueError('Unsupported CVSS replay scheme')
    keys = _BASE_METRICS
    prefix = result.scheme.removesuffix('/B') + '/'
    if not result.vector.startswith(prefix):
        raise ValueError('CVSS scheme/vector version mismatch')
    if (result.assessment_status != 'assessed' or result.missing_metrics
            or set(assessment.metrics) != set(keys) or result.metric_facts != assessment.metrics):
        raise ValueError('CVSS replay requires complete matching reviewed base metrics')
    if any(ref not in trusted_evidence_refs for fact in assessment.metrics.values() for ref in fact.evidence_refs):
        raise ValueError('CVSS replay metric evidence is not trusted')
    vector = prefix + '/'.join(f'{key}:{assessment.metrics[key].value}' for key in keys)
    try:
        expected = CVSS3(vector)
    except CVSS3Error as error:
        raise ValueError('Invalid CVSS replay metrics') from error
    if result.vector != expected.clean_vector():
        raise ValueError('CVSS vector does not match reviewed base metrics')
    if (result.score is None or not isfinite(result.score) or result.score != expected.scores()[0]
            or result.severity != expected.severities()[0].upper()):
        raise ValueError('CVSS score/severity does not match the declared calculator')
