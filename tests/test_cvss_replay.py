"""CVSS 3.1 replay: reading data is distinct from verifying a score."""
import hashlib
import json
import subprocess
import zipfile

import pytest

from app.b08_acceptance import package, replay, run
from evaluation.cvss_replay import verify_cvss_result
from schemas.scoring import CVSSResult, ScoringReview
from scoring.service import ScoringService


@pytest.fixture
def acceptance(tmp_path):
    root = tmp_path / 'acceptance'
    run(root)
    return root


def reseal(root):
    files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in root.rglob('*') if p.is_file() and p != root / 'seal.json'}
    (root / 'seal.json').write_text(json.dumps(files), encoding='utf-8')


def test_score_replays_without_execution(acceptance, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Scoring replay must not execute anything')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    checked = replay(acceptance)
    assert checked['status'] == 'passed'
    assert checked['cvss_reference_score'] == 9.8
    assert checked == replay(acceptance)


def test_current_acceptance_run_package_and_extracted_replay(tmp_path):
    source = tmp_path / 'new'
    checked = run(source)
    assert checked['cvss_reference_score'] == 9.8
    saved = json.loads((source / 'report.json').read_bytes())['cvss']
    assert saved['scheme'] == 'CVSS:3.1/B'
    assert saved['vector'].startswith('CVSS:3.1/')
    archive = tmp_path / 'new.zip'
    assert package(source, archive)['cvss_reference_score'] == 9.8
    extracted = tmp_path / 'extracted'
    with zipfile.ZipFile(archive) as zipped:
        zipped.extractall(extracted)
    assert replay(extracted) == checked


@pytest.mark.parametrize('mutation', ['number', 'category', 'scheme', 'unknown', 'vector', 'missing', 'extra', 'facts'])
def test_resealed_mixed_or_forged_scores_are_rejected(acceptance, mutation):
    path = acceptance / 'report.json'
    data = json.loads(path.read_bytes())
    cvss = data['cvss']
    if mutation == 'number':
        cvss['score'] = 9.9
    elif mutation == 'category':
        cvss['severity'] = 'LOW'
    elif mutation == 'scheme':
        cvss['scheme'] = 'CVSS:3.0/B'
    elif mutation == 'unknown':
        cvss['scheme'] = 'CVSS:9.9/B'
    elif mutation == 'vector':
        cvss['vector'] = cvss['vector'].replace('CVSS:3.1/', 'CVSS:3.0/')
    elif mutation == 'missing':
        del cvss['metric_facts']['A']
    elif mutation == 'extra':
        cvss['vector'] += '/E:A'
    else:
        cvss['metric_facts']['PR']['value'] = 'L'
    path.write_text(json.dumps(data), encoding='utf-8')
    reseal(acceptance)
    with pytest.raises(ValueError, match='CVSS'):
        replay(acceptance)


def test_seal_checked_before_scoring(acceptance):
    path = acceptance / 'report.json'
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='seal'):
        replay(acceptance)


def test_nonbase_metrics_do_not_produce_a_score(acceptance):
    from schemas.finding import Finding
    finding = Finding.model_validate_json((acceptance / 'finding.json').read_bytes())
    review = ScoringReview.model_validate_json((acceptance / 'review.json').read_bytes())
    review.cvss.metrics['E'] = review.cvss.metrics['AV']
    result = ScoringService().score_cvss(finding, review.cvss,
                                       trusted_evidence_refs=frozenset({'fixture-source'}))
    assert result.score is None and result.scheme == 'CVSS:3.1/B'


def test_correct_readable_unknown_report_is_not_a_verified_score(acceptance):
    data = json.loads((acceptance / 'report.json').read_bytes())['cvss']
    data['scheme'] = 'CVSS:9.9/B'
    report = CVSSResult.model_validate(data)
    review = ScoringReview.model_validate_json((acceptance / 'review.json').read_bytes())
    with pytest.raises(ValueError, match='Unsupported'):
        verify_cvss_result(report, review.cvss, trusted_evidence_refs=frozenset({'fixture-source'}))
