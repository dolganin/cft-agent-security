"""C03 operator CLI: verify a reviewed proposal or qualify a reference patch.

References are engineering inputs, never described as model-generated patches.
"""
import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.stage1_e2e import pinned_image
from executor.c03_runtime import WORKER_IMAGE
from fix_verification.independent import (
    ROOT,
    IndependentPatchVerificationService,
    archived_reports,
    registered_profile,
)
from fix_verification.scope import validate_candidate
from fix_verification.workspace import digest, safe_file
from schemas.fix import PatchReviewArtifact, ProposedPatch
from schemas.independent_fix import C03Artifact
from schemas.report import FinalReport


def write_json(path, data):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def seal(directory):
    members = {p.relative_to(directory).as_posix(): digest(p.read_bytes())
               for p in sorted(directory.rglob('*')) if p.is_file() and p.name != 'seal.json'}
    write_json(directory / 'seal.json', {'schema_version': 'cft.c03.seal.v1', 'files': members})
    return digest((directory / 'seal.json').read_bytes())


def run(*, family, target, output, fix_image, report=None, review=None, deadline_monotonic=None):
    source = target.resolve(strict=True)
    destination = output.resolve()
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError('Artifact directory must be outside the target')
    destination.mkdir(parents=True, exist_ok=False)
    image = pinned_image(fix_image)
    os.environ['CFT_SANDBOX_IMAGE'] = WORKER_IMAGE
    profile = registered_profile(family, source, image)
    if report is None:
        candidates = archived_reports(family)
        expected_file = 'routes/search.ts' if family == 'sql-search' else 'lib/insecurity.ts'
        report = next(r for r in candidates if r.finding.file == expected_file)
    if review is None:
        file = 'routes/search.ts' if family == 'sql-search' else 'lib/insecurity.ts'
        raw = safe_file(source, file).read_bytes()
        proposal = ProposedPatch(finding_id=report.finding_id,
            rationale='C01 operator reference patch; engineering qualification, not LLM generation',
            unified_diff=(ROOT / f'contracts/c01/reference/{family}.patch').read_text(encoding='utf-8'))
        canonical = validate_candidate(family_id=family, proposal=proposal, source_root=source, source_sha256=digest(raw))
        proposal = proposal.model_copy(update={'unified_diff': canonical})
        review = PatchReviewArtifact(id='c03-reference-' + uuid4().hex, run_id=destination.name,
            finding_id=report.finding_id, file=file, status='ready_for_review', source_sha256=digest(raw),
            proposal_sha256=digest(proposal.model_dump_json().encode()), generated_at=datetime.now(UTC),
            proposal=proposal, validation_detail='C01 scope and source digest checked',
            editable_start=1, editable_end=len(raw.decode().splitlines()))
    service = IndependentPatchVerificationService(family)
    verification_options = {'deadline_monotonic': deadline_monotonic} if deadline_monotonic is not None else {}
    try:
        result = service.verify(report=report, review=review, profile=profile,
            artifact_directory=destination, **verification_options)
    except KeyboardInterrupt:
        partial = getattr(service, 'partial_result', None)
        if partial is not None:
            # A completed base phase can still be interrupted during independent
            # replay. Preserve its observations without claiming verification.
            partial = partial.model_copy(update={'status': 'INCONCLUSIVE', 'security_verified': False,
                'verdict': 'inconclusive', 'explanation': 'Fix verification interrupted by operator'})
            package = C03Artifact(family=family, inputs=service.inputs, result=partial,
                receipts=service.receipts, lifecycle=service.lifecycle,
                reason_codes=['operator_interrupted'])
            write_json(destination / 'manifest.json', package.model_dump(mode='json'))
        write_json(destination / 'interruption.json', {'reason': 'operator_interrupted',
            'partial_manifest': partial is not None})
        seal(destination)
        raise
    package = C03Artifact(family=family, inputs=service.inputs, result=result,
        receipts=service.receipts, lifecycle=service.lifecycle,
        reason_codes=service.reason_codes or ['preflight_failed'])
    write_json(destination / 'manifest.json', package.model_dump(mode='json'))
    seal_sha256 = seal(destination)
    print(json.dumps({'status': result.status, 'explanation': result.explanation,
                      'artifact': str(destination), 'seal_sha256': seal_sha256}))
    return package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', type=Path, help='Offline verification; no Docker or patch execution')
    parser.add_argument('--family', choices=['sql-search', 'redirect-allowlist'])
    parser.add_argument('--target', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fix-image', default='cft-fix-juice:stage1', help='Already provisioned operator image; never pulled')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--review', type=Path)
    args = parser.parse_args()
    if args.replay:
        from fix_verification.independent_replay import replay
        print(json.dumps(replay(args.replay)))
        return 0
    if not (args.family and args.target and args.output):
        parser.error('--family, --target and --output are required for a run')
    if bool(args.report) != bool(args.review):
        parser.error('--report and --review must be supplied together')
    package = run(family=args.family, target=args.target, output=args.output, fix_image=args.fix_image,
        report=FinalReport.model_validate_json(args.report.read_text(encoding='utf-8')) if args.report else None,
        review=PatchReviewArtifact.model_validate_json(args.review.read_text(encoding='utf-8')) if args.review else None)
    return 0 if package.result.status == 'FIXED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
