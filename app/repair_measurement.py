"""C05 fixed six-slot series, offline rescore and complete local delivery."""
import argparse
import json
import zipfile
from pathlib import Path

from fix_verification.measurement import execute, finalize, freeze, protocol, replay_series


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--replay', action='store_true')
    parser.add_argument('--bundle', type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    if args.bundle and (args.bundle.exists() or args.bundle.resolve().is_relative_to(root)
                        or (args.target and args.bundle.resolve().is_relative_to(args.target.resolve()))):
        parser.error('Bundle must be new and outside series and original target')
    if args.replay:
        report = replay_series(root)
    else:
        if args.target is None:
            parser.error('--target is required for a new series')
        freeze(args.target, root)
        try:
            execute(args.target, root)
        finally:
            finalize(root)
        report = replay_series(root)
    if args.bundle:
        if args.bundle.resolve().is_relative_to(Path(protocol(root)['original_path']).resolve()):
            parser.error('Bundle must be outside original target')
        with zipfile.ZipFile(args.bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(root.rglob('*')):
                if file.is_file():
                    archive.write(file, file.relative_to(root).as_posix())
    print(json.dumps({'complete': report['complete'], 'statuses': report['statuses'],
                      'verified_eligible': report['verified_eligible']}))
    return 0 if report['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
