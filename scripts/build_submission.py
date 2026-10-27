"""Build an allowlisted local submission ZIP; exclude databases, environments and secrets."""
import argparse
from datetime import datetime
import hashlib
import gzip
import json
from pathlib import Path
import zipfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
ROOT_FILES = ('README.md', 'pyproject.toml', 'requirements.txt',
              'start-cti.sh',
              'Dockerfile', 'docker-compose.yml', '.env.example', '.gitignore', '.dockerignore',
              'RELEASE_CHECKS.json')
DIRECTORIES = ('app', 'config', 'scripts', 'tests', 'examples', 'evaluation', 'docs')
DATA_FILES = ('data/review_snapshot.json.gz', 'data/submission_manifest.json',
              'data/attack/LICENSE-MITRE.txt', 'data/attack/import_manifest.json',
              'data/attack/status.json', 'data/attack/reviewed_mappings.json')


def selected_files():
    paths = [ROOT / name for name in (*ROOT_FILES, *DATA_FILES)]
    for name in DIRECTORIES:
        paths.extend(p for p in (ROOT / name).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.sqlite3', '.pdf')
                     and not (p.suffix == '.png' and p.is_relative_to(ROOT / 'docs'))
                     and not p.is_relative_to(ROOT / 'docs/submission'))
    return sorted(set(paths))


def secret_values():
    # Read solely to prevent accidental inclusion; never put these values in output.
    source = ROOT / '.env'
    values = []
    if source.exists():
        for line in source.read_text().splitlines():
            key, _, value = line.partition('=')
            if any(marker in key.upper() for marker in ('TOKEN', 'PASSWORD', 'SECRET', 'API_KEY')) and len(value.strip()) >= 8:
                values.append(value.strip().strip('\"\'').encode())
    return values


def main():
    p = argparse.ArgumentParser(description='Собрать комплект сдачи без локальных секретов')
    p.add_argument('--output', type=Path, default=ROOT.parent / f'cti-platform-submission-{VERSION}.zip')
    args = p.parse_args()
    files = selected_files()
    payload = {}
    forbidden = secret_values()
    for path in files:
        if not path.is_file():
            raise ValueError('Не найден обязательный файл: ' + str(path.relative_to(ROOT)))
        if path.is_symlink():
            raise ValueError('Символьная ссылка не включается: ' + str(path.relative_to(ROOT)))
        data = path.read_bytes()
        if any(value in (gzip.decompress(data) if path.suffix == ".gz" else data) for value in forbidden):
            raise ValueError('Обнаружен локальный секрет в файле: ' + str(path.relative_to(ROOT)))
        payload[path.relative_to(ROOT).as_posix()] = data
    metadata = json.loads(payload['data/submission_manifest.json'])
    manifest = {'project_version': VERSION, 'frozen_at': metadata['frozen_at'],
                'snapshot_content_sha256': metadata['content_sha256'],
                'exclusions': ['.env', '.venv', 'working databases', 'backups', 'credentials'],
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                          for name, data in sorted(payload.items())}}
    payload['PACKAGE_MANIFEST.json'] = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
    stamp = datetime.fromisoformat(metadata['frozen_at']).timetuple()[:6]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo('cti-platform/' + name, stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if name == 'start-cti.sh' else 0o100644) << 16
            archive.writestr(info, data)
    checksum = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + '.sha256').write_text(checksum + '  ' + args.output.name + '\n')
    print(json.dumps({'archive': str(args.output.resolve()), 'files': len(payload),
                      'bytes': args.output.stat().st_size, 'sha256': checksum}, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
