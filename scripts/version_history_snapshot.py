#!/usr/bin/env python3
"""Publish complete history snapshots and import only successful workflow artifacts."""
import argparse
import hashlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import zipfile
import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = 'versions-history-snapshot'
WORKFLOW = 'versions-history.yml'


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def validate(histories):
    if not isinstance(histories, dict) or not histories:
        raise ValueError('Empty or invalid history snapshot')
    for name, entry in histories.items():
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', name):
            raise ValueError('Invalid extension name')
        datetime.fromisoformat(entry['fetchedAt'])
        if not isinstance(entry['builds'], list):
            raise ValueError('Invalid build list')
        for build in entry['builds']:
            if not isinstance(build['version'], str) or not build['version']:
                raise ValueError('Missing image version')
            if not re.fullmatch(r'ghcr\.io/[a-z0-9._/:-]+@sha256:[0-9a-f]{64}', build['reference']):
                raise ValueError('Invalid image reference')
            if not isinstance(build['annotations'], dict) or not isinstance(build['platforms'], list):
                raise ValueError('Invalid image metadata')
            if not re.fullmatch(r'https://github\.com/orgs/[\w.-]+/packages/container/[^?]+/[0-9]+\?tag=[^\s]+', build['imageURL']):
                raise ValueError('Missing verified exact-image link')


def prepare(catalog_dir, destination):
    entries = {}
    for path in sorted(catalog_dir.glob('catalog-*.yaml')):
        catalog = yaml.safe_load(path.read_text())
        for image in catalog['spec']['images']:
            for extension in image.get('extensions', []):
                entry = entries.setdefault(extension['name'], {'name': extension['name'], 'variants': []})
                entry['variants'].append({'reference': extension['image']['reference']})
    if not entries:
        raise ValueError('No catalog extensions found')
    atomic_json(destination, {'extensions': list(entries.values())})


def mark_complete(candidate, catalog):
    receipt = {'historySHA256': hashlib.sha256(candidate.read_bytes()).hexdigest(),
               'catalogSHA256': hashlib.sha256(catalog.read_bytes()).hexdigest()}
    atomic_json(candidate.with_suffix('.complete.json'), receipt)


def publish(candidate, catalog, destination):
    histories = json.loads(candidate.read_text())
    names = {e['name'] for e in json.loads(catalog.read_text())['extensions']}
    # Omit removed catalog entries; fail if any current entry is missing.
    complete = {name: histories[name] for name in names}
    validate(complete)
    receipt = json.loads(candidate.with_suffix('.complete.json').read_text())
    if (receipt['historySHA256'] != hashlib.sha256(candidate.read_bytes()).hexdigest() or
            receipt['catalogSHA256'] != hashlib.sha256(catalog.read_bytes()).hexdigest()):
        raise ValueError('History does not match a completed full refresh')
    snapshot = {'schemaVersion': 1, 'publishedAt': datetime.now(timezone.utc).isoformat(), 'extensions': complete}
    atomic_json(destination, snapshot)
    print(f'Published complete snapshot for {len(complete)} extensions')


def import_archive(data, destination):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.namelist() != ['version-history.json']:
            raise ValueError('Unexpected snapshot artifact contents')
        snapshot = json.loads(archive.read('version-history.json'))
    install_snapshot(snapshot, destination)


def install_snapshot(snapshot, destination):
    if snapshot.get('schemaVersion') != 1:
        raise ValueError('Unsupported history snapshot schema')
    datetime.fromisoformat(snapshot['publishedAt'])
    validate(snapshot['extensions'])
    atomic_json(destination, snapshot['extensions'])


def fetch_latest(repository, token, destination):
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
    base = f'https://api.github.com/repos/{repository}'
    # Only completed successful main-branch collector runs are eligible, never
    # partially uploaded artifacts from failed/cancelled/in-progress runs.
    url = base + f'/actions/workflows/{WORKFLOW}/runs?branch=main&status=success&per_page=100'
    while url:
        response = session.get(url, timeout=60)
        if response.status_code == 404:
            print('No published history workflow yet; using current catalog only.')
            return False
        response.raise_for_status()
        for run in response.json()['workflow_runs']:
            if run['status'] != 'completed' or run['conclusion'] != 'success' or run['head_branch'] != 'main':
                continue
            artifacts = session.get(base + f"/actions/runs/{run['id']}/artifacts?per_page=100", timeout=60)
            artifacts.raise_for_status()
            artifact = next((a for a in artifacts.json()['artifacts'] if a['name'] == ARTIFACT and not a['expired']), None)
            if not artifact:
                continue
            download = session.get(base + f"/actions/artifacts/{artifact['id']}/zip", timeout=180)
            download.raise_for_status()
            import_archive(download.content, destination)
            print(f"Imported complete history snapshot from {run['html_url']}")
            return True
        url = response.links.get('next', {}).get('url')
    print('No retained successful history snapshot; using current catalog only.')
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('catalog_dir', type=Path)
    p.add_argument('destination', type=Path)
    p = sub.add_parser('publish')
    p.add_argument('candidate', type=Path)
    p.add_argument('catalog', type=Path)
    p.add_argument('destination', type=Path)
    p = sub.add_parser('install')
    p.add_argument('snapshot', type=Path)
    sub.add_parser('import')
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.catalog_dir, args.destination)
    elif args.command == 'publish':
        publish(args.candidate, args.catalog, args.destination)
    elif args.command == 'install':
        install_snapshot(json.loads(args.snapshot.read_text()), ROOT / 'data/version_history.json')
    else:
        fetch_latest(os.environ['GITHUB_REPOSITORY'], os.environ['GH_TOKEN'], ROOT / 'data/version_history.json')


if __name__ == '__main__':
    main()
