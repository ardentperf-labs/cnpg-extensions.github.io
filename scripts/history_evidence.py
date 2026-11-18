#!/usr/bin/env python3
"""Retrieve version history independently and verify it during site assembly."""

import argparse
import json

import yaml

from generate import REPOS, ROOT, checkout
from version_history import EXTENSION_NAME, atomic_json, generate_history, validate


def catalog_entries(catalogs):
    entries = {}
    for path in sorted(catalogs.glob('catalog-*.yaml')):
        catalog = yaml.safe_load(path.read_text())
        for image in catalog['spec']['images']:
            for extension in image.get('extensions', []):
                name = extension['name']
                if not EXTENSION_NAME.fullmatch(name):
                    raise ValueError('Unsafe extension name')
                entry = entries.setdefault(name, {'name': name, 'variants': []})
                entry['variants'].append({'reference': extension['image']['reference']})
    if not entries:
        raise RuntimeError('Catalog contains no extensions')
    return [entries[name] for name in sorted(entries)]


def capture(root, refresh_extension=None):
    cache = root / '.cache'
    marker = cache / 'history-commits.json'
    cache.mkdir(exist_ok=True)
    marker.unlink(missing_ok=True)
    commits = {name: checkout(name, refresh=True) for name in REPOS}
    entries = catalog_entries(cache / 'artifacts/image-catalogs-extensions')
    if refresh_extension is not None and refresh_extension not in {entry['name'] for entry in entries}:
        raise ValueError(f'Unknown catalog extension: {refresh_extension}')
    generate_history(entries, refresh_extension=refresh_extension)
    atomic_json(marker, commits)


def verify(root, entries, commits):
    marker = root / '.cache/history-commits.json'
    if json.loads(marker.read_text()) != commits:
        raise RuntimeError('Version history source commits differ from current sources')
    history = json.loads((root / 'data/version_history.json').read_text())
    validate(history)
    if history.keys() != {entry['name'] for entry in entries}:
        raise RuntimeError('Version history extension names do not match the current catalogs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-extension', help='Refetch every published build of one extension')
    args = parser.parse_args()
    capture(ROOT, refresh_extension=args.refresh_extension)
