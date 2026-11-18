#!/usr/bin/env python3
"""Fetch timestamp-tagged GHCR history for the local-only Versions preview."""
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
from version_history_snapshot import mark_complete
from generate import ROOT, Registry, check_digest, image_package_url

BUILD_TAG = re.compile(r'^.+-\d{12}-\d+-(?:bookworm|trixie)$')


def build_tags(registry):
    url = registry.base + 'tags/list?n=1000'
    tags = set()
    visited = set()
    while url:
        if url in visited or urlsplit(url).netloc != 'ghcr.io' or not urlsplit(url).path.startswith(urlsplit(registry.base).path):
            raise ValueError('Unexpected registry pagination URL')
        visited.add(url)
        response = registry.session.get(url, timeout=60)
        response.raise_for_status()
        tags.update(tag for tag in response.json().get('tags', []) if BUILD_TAG.fullmatch(tag))
        next_url = response.links.get('next', {}).get('url')
        url = urljoin(url, next_url) if next_url else None
    return sorted(tags)


def read_build(registry, tag):
    response = registry.session.get(registry.base + 'manifests/' + tag, timeout=60)
    response.raise_for_status()
    digest = response.headers.get('Docker-Content-Digest') or 'sha256:' + hashlib.sha256(response.content).hexdigest()
    check_digest(response.content, digest)
    index = response.json()
    annotations = index.get('annotations', {})
    # Version and dates come from published metadata, never inferred from tag names.
    version = annotations.get('org.opencontainers.image.version')
    if not version:
        raise ValueError(f'{tag}: missing published version metadata')
    reference = f'ghcr.io/{registry.repo}:{tag}@{digest}'
    return {'version': version, 'tag': tag, 'reference': reference,
            'annotations': annotations, 'packageURL': image_package_url(reference),
            'distro': annotations.get('io.cloudnativepg.image.base.os', 'Unknown'),
            'pg': annotations.get('io.cloudnativepg.image.base.pgmajor', 'Unknown'),
            'platforms': [m['platform'] for m in index.get('manifests', [])
                          if m.get('platform', {}).get('os') == 'linux']}


def add_image_links(builds):
    remaining = {b['tag']: b for b in builds}
    packages = {b['packageURL'] for b in builds}
    for package in packages:
        url = package.replace('/package/', '/') + '/versions?filters%5Bversion_type%5D=tagged'
        visited = set()
        while url and url not in visited:
            if urlsplit(url).netloc != 'github.com':
                raise ValueError('Unexpected package pagination host')
            visited.add(url)
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for anchor in soup.select('a[href]'):
                tag = anchor.get_text(strip=True)
                build = remaining.get(tag)
                if not build or build['packageURL'] != package:
                    continue
                href = anchor['href']
                if not re.search(r'/[0-9]+\?tag=', href):
                    continue
                digest = build['reference'].split('@')[1]
                row = anchor.find_parent('div', class_='flex-column')
                if row and row.find('clipboard-copy', attrs={'value': digest}):
                    build['imageURL'] = urljoin('https://github.com', href)
                    del remaining[tag]
            if not any(b['packageURL'] == package for b in remaining.values()):
                break
            next_link = soup.select_one('a.next_page')
            url = urljoin(url, next_link['href']) if next_link else None
    if remaining:
        raise ValueError(f'Could not verify exact GitHub image links for {len(remaining)} builds')


def refresh_repository(registry, previous, current_digests=None, full_refresh=False):
    current_digests = current_digests or {}
    cached = {b['tag']: b for b in previous
              if b['reference'].split('@')[0].rsplit(':', 1)[0] == 'ghcr.io/' + registry.repo}
    tags = build_tags(registry)
    reused = []
    missing = []
    for tag in tags:
        build = cached.get(tag)
        expected = current_digests.get(tag)
        if (not full_refresh and build and
                (not expected or build['reference'].split('@')[1] == expected)):
            reused.append(dict(build))
        else:
            missing.append(tag)
    with ThreadPoolExecutor(max_workers=4) as pool:
        fetched = list(pool.map(lambda tag: read_build(registry, tag), missing))
    builds = reused + fetched
    # Only unresolved/new images require GitHub HTML pagination.
    unresolved = [b for b in builds if not b.get('imageURL')]
    if unresolved:
        add_image_links(unresolved)
    print(f'{registry.repo}: reused {len(reused)}, fetched {len(fetched)}, resolved {len(unresolved)} links')
    return builds


def refresh_entry(entry, full_refresh=False, history_path=None):
    repositories = {v['reference'].split('@')[0].split(':')[0] for v in entry['variants']}
    path = Path(history_path) if history_path else ROOT / '.cache/version-history/history.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    history = json.loads(path.read_text()) if path.exists() else {}
    previous = history.get(entry['name'], {}).get('builds', [])
    builds = []
    for repository in sorted(repositories):
        registry = Registry(repository + '@sha256:unused')
        current = {v['reference'].split('@')[0].rsplit(':', 1)[1]: v['reference'].split('@')[1]
                   for v in entry['variants'] if v['reference'].startswith(repository + ':')}
        builds.extend(refresh_repository(registry, previous, current, full_refresh))
    # Mutable aliases and attestation tags are excluded; deduplicate image digests.
    builds = list({b['reference'].split('@')[1]: b for b in builds}.values())
    builds.sort(key=lambda b: b['annotations'].get('org.opencontainers.image.created', ''), reverse=True)
    history[entry['name']] = {'fetchedAt': datetime.now(timezone.utc).isoformat(), 'builds': builds}
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(history))
    temporary.replace(path)
    print(f"{entry['name']}: {len(builds)} images", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('extension', nargs='?')
    parser.add_argument('--all', action='store_true', help='Refresh every catalog extension sequentially')
    parser.add_argument('--full-refresh', action='store_true', help='Refetch all historical manifests and exact image links')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'data/generated.json')
    parser.add_argument('--history-file', type=Path, help='Private incremental cache destination')
    args = parser.parse_args()
    if bool(args.extension) == args.all:
        parser.error('Specify an extension or --all')
    data = json.loads(args.catalog.read_text())
    entries = data['extensions'] if args.all else [e for e in data['extensions'] if e['name'] == args.extension]
    if not entries:
        parser.error('Extension not found in catalog')
    for entry in entries:
        if args.history_file:
            refresh_entry(entry, args.full_refresh, args.history_file)
        else:
            refresh_entry(entry, args.full_refresh)

    if args.all:
        mark_complete(args.history_file or ROOT / '.cache/version-history/history.json', args.catalog)


if __name__ == '__main__':
    main()
