"""Validate independently scanned catalog evidence before assembling the site."""

import json
from pathlib import Path


def shard_path(cache, index):
    return cache / f'inspected-shard-{index}.json'


def image_identity(image):
    return tuple(image[field] for field in ('name', 'pg', 'distro', 'reference', 'catalog'))


def database_identity(database, osv_database):
    # Grype's source URL records the archive checksum. Local paths and fetch
    # times vary across runners even when the downloaded databases are identical.
    grype = tuple(database.get(field) for field in ('schemaVersion', 'from', 'built'))
    if database.get('error') or database.get('valid') is not True or not all(grype):
        raise RuntimeError('Evidence requires a verified Grype database identity')
    osv = tuple(osv_database.get('databases', {}).get(ecosystem, {}).get('sha256')
                for ecosystem in ('crates.io', 'Debian'))
    if osv_database.get('error') or not all(osv):
        raise RuntimeError('Evidence requires verified OSV database identities')
    return grype, osv


def check_reports(images, static):
    for image in images:
        for platform in image['platforms']:
            if platform['status'] != 'available':
                continue
            arch = platform['architecture']
            sbom = Path('reports') / image['name'] / f"{image['distro']}-pg{image['pg']}-{arch}.spdx.json"
            reports = [(platform['sbom'], sbom)]
            for field, suffix in (('scan', '.grype.json'), ('osvScan', '.osv.json')):
                scan = platform[field]
                if scan['status'] == 'scanned':
                    reports.append((scan['report'], sbom.with_suffix(suffix)))
                elif scan['status'] != 'unavailable':
                    raise RuntimeError(f'Evidence lacks a fresh {field} result for {sbom}')
            for recorded, expected in reports:
                if recorded != expected.as_posix() or not (static / expected).is_file():
                    raise RuntimeError(f'Evidence report is missing or mismatched: {expected}')


def merge_shards(cache, jobs, commits, static):
    paths = sorted(cache.glob('inspected-shard-*.json'))
    if not paths:
        raise RuntimeError('No evidence shards found')

    indexed = {}
    count = len(paths)
    expected = [image_identity(job) for job in jobs]
    if len(set(expected)) != len(expected):
        raise RuntimeError('Current catalogs contain duplicate evidence image identities')
    for path in paths:
        shard = json.loads(path.read_text())
        index = shard['shardIndex']
        if shard['shardCount'] != count:
            raise RuntimeError(f'Evidence shard set is incomplete or inconsistent: {path.name}')
        if type(index) is not int or index in indexed or index not in range(count) or path != shard_path(cache, index):
            raise RuntimeError(f'Evidence shard index is duplicate or invalid: {path.name}')
        if shard['commits'] != commits:
            raise RuntimeError(f'Evidence source commits differ from current sources: {path.name}')
        indexed[index] = shard

    first = indexed[0]
    identity = database_identity(first['database'], first['osvDatabase'])
    images = {}
    for index, shard in indexed.items():
        if database_identity(shard['database'], shard['osvDatabase']) != identity:
            raise RuntimeError(f'Evidence advisory databases differ across shards: shard {index}')
        part = {image_identity(image): image for image in shard['images']}
        if len(part) != len(shard['images']) or part.keys() != set(expected[index::count]):
            raise RuntimeError(f'Evidence images do not match the catalog partition: shard {index}')
        check_reports(part.values(), static)
        images.update(part)
    return [images[key] for key in expected], first['database']
