"""Run the documented OSV supplement against an unchanged SPDX document."""
import json
import os
import re
import hashlib
import zipfile
from pathlib import Path
import requests
import subprocess
from datetime import datetime, timezone


def refresh_database(root):
    """Refresh each supported ecosystem once; never scan stale data after failure."""
    cache = Path(root) / '.cache/osv-local-db'
    metadata = {'path': str(cache), 'databases': {}}
    try:
        for ecosystem in ('crates.io', 'Debian'):
            url = f'https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip'
            response = requests.get(url, timeout=180)
            response.raise_for_status()
            destination = cache / 'osv-scalibr' / ecosystem / 'all.zip'
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix('.tmp')
            try:
                temporary.write_bytes(response.content)
                with zipfile.ZipFile(temporary) as archive:
                    if archive.testzip() is not None:
                        raise ValueError('Corrupt OSV database archive')
                temporary.replace(destination)
            finally:
                temporary.unlink(missing_ok=True)
            metadata['databases'][ecosystem] = {'sha256': hashlib.sha256(response.content).hexdigest(), 'lastModified': response.headers.get('Last-Modified')}
        metadata['refreshedAt'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    except Exception as error:
        metadata['error'] = 'OSV database refresh failed: ' + str(error)
    return metadata


def findings(raw):
    found = {}
    for result in raw.get('results', []):
        for entry in result.get('packages', []):
            package = entry['package']
            for advisory in entry.get('vulnerabilities', []):
                key = (advisory['id'], package['name'], package['version'])
                found[key] = dict(id=key[0], package=key[1], version=key[2])
    return list(found.values())


def scan_osv_batch(sboms, root, executable, database=None):
    """Scan unchanged SPDX files and write a separate report for each source."""
    sboms = list(dict.fromkeys(sboms))
    if not executable:
        return {sbom: {'status': 'not-run', 'reason': 'OSV scanning was not requested.'} for sbom in sboms}
    if database and database.get('error'):
        return {sbom: {'status': 'unavailable', 'reason': database['error']} for sbom in sboms}
    results = {}
    candidates = []
    for sbom in sboms:
        if sbom.is_file():
            candidates.append(sbom)
        else:
            results[sbom] = {'status': 'unavailable', 'reason': 'SPDX file is unavailable'}
    # Bound command size and memory use while loading the databases once per batch.
    batch_size = 512
    for offset in range(0, len(candidates), batch_size):
        results.update(scan_batch(candidates[offset:offset + batch_size], root, executable, database))
    return results


def scan_batch(sboms, root, executable, database):
    sources = {str(sbom.absolute()): sbom for sbom in sboms}
    command = [executable, 'scan', 'source', '--offline', '--all-packages',
               '--verbosity', 'error', '--format', 'json']
    for source in sources:
        command.extend(('-L', source))
    env = {**os.environ, 'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': str(Path(root) / '.cache/osv-local-db')}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600, env=env)
        if (result.returncode == 127 and len(sboms) > 1
                and ('extraction failed on specified lockfile' in result.stderr
                     or 'failed to resolve path' in result.stderr)):
            # A bad explicit input aborts the command. Isolate it so other inputs still get reports.
            midpoint = len(sboms) // 2
            left = scan_batch(sboms[:midpoint], root, executable, database)
            return {**left, **scan_batch(sboms[midpoint:], root, executable, database)}
        failed_ecosystems = set()
        for line in result.stderr.splitlines():
            if not line.strip():
                continue
            match = re.search(r'could not load db for (.+?) ecosystem:', line)
            if not match:
                raise RuntimeError('OSV scanner error: ' + line[-400:])
            failed_ecosystems.add(match[1].partition(':')[0])
        # OSV can return findings (1) despite an ecosystem extraction failure,
        # or 127 when the remaining sources are clean. Neither proves full coverage.
        if result.returncode not in (0, 1) and not (result.returncode == 127 and failed_ecosystems):
            raise RuntimeError(result.stderr[-400:] or f'OSV-Scanner exited with code {result.returncode}')
        raw = json.loads(result.stdout)
        if not isinstance(raw, dict) or not isinstance(raw.get('results'), list):
            raise ValueError('OSV report lacks results')
        by_source = {}
        for entry in raw['results']:
            source = entry.get('source', {})
            path = source.get('path')
            if source.get('type') == 'sbom' and path in sources:
                by_source.setdefault(path, []).append(entry)
    except Exception as error:
        return {sbom: {'status': 'unavailable', 'reason': str(error)} for sbom in sboms}

    scanned_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
    results = {}
    for path, sbom in sources.items():
        try:
            entries = by_source.get(path, [])
            if len(entries) != 1:
                raise ValueError('OSV report does not uniquely identify this SPDX source')
            entry = entries[0]
            packages = entry.get('packages')
            if not isinstance(packages, list) or not packages:
                raise ValueError('OSV report lacks packages for this SPDX source')
            ecosystems = {package.get('package', {}).get('ecosystem', '').partition(':')[0]
                          for package in packages}
            if failed_ecosystems and ('' in ecosystems or ecosystems & failed_ecosystems):
                raise ValueError('OSV database unavailable for source ecosystem: ' +
                                 ', '.join(sorted(failed_ecosystems & ecosystems or failed_ecosystems)))
            vulnerable = [package for package in packages if package.get('vulnerabilities')]
            report_data = {'results': [{**entry, 'packages': vulnerable}] if vulnerable else []}
            if 'experimental_config' in raw:
                report_data['experimental_config'] = raw['experimental_config']
            report = sbom.with_suffix('.osv.json')
            relative_report = str(report.relative_to(root / 'static'))
            detected = findings(report_data)
            report.write_text(json.dumps(report_data, indent=2) + '\n')
            results[sbom] = {'status': 'scanned', 'scannedAt': scanned_at, 'database': database or {},
                             'findings': detected, 'report': relative_report}
        except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
            results[sbom] = {'status': 'unavailable', 'reason': str(error)}
    return results
