import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from version_history_snapshot import publish, import_archive, fetch_latest, mark_complete


def histories():
    return {'semver': {'fetchedAt': '2026-11-18T00:00:00+00:00', 'builds': [{
        'version': '0.43.0', 'reference': 'ghcr.io/org/semver:tag@sha256:' + 'a' * 64,
        'annotations': {}, 'platforms': [],
        'imageURL': 'https://github.com/orgs/org/packages/container/semver/123?tag=tag'}]}}


def archive(snapshot):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('version-history.json', json.dumps(snapshot))
    return stream.getvalue()


class SnapshotTests(unittest.TestCase):
    def test_partial_progress_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'candidate').write_text(json.dumps(histories()))
            (root/'catalog').write_text(json.dumps({'extensions': [{'name': 'semver'}, {'name': 'missing'}]}))
            with self.assertRaises(KeyError):
                publish(root/'candidate', root/'catalog', root/'snapshot')
            self.assertFalse((root/'snapshot').exists())

    def test_complete_publish_and_import(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'candidate').write_text(json.dumps(histories()))
            (root/'catalog').write_text(json.dumps({'extensions': [{'name': 'semver'}]}))
            mark_complete(root/'candidate', root/'catalog')
            publish(root/'candidate', root/'catalog', root/'snapshot')
            import_archive(archive(json.loads((root/'snapshot').read_text())), root/'hugo.json')
            self.assertEqual(json.loads((root/'hugo.json').read_text()), histories())

    def test_invalid_artifact_does_not_replace_hugo_data(self):
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d)/'hugo.json'
            destination.write_text('previous good data')
            for snapshot in ({'schemaVersion': 2}, {'schemaVersion': 1, 'publishedAt': '2026-11-18T00:00:00Z', 'extensions': {}}):
                with self.assertRaises(ValueError):
                    import_archive(archive(snapshot), destination)
                self.assertEqual(destination.read_text(), 'previous good data')

    def test_failed_and_in_progress_runs_are_never_imported(self):
        response = Mock(status_code=200, links={})
        response.json.return_value = {'workflow_runs': [
            {'id': 3, 'status': 'completed', 'conclusion': 'failure', 'head_branch': 'main'},
            {'id': 2, 'status': 'in_progress', 'conclusion': None, 'head_branch': 'main'},
            {'id': 1, 'status': 'completed', 'conclusion': 'success', 'head_branch': 'main', 'html_url': 'https://github.com/org/repo/actions/runs/1'}]}
        artifacts = Mock()
        artifacts.json.return_value = {'artifacts': [{'id': 10, 'name': 'versions-history-snapshot', 'expired': False}]}
        download = Mock(content=archive({'schemaVersion': 1, 'publishedAt': '2026-11-18T00:00:00Z', 'extensions': histories()}))
        with tempfile.TemporaryDirectory() as d, patch('version_history_snapshot.requests.Session') as factory:
            factory.return_value.get.side_effect = [response, artifacts, download]
            self.assertTrue(fetch_latest('org/repo', 'test-token', Path(d)/'hugo.json'))
            urls = [c.args[0] for c in factory.return_value.get.call_args_list]
            self.assertIn('/runs/1/artifacts', urls[1])
            self.assertEqual(len(urls), 3)

    def test_no_successful_snapshot_is_a_valid_initial_state(self):
        response = Mock(status_code=200, links={})
        response.json.return_value = {'workflow_runs': []}
        with tempfile.TemporaryDirectory() as d, patch('version_history_snapshot.requests.Session') as factory:
            factory.return_value.get.return_value = response
            destination = Path(d)/'hugo.json'
            self.assertFalse(fetch_latest('org/repo', 'test-token', destination))
            self.assertFalse(destination.exists())

    def test_modified_progress_cannot_reuse_a_previous_completion_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'candidate').write_text(json.dumps(histories()))
            (root/'catalog').write_text(json.dumps({'extensions':[{'name':'semver'}]}))
            mark_complete(root/'candidate',root/'catalog')
            updated=histories()
            updated['semver']['fetchedAt']='2026-11-19T00:00:00Z'
            (root/'candidate').write_text(json.dumps(updated))
            with self.assertRaises(ValueError):
                publish(root/'candidate',root/'catalog',root/'snapshot')
            self.assertFalse((root/'snapshot').exists())
