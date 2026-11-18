import json
from pathlib import Path
import sys
import tempfile
from threading import Barrier, Event, get_ident
import unittest
from unittest.mock import patch, call

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import version_history as history


RECORD = {'fetchedAt': '2026-11-18T00:00:00Z', 'builds': []}


class HistoryGenerationTests(unittest.TestCase):
    def test_selective_refresh_only_bypasses_selected_extension(self):
        entries = [{'name': 'one'}, {'name': 'two'}]
        with tempfile.TemporaryDirectory() as directory, patch.object(history, 'ROOT', Path(directory)):
            with patch.object(history, 'fetch_entry', return_value=RECORD) as refresh:
                history.generate_history(entries, refresh_extension='two')
        refresh.assert_has_calls([
            call(entries[0], {}, full_refresh=False, manifest_workers=1),
            call(entries[1], {}, full_refresh=True, manifest_workers=1),
        ], any_order=True)

    def test_failed_generation_preserves_hugo_data_and_successful_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'data/version_history.json'
            destination.parent.mkdir()
            destination.write_text('previous good data')
            started = Barrier(2, timeout=5)
            saved = Event()
            coordinator = get_ident()
            atomic_json = history.atomic_json

            def retrieve(entry, previous, **kwargs):
                started.wait()
                if entry['name'] == 'two':
                    self.assertTrue(saved.wait(5), 'Successful cache write should precede remaining retrievals')
                    raise RuntimeError('offline')
                return RECORD

            def save(path, record):
                self.assertEqual(get_ident(), coordinator)
                atomic_json(path, record)
                saved.set()

            with patch.object(history, 'ROOT', root), patch.object(history, 'fetch_entry', side_effect=retrieve), patch.object(history, 'atomic_json', side_effect=save):
                with self.assertRaisesRegex(RuntimeError, 'offline'):
                    history.generate_history([{'name': 'one'}, {'name': 'two'}])
                self.assertEqual(history.HistoryCache().load('one'), RECORD)
                self.assertEqual(history.HistoryCache().load('two'), {})
            self.assertEqual(destination.read_text(), 'previous good data')

    def test_default_cache_reads_legacy_once_and_prefers_new_files(self):
        entries = [{'name': 'one'}, {'name': 'two'}, {'name': 'three'}]
        legacy_record = {**RECORD, 'fetchedAt': '2026-11-17T00:00:00Z'}
        with tempfile.TemporaryDirectory() as directory, patch.object(history, 'ROOT', Path(directory)):
            cache = history.HistoryCache()
            history.atomic_json(cache.path, {'one': legacy_record, 'two': legacy_record})
            cache.save('one', RECORD)
            read_text = Path.read_text
            with patch.object(Path, 'read_text', autospec=True, side_effect=read_text) as read:
                with patch.object(history, 'fetch_entry', return_value=RECORD) as refresh:
                    history.generate_history(entries)
                self.assertEqual(read.call_args_list.count(call(cache.path)), 1)
            refresh.assert_has_calls([
                call(entries[0], RECORD, full_refresh=False, manifest_workers=1),
                call(entries[1], legacy_record, full_refresh=False, manifest_workers=1),
                call(entries[2], {}, full_refresh=False, manifest_workers=1),
            ], any_order=True)
            self.assertEqual(history.HistoryCache().load('two'), RECORD)
            self.assertEqual(history.HistoryCache().load('three'), RECORD)
            with patch.object(history, 'fetch_entry', return_value=RECORD) as refresh:
                history.refresh_entry(entries[1], full_refresh=True)
            refresh.assert_called_once_with(entries[1], RECORD, full_refresh=True)

    def test_explicit_default_path_updates_the_migrated_cache(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(history, 'ROOT', Path(directory)):
            default = history.HistoryCache()
            default.save('one', RECORD)
            updated = {**RECORD, 'fetchedAt': '2026-11-19T00:00:00Z'}
            explicit = history.HistoryCache(default.path)
            explicit.save('one', updated)
            self.assertEqual(history.HistoryCache().load('one'), updated)

    def test_install_validates_all_entries_before_replacing_hugo_data(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'hugo.json'
            destination.write_text('previous good data')
            records = {'one': RECORD}
            with self.assertRaises(KeyError):
                history.install_history([{'name': 'one'}, {'name': 'two'}], records, destination)
            self.assertEqual(destination.read_text(), 'previous good data')
            history.install_history([{'name': 'one'}], records, destination)
            self.assertEqual(json.loads(destination.read_text()), records)
