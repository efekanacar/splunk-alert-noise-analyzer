import contextlib
import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from analyzer import analyze, enrich_report, FIELDS, write_reports
from cli import main, bound
from dashboard import write_dashboard
from input_files import load_file, resolve_fields, discover_files
from local_splunk import fetch_triggered, connection
from datetime import datetime, timezone

MAPPING = dict(zip(FIELDS, FIELDS))


class FileTests(unittest.TestCase):
    def test_gzip_csv_and_missing_optional(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'results.csv.gz'
            with gzip.open(path, 'wt', encoding='utf-8') as f:
                f.write('_time,rule_name\n0,Rule\n60,Rule\n')
            rows, headers = load_file(path)
            result = analyze(rows, resolve_fields(headers))
            self.assertEqual(result['summary'][0]['repeat_alerts'], 1)
            self.assertEqual(result['repeats'][0]['confidence'], 'low')

    def test_json_formats(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, body in [('a.json', '[{"_time":0,"rule_name":"R"}]'),
                               ('b.json', '{"results":[{"_time":0,"rule_name":"R"}]}'),
                               ('c.jsonl', '{"result":{"_time":0,"rule_name":"R"}}\n')]:
                path = Path(folder) / name
                path.write_text(body, encoding='utf-8')
                rows, headers = load_file(path)
                self.assertEqual(rows[0]['rule_name'], 'R')

    def test_csv_shape_and_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'a.csv'
            for body in ('a,a\n1,2', 'a,b\n1,2,3', 'a,b\n1'):
                path.write_text(body, encoding='utf-8')
                with self.assertRaises(ValueError):
                    load_file(path)
            path.write_text('_time,rule_name\n0,R\n1,R', encoding='utf-8')
            with self.assertRaises(ValueError):
                load_file(path, max_rows=1)
            with self.assertRaises(ValueError):
                load_file(path, max_bytes=2)

    def test_ambiguous_mapping_requires_choice(self):
        with self.assertRaises(ValueError):
            resolve_fields(['_time', 'rule_name', 'host', 'dest'])
        self.assertEqual(resolve_fields(['_time', 'rule_name', 'host', 'dest'], {'host':'dest'})['host'], 'dest')

    def test_discovery_does_not_read_indexes(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            for name in ('var/run/splunk/csv/one.csv', 'var/run/splunk/dispatch/sid/results.csv.gz',
                         'var/lib/splunk/index/secret.csv'):
                path = home / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'not read by discovery')
            files, notes = discover_files(home)
            self.assertEqual(len(files), 2)
            self.assertFalse(any('secret' in item['path'] for item in files))


class ReportTests(unittest.TestCase):
    def test_metrics_and_html_escaping(self):
        rule = '<script>alert("x")</script>'
        rows = [{'_time': str(n), 'rule_name': rule, 'host':'h', 'user':'u', 'severity':'high'} for n in (0, 60, 300)]
        report = enrich_report(analyze(rows, MAPPING))
        self.assertEqual(report['candidates'][0]['repeats'], 1)
        self.assertEqual(report['candidates'][0]['repeat_percent'], 33.33)
        with tempfile.TemporaryDirectory() as folder:
            write_reports(report, folder)
            path = write_dashboard(report, folder, {'kind':'Test', 'scope':'Test', 'source':rule, 'window_minutes':5})
            html = path.read_text(encoding='utf-8')
            self.assertNotIn(rule, html)
            self.assertIn('&lt;script&gt;', html)
            self.assertTrue((Path(folder) / 'run.json').exists())

    def test_cli_demo_and_non_overwrite(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            target = Path(folder) / 'report'
            self.assertEqual(main(['--demo', '--output-dir', str(target)]), 0)
            self.assertTrue((target / 'dashboard.html').exists())
            self.assertEqual(main(['--demo', '--output-dir', str(target)]), 1)

    def test_single_rule_export(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            path = Path(folder) / 'a.csv'
            path.write_text('_time,host\n0,server\n60,server', encoding='utf-8')
            self.assertEqual(main(['--file', str(path), '--rule-name', 'My actual rule', '--output-dir', str(Path(folder)/'out')]), 0)

    def test_relative_bounds(self):
        now = datetime(2026, 10, 7, tzinfo=timezone.utc)
        self.assertEqual((now - bound('-24h', now)).total_seconds(), 86400)

    def test_menu_demo(self):
        with tempfile.TemporaryDirectory() as folder, patch('cli.sys.stdin.isatty', return_value=True), \
                patch('builtins.input', return_value='1'), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--output-dir', str(Path(folder) / 'out')]), 0)

    def test_menu_single_rule_file(self):
        with tempfile.TemporaryDirectory() as folder, patch('cli.sys.stdin.isatty', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(folder) / 'results.csv'
            path.write_text('_time,host\n0,server\n60,server', encoding='utf-8')
            with patch('builtins.input', side_effect=['2', str(path), '', 'Known rule', '']):
                self.assertEqual(main(['--output-dir', str(Path(folder) / 'out')]), 0)


class TriggeredTests(unittest.TestCase):
    def fetch(self, payloads):
        session = MagicMock()
        session.__enter__.return_value = session
        responses = []
        for payload in payloads:
            r = MagicMock(status_code=200)
            r.json.return_value = payload
            responses.append(r)
        session.get.side_effect = responses
        with patch('local_splunk.requests.Session', return_value=session), patch.dict('os.environ', {'SPLUNK_TOKEN':'test-only'}, clear=True):
            rows = fetch_triggered({'search_timeout_seconds':120, 'request_timeout_seconds':15, 'page_size':1, 'max_results':10})
        return rows, session

    def test_paging_and_no_invented_user(self):
        first = {'id':'a', 'content':{'savedsearch_name':'Rule', 'trigger_time':'0', 'severity':'3', 'triggered_alerts':99}, 'author':'admin'}
        second = {'id':'b', 'content':{'savedsearch_name':'Rule', 'trigger_time':'60'}}
        rows, session = self.fetch([{'entry':[first], 'paging':{'total':2, 'offset':0}}, {'entry':[second], 'paging':{'total':2, 'offset':1}}])
        self.assertEqual(len(rows), 2)  # Never turn triggered_alerts=99 into 99 events.
        self.assertEqual(rows[0]['user'], '')
        self.assertEqual(session.get.call_args.kwargs['params']['offset'], 1)
        self.assertTrue(session.get.call_args.kwargs['verify'])

    def test_partial_unstable_and_duplicate_fail(self):
        entry = {'id':'a', 'content':{'savedsearch_name':'r', 'trigger_time':'0'}}
        first = {'entry':[entry], 'paging':{'total':2, 'offset':0}}
        for second in ({'entry':[], 'paging':{'total':2, 'offset':1}},
                       {'entry':[], 'paging':{'total':3, 'offset':1}},
                       {'entry':[entry], 'paging':{'total':2, 'offset':1}}):
            with self.subTest(second=second), self.assertRaises(ValueError):
                self.fetch([first, second])

    def test_empty_collection(self):
        rows, _ = self.fetch([{'entry':[], 'paging':{'total':0}}])
        self.assertEqual(rows, [])

    def test_no_total_rejected(self):
        with self.assertRaises(ValueError):
            self.fetch([{'entry':[]}])

    def test_default_localhost_and_tls(self):
        with patch.dict('os.environ', {}, clear=True):
            session, base, verify = connection()
            session.close()
            self.assertEqual(base, 'https://localhost:8089')
            self.assertIs(verify, True)
            with self.assertRaises(ValueError):
                connection('http://localhost:8000')


if __name__ == '__main__':
    unittest.main()
