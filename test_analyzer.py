import unittest
import requests
from analyzer import FIELDS, analyze, parse_time, read_csv
from splunk_client import validate_search, fetch_results
from unittest.mock import patch, MagicMock

MAPPING = dict(zip(FIELDS, FIELDS))


def row(time, **kwargs):
    return {'_time': time, 'rule_name': 'r', 'host': 'h', 'user': 'u', **kwargs}


class AnalysisTests(unittest.TestCase):
    def test_fixed_windows_sorted_and_boundary(self):
        rows = [row(f'2026-10-01T10:{m}:00Z') for m in ('08', '05', '04', '00', '09', '10')]
        result = analyze(rows, MAPPING)
        self.assertEqual([g['count'] for g in result['repeats']], [2, 3])
        self.assertEqual(result['summary'][0]['repeat_alerts'], 3)

    def test_rule_triggers_ignore_entities_and_keep_fixed_boundaries(self):
        rows = [row(str(t), host=f'h{t}', user=f'u{t}') for t in (301, 299, 0, 300, 60)]
        result = analyze(rows, MAPPING, rule_only=True)
        self.assertEqual([group['count'] for group in result['repeats']], [3, 2])
        self.assertEqual(result['summary'][0]['repeat_alerts'], 3)
        # The original CSV analysis still separates distinct entity combinations.
        self.assertEqual(analyze(rows, MAPPING)['summary'][0]['repeat_alerts'], 0)

    def test_missing_and_invalid(self):
        rows = [row('0', host='', user=''), row('60', host='', user=''),
                row('bad'), row('120', rule_name=''), row('180', host='other')]
        result = analyze(rows, MAPPING)
        self.assertEqual(result['summary'][0]['skipped_rows'], 2)
        self.assertEqual(result['summary'][0]['total_alerts'], 3)
        self.assertEqual(result['repeats'][0]['confidence'], 'low')
        self.assertEqual(result['repeats'][0]['host'], 'unknown')
        self.assertEqual(result['alerts'][0]['severity'], 'unknown')

    def test_timezone_and_bounds(self):
        self.assertEqual(parse_time('2026-10-01T13:00:00+03:00'), parse_time('2026-10-01T10:00:00Z'))
        result = analyze([row('0'), row('60'), row('120')], MAPPING, earliest=parse_time('60'), latest=parse_time('120'))
        self.assertEqual(result['summary'][0]['total_alerts'], 1)
        self.assertEqual(result['summary'][0]['filtered_rows'], 2)
        with self.assertRaises(ValueError):
            parse_time('2026-10-01T10:00:00')

    def test_empty(self):
        self.assertEqual(analyze([], MAPPING)['summary'][0]['repeat_alerts'], 0)

    def test_sample(self):
        result = analyze(read_csv('sample_alerts.csv', MAPPING), MAPPING)
        self.assertEqual(result['summary'][0], dict(input_rows=12, total_alerts=10, skipped_rows=2,
                                                  filtered_rows=0, repeat_groups=3, repeat_alerts=4))
        self.assertEqual(result['rules'][0]['percent'], 50.0)

    def test_read_only_guard(self):
        for search in ('search index=x | outputlookup x', 'search `macro`', 'search [search x]',
                       '| savedsearch x', 'search x | collect index=y', 'search x | map search="x"'):
            with self.subTest(search=search), self.assertRaises(ValueError):
                validate_search(search)
        validate_search('search index=x | rename title AS rule_name | fields _time rule_name')


class SplunkTests(unittest.TestCase):
    def fetch(self, payloads, status_code=200, error=None):
        config = dict(search='search index=test', search_timeout_seconds=10,
                      request_timeout_seconds=2, page_size=2, max_results=10)
        session = MagicMock()
        session.__enter__.return_value = session
        responses = []
        for payload in payloads:
            response = MagicMock(status_code=status_code)
            response.json.return_value = payload
            responses.append(response)
        session.request.side_effect = error or responses
        with patch('splunk_client.requests.Session', return_value=session), patch.dict(
                'os.environ', {'SPLUNK_TOKEN': 'fake-test-token'}, clear=True):
            result = fetch_results(config, '-24h', 'now')
        return result, session

    def test_http_and_transport_errors(self):
        for code in (400, 401, 403, 500, 302):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.fetch([{}], status_code=code)
        for error in (requests.exceptions.Timeout(), requests.exceptions.ConnectionError(), requests.exceptions.SSLError()):
            with self.subTest(error=type(error).__name__), self.assertRaises(ValueError):
                self.fetch([], error=error)

    def test_overall_deadline(self):
        with patch('splunk_client.time.monotonic', side_effect=[0, 11]), self.assertRaisesRegex(ValueError, 'timeout'):
            self.fetch([])

    def test_pagination(self):
        result, session = self.fetch([{'sid': 'test'}, {'entry': [{'content': {'isDone': True, 'resultCount': 3}}]},
                                     {'results': [row('0'), row('60')]}, {'results': [row('120')]}])
        self.assertEqual(len(result), 3)
        self.assertEqual(session.request.call_args.kwargs['params']['offset'], 2)
        self.assertTrue(session.request.call_args.kwargs['verify'])

    def test_incomplete_pages_and_server_limits(self):
        for content, pages in [({'isDone': True, 'resultCount': 3}, [{'results': []}]),
                               ({'isDone': True, 'resultCount': 10}, []),
                               ({'isDone': True, 'isFinalized': True, 'resultCount': 1}, []),
                               ({'isFailed': True}, []),
                               ({'messages': [{'type': 'WARN'}]}, [])]:
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.fetch([{'sid': 'test'}, {'entry': [{'content': content}]}, *pages])


if __name__ == '__main__':
    unittest.main()
