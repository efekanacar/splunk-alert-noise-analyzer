"""Exercise the browser's actual HTTP routes with mocked Splunk responses."""
import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

import requests
from app import UI_HEADERS, create_server, make_report
from analyzer import FIELDS
from local_splunk import connection


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = create_server(0, cls.temp.name)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.addCleanup(self.session.close)
        self.server.sessions.clear()

    def post(self, route, payload, token=True, session=None):
        headers = {'X-Analyzer-Token': self.server.token} if token else {}
        return (session or self.session).post(self.base + route, json=payload, headers=headers, timeout=5)

    def login(self, mode='password'):
        payload = {'auth_mode':mode, 'base_url':'https://localhost:8089', 'verify_tls':True}
        payload.update({'username':'lab', 'password':'test-only-secret'} if mode == 'password'
                       else {'token':'test-only-token'})
        with patch('app.diagnose', return_value={}) as diagnose:
            response = self.post('/api/connect', payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('test-only', response.text)
        return response, diagnose

    def test_password_session_and_cookie(self):
        response, diagnose = self.login()
        self.assertTrue(response.json()['connected'])
        self.assertIn('HttpOnly', response.headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', response.headers['Set-Cookie'])
        self.assertEqual(diagnose.call_args.kwargs['credentials']['username'], 'lab')
        status = self.session.get(self.base + '/api/session', timeout=5)
        self.assertTrue(status.json()['connected'])
        self.assertNotIn('test-only-secret', status.text)

    def test_token_mode(self):
        response, diagnose = self.login('token')
        self.assertEqual(response.json()['auth_mode'], 'token')
        self.assertEqual(diagnose.call_args.kwargs['credentials']['token'], 'test-only-token')
        self.assertEqual(diagnose.call_args.kwargs['credentials']['password'], '')

    def test_missing_mixed_credentials_and_invalid_tls(self):
        invalid = [{}, {'auth_mode':'password','username':'lab'},
                   {'auth_mode':'password','username':'lab','password':'x','token':'y'},
                   {'auth_mode':'token','token':'x','username':'lab'},
                   {'auth_mode':'token','token':'x','verify_tls':'false'}]
        with patch('app.diagnose') as diagnose:
            for payload in invalid:
                with self.subTest(payload=payload):
                    self.assertEqual(self.post('/api/connect', payload).status_code, 400)
            diagnose.assert_not_called()
        self.assertFalse(self.server.sessions)

    def test_failed_connection_is_not_authenticated(self):
        with patch('app.diagnose', side_effect=ValueError('401: Kimlik doğrulaması başarısız.')):
            response = self.post('/api/connect', {'auth_mode':'token','token':'test-only-token'})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.server.sessions)
        self.assertFalse(self.session.get(self.base + '/api/session', timeout=5).json()['connected'])

    def test_analyze_requires_session_and_expires(self):
        with patch('app.fetch_triggered') as fetch:
            self.assertEqual(self.post('/api/analyze', {}).status_code, 401)
            self.login()
            item = next(iter(self.server.sessions.values()))
            item['expires'] = time.monotonic() - 1
            self.assertEqual(self.post('/api/analyze', {}).status_code, 401)
            fetch.assert_not_called()
        self.assertFalse(self.server.sessions)

    def test_logout_revokes_credentials(self):
        self.login()
        self.assertEqual(self.post('/api/disconnect', {}).status_code, 200)
        self.assertFalse(self.server.sessions)
        self.assertEqual(self.post('/api/analyze', {}).status_code, 401)
        self.assertFalse(self.session.cookies.get('analyzer_session'))

    def test_analyze_download_scope_and_report_privacy(self):
        self.login()
        rows = [{'_time':str(t),'rule_name':'Rule','host':'','user':'','severity':''}
                for t in (300, 0, 299, 600, 301)]
        settings = {'window':5,'earliest':'1970-01-01T00:00:00Z','latest':'1970-01-01T01:00:00Z'}
        with patch('app.fetch_triggered', return_value=rows) as fetch:
            response = self.post('/api/analyze', settings)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result['report']['summary'][0]['total_alerts'], 5)
        self.assertEqual(result['report']['summary'][0]['repeat_alerts'], 2)
        self.assertEqual(set(result['report']), set(UI_HEADERS))
        self.assertEqual(set(result['report']['alerts'][0]), {'_time', 'rule_name'})
        self.assertNotIn('confidence', result['report']['repeats'][0])
        self.assertNotIn('unknown', response.text)
        self.assertEqual(result['metadata']['grouping'], 'rule_name')
        self.assertIn('tetiklenme', result['metadata']['kind'])
        self.assertNotIn('test-only-secret', response.text)
        self.assertEqual(fetch.call_args.kwargs['credentials']['password'], 'test-only-secret')
        url = self.base + f'/reports/{result["id"]}/report.zip'
        download = self.session.get(url, timeout=5)
        self.assertEqual(download.status_code, 200)
        with ZipFile(io.BytesIO(download.content)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn('dashboard.html', archive.namelist())
            self.assertNotIn('.env', archive.namelist())
            self.assertEqual({name for name in archive.namelist() if name.endswith('.csv')},
                             {name + '.csv' for name in UI_HEADERS})
            for name in archive.namelist():
                self.assertNotIn(b'test-only-secret', archive.read(name))
                self.assertNotIn(b'unknown', archive.read(name))
            for name, columns in UI_HEADERS.items():
                self.assertEqual(archive.read(name + '.csv').decode().splitlines()[0], ','.join(columns))
            html = archive.read('dashboard.html').decode()
            self.assertNotIn('Severity', html)
            self.assertNotIn('<h2>Veri kalitesi', html)
            self.assertNotIn('<th scope="col">Host</th>', html)
        stranger = requests.Session()
        stranger.trust_env = False
        with stranger:
            self.assertEqual(stranger.get(url, timeout=5).status_code, 403)

    def test_invalid_settings_do_not_fetch(self):
        self.login()
        with patch('app.fetch_triggered') as fetch:
            for payload in ({'window':0},{'window':'nan'},{'earliest':'now','latest':'-24h'}):
                self.assertEqual(self.post('/api/analyze', payload).status_code, 400)
            fetch.assert_not_called()

    def test_missing_csrf_and_foreign_origin(self):
        self.assertEqual(self.post('/api/connect', {}, token=False).status_code, 403)
        response = self.session.post(self.base + '/api/connect', json={}, headers={
            'X-Analyzer-Token':self.server.token,'Origin':'https://example.org'}, timeout=5)
        self.assertEqual(response.status_code, 403)

    def test_removed_file_routes_and_arbitrary_paths(self):
        for route in ('/api/demo','/api/import','/api/discover','/api/local-import','/api/splunk'):
            self.assertEqual(self.post(route, {}).status_code, 404)
        self.assertEqual(self.session.get(self.base, headers={'Host':'example.org'}, timeout=5).status_code, 403)
        self.assertEqual(self.session.get(self.base + '/.env', timeout=5).status_code, 404)
        home = self.session.get(self.base, timeout=5)
        self.assertIn(self.server.token, home.text)
        self.assertIn('Efekan Acar', home.text)
        self.assertNotIn('CSV yükle', home.text)

    def test_ui_tls_and_ca_override_environment(self):
        with patch.dict('os.environ', {'SPLUNK_VERIFY_TLS':'false','SPLUNK_CA_BUNDLE':'env.pem',
                                      'SPLUNK_TOKEN':'env-secret'}, clear=True):
            session, base, verify = connection(credentials={'username':'lab','password':'x'},
                                               verify_tls=True, ca_bundle='')
            with session:
                self.assertIs(verify, True)
                self.assertEqual(session.auth, ('lab','x'))
                self.assertNotIn('Authorization', session.headers)
            session, _, verify = connection(credentials={'token':'x'}, verify_tls=True, ca_bundle='lab.pem')
            session.close()
            self.assertEqual(verify, 'lab.pem')
            with contextlib.redirect_stdout(io.StringIO()):
                session, _, verify = connection(credentials={'token':'x'}, verify_tls=False)
            session.close()
            self.assertIs(verify, False)

    def test_single_rule_does_not_mutate_source(self):
        rows = [{'_time':'0'}]
        with tempfile.TemporaryDirectory() as folder:
            _, _, result = make_report(rows, ['_time'], {'mapping':{'_time':'_time'},'rule_name':'Rule','window':5},
                                       'file','file','scope',folder)
        self.assertEqual(rows, [{'_time':'0'}])
        self.assertEqual(result['report']['rules'][0]['rule_name'], 'Rule')

    def test_empty_rule_report(self):
        with tempfile.TemporaryDirectory() as folder:
            _, directory, result = make_report([], list(FIELDS), {'mapping':dict(zip(FIELDS, FIELDS))},
                'Splunk', 'Tetiklenme kayıtları', 'Aynı kuralın tekrarları.', folder, rule_only=True)
            self.assertEqual(result['report']['summary'][0]['total_alerts'], 0)
            self.assertEqual(result['counts']['repeats'], 0)
            self.assertEqual(set(result['metadata']['mapping']), {'_time', 'rule_name'})
            self.assertNotIn('unknown', (directory / 'dashboard.html').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
