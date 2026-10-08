"""Local browser UI. Run: python3 app.py. Uses the standard-library HTTP server."""
import argparse
import errno
import json
import math
import mimetypes
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZipFile, ZIP_DEFLATED

from analyzer import FIELDS, HEADERS, analyze, enrich_report, write_reports
from cli import bound, DEFAULTS
from dashboard import write_dashboard
from local_splunk import diagnose, fetch_triggered

ROOT = Path(__file__).resolve().parent

# The browser analyzes rule triggers, so its reports expose only available data.
UI_HEADERS = {
    'summary': HEADERS['summary'], 'rules': HEADERS['rules'], 'hourly': HEADERS['hourly'],
    'candidates': ['rule_name', 'count', 'percent', 'repeats', 'repeat_percent', 'groups'],
    'repeats': ['rule_name', 'start', 'end', 'count', 'repeats'],
    'alerts': ['_time', 'rule_name'], 'rejected': HEADERS['rejected'],
}


def make_report(rows, headers, payload, source, kind, scope, output_dir, rule_only=False):
    window = float(payload.get('window', 5))
    if not math.isfinite(window) or not 0 < window <= 525600:
        raise ValueError('Tekrar penceresi 0’dan büyük ve en fazla 525600 dakika olmalı.')
    mapping = payload.get('mapping') or {}
    if not isinstance(mapping, dict):
        raise ValueError('Alan eşleştirmesi geçersiz.')
    rule = payload.get('rule_name', '').strip()
    if rule:
        if mapping.get('rule_name'):
            raise ValueError('Kural sütunu ve tek kural adından yalnızca birini seçin.')
        # Work on copies: a second run must not mutate the imported source.
        rows = [{**row, '__assigned_rule__': rule} for row in rows]
        headers = list(headers) + ['__assigned_rule__']
        mapping = {**mapping, 'rule_name': '__assigned_rule__'}
    for field in FIELDS:
        column = mapping.get(field, '')
        if not isinstance(column, str) or (column and column not in headers):
            raise ValueError(f'{field} için dosyada bulunan bir sütun seçin.')
        if not column and field in ('_time', 'rule_name') and rows:
            raise ValueError('Zaman ve kural alanlarını seçin; tek kurallı dosyada kural adını yazabilirsiniz.')
        mapping[field] = column or '__missing_' + field + '__'
    now = datetime.now(timezone.utc)
    earliest, latest = bound(payload.get('earliest'), now), bound(payload.get('latest'), now)
    if earliest and latest and earliest >= latest:
        raise ValueError('Başlangıç zamanı bitişten önce olmalı.')
    report = enrich_report(analyze(rows, mapping, window, earliest, latest, rule_only=rule_only))
    if rule_only:
        report = {name: [{key: row[key] for key in columns} for row in report[name]]
                  for name, columns in UI_HEADERS.items()}
    identifier = secrets.token_hex(8)
    directory = Path(output_dir) / identifier
    metadata = {'kind': kind, 'scope': scope, 'source': source,
                'mapping': {key: value for key, value in mapping.items() if not rule_only or key in ('_time', 'rule_name')},
                'grouping': 'rule_name' if rule_only else 'rule_name,host,user',
                'window_minutes': window, 'earliest': payload.get('earliest'), 'latest': payload.get('latest'),
                'resolved_earliest_utc': earliest.isoformat() if earliest else None,
                'resolved_latest_utc': latest.isoformat() if latest else None,
                'rule_name_override': rule or None}
    write_reports(report, directory, UI_HEADERS if rule_only else None)
    write_dashboard(report, directory, metadata)
    with ZipFile(directory / 'report.zip', 'w', ZIP_DEFLATED) as archive:
        for path in sorted(directory.iterdir()):
            if path.suffix in ('.csv', '.html', '.json'):
                archive.write(path, path.name)
    visible = {name: data[:500] for name, data in report.items()}
    return identifier, directory, {'report': visible, 'counts': {name: len(data) for name, data in report.items()},
                                  'metadata': metadata, 'id': identifier, 'created': now.isoformat()}


class SessionExpired(ValueError):
    pass


def purge_sessions(server):
    now = time.monotonic()
    for sid, item in list(server.sessions.items()):
        if item['expires'] <= now:
            server.sessions.pop(sid, None)


def login_options(payload):
    """UI authentication is explicit; never fall back to .env credentials."""
    for key in ('base_url', 'username', 'password', 'token', 'ca_bundle'):
        if not isinstance(payload.get(key, ''), str) or len(payload.get(key, '')) > 4096:
            raise ValueError('Bağlantı bilgileri geçersiz.')
    mode = payload.get('auth_mode')
    username, password, token = (payload.get(key, '') for key in ('username', 'password', 'token'))
    if mode == 'password' and username.strip() and password and not token:
        credentials = {'username': username.strip(), 'password': password, 'token': ''}
    elif mode == 'token' and token.strip() and not username and not password:
        if '\n' in token or '\r' in token:
            raise ValueError('Token tek satır olmalı.')
        credentials = {'username': '', 'password': '', 'token': token.strip()}
    else:
        raise ValueError('Yalnızca bir giriş yöntemi seçin: kullanıcı/parola veya token. Gerekli alanları doldurun.')
    verify = payload.get('verify_tls', True)
    if type(verify) is not bool:
        raise ValueError('TLS seçimi geçersiz.')
    return {'base_url': payload.get('base_url', '').strip() or 'https://localhost:8089',
            'credentials': credentials, 'verify_tls': verify,
            'ca_bundle': payload.get('ca_bundle', '').strip()}


class Handler(BaseHTTPRequestHandler):
    """Loopback-only UI; credentials stay in expiring server-memory sessions."""
    def log_message(self, *args):
        pass

    def respond(self, status, data, content_type='application/json; charset=utf-8'):
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', f"default-src 'self'; script-src 'self' 'nonce-{self.server.token}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if getattr(self, 'cookie', None):
            self.send_header('Set-Cookie', self.cookie)
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get('Host') in self.server.allowed_hosts

    def reject_post(self, status, message):
        # Drain a small body before closing, avoiding a TCP reset on Windows.
        self.connection.settimeout(2)
        try:
            size = int(self.headers.get('Content-Length', 0))
            if 0 < size <= 65536:
                self.rfile.read(size)
        except (OSError, ValueError):
            pass
        return self.respond(status, {'error': message})

    def current_session(self, required=False):
        purge_sessions(self.server)
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
        except CookieError:
            pass
        sid = cookie['analyzer_session'].value if 'analyzer_session' in cookie else ''
        item = self.server.sessions.get(sid)
        if required and not item:
            raise SessionExpired('Splunk oturumu yok veya süresi dolmuş. Yeniden bağlanın.')
        return sid, item

    @staticmethod
    def session_info(item):
        return {'connected': bool(item), **({
            'base_url': item['options']['base_url'], 'auth_mode': item['mode'],
            'verify_tls': item['options']['verify_tls'],
            'expires_at': item['expires_at']} if item else {})}

    def do_GET(self):
        if not self.valid_host():
            return self.respond(403, {'error': 'Yerel adres kullanın.'})
        path = urlsplit(self.path).path
        if path == '/api/session':
            return self.respond(200, self.session_info(self.current_session()[1]))
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in assets:
            name, content_type = assets[path]
            data = (ROOT / 'ui' / name).read_bytes()
            if path == '/':
                data = data.replace(b'__SESSION_TOKEN__', self.server.token.encode())
            return self.respond(200, data, content_type)
        parts = path.split('/')
        if len(parts) == 4 and parts[1] == 'reports':
            saved = self.server.reports.get(parts[2])
            name = parts[3]
            allowed = {'dashboard.html', 'run.json', 'report.zip'} | {key + '.csv' for key in UI_HEADERS}
            if saved and name in allowed:
                directory, owner = saved
                sid, session = self.current_session()
                if not session or owner != sid:
                    return self.respond(403, {'error': 'Rapor için onu oluşturan Splunk oturumunu kullanın.'})
                target = directory / name
                if target.is_file():
                    content_type = mimetypes.guess_type(name)[0] or 'application/octet-stream'
                    data = target.read_bytes()
                    if name == 'dashboard.html':
                        data = data.replace(b'<script>', f'<script nonce="{self.server.token}">'.encode())
                    return self.respond(200, data, content_type)
        self.respond(404, {'error': 'Dosya bulunamadı.'})

    def do_POST(self):
        origin = self.headers.get('Origin')
        trusted = (self.valid_host() and (not origin or origin in self.server.allowed_origins)
                   and secrets.compare_digest(self.headers.get('X-Analyzer-Token', ''), self.server.token))
        if not trusted:
            return self.reject_post(403, 'Bu yerel uygulama sekmesini yenileyin.')
        path = urlsplit(self.path).path
        if path not in ('/api/connect', '/api/disconnect', '/api/analyze'):
            return self.reject_post(404, 'İşlem bulunamadı.')
        if not self.server.busy.acquire(blocking=False):
            return self.reject_post(409, 'Bir işlem sürüyor. Tamamlanmasını bekleyin.')
        try:
            self.connection.settimeout(30)
            size = int(self.headers.get('Content-Length', 0))
            if not 0 < size <= 65536:
                raise ValueError('İstek boş veya çok büyük.')
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError('İstek tamamlanmadı; tekrar deneyin.')
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError('İstek biçimi geçersiz.')
            self.respond(200, self.action(path, payload))
        except SessionExpired as exc:
            self.respond(401, {'error': str(exc)})
        except ValueError as exc:
            self.respond(400, {'error': str(exc)})
        except (OSError, UnicodeError):
            self.respond(400, {'error': 'Rapor yazılamadı; yerel klasör izinlerini kontrol edin.'})
        except (KeyError, TypeError, AttributeError, OverflowError):
            self.respond(400, {'error': 'Veri veya Splunk yanıtı beklenen biçimde değil.'})
        finally:
            self.server.busy.release()

    def action(self, path, payload):
        if path == '/api/connect':
            options = login_options(payload)
            diagnose(**options)  # Store credentials only after all checks succeed.
            old_sid, _ = self.current_session()
            self.server.sessions.pop(old_sid, None)
            sid = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=3600)
            item = {'options': options, 'mode': payload['auth_mode'],
                    'expires': time.monotonic() + 3600, 'expires_at': expires_at.isoformat()}
            self.server.sessions[sid] = item
            self.cookie = f'analyzer_session={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600'
            return self.session_info(item)
        if path == '/api/disconnect':
            sid, _ = self.current_session()
            self.server.sessions.pop(sid, None)
            self.cookie = 'analyzer_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
            return {'connected': False}
        sid, item = self.current_session(required=True)
        # Validate settings before making any Splunk request.
        window = float(payload.get('window', 5))
        if not math.isfinite(window) or not 0 < window <= 525600:
            raise ValueError('Tekrar penceresi 0’dan büyük ve en fazla 525600 dakika olmalı.')
        settings = {'window': window, 'earliest': payload.get('earliest') or '-24h',
                    'latest': payload.get('latest') or 'now', 'mapping': dict(zip(FIELDS, FIELDS))}
        now = datetime.now(timezone.utc)
        earliest, latest = bound(settings['earliest'], now), bound(settings['latest'], now)
        if earliest and latest and earliest >= latest:
            raise ValueError('Başlangıç zamanı bitişten önce olmalı.')
        # Freeze relative bounds before network I/O, so a slow fetch cannot shift them.
        settings['earliest'] = earliest.isoformat() if earliest else ''
        settings['latest'] = latest.isoformat() if latest else ''
        rows = fetch_triggered(DEFAULTS, **item['options'])
        scope = ('Her kayıt bir alarm tetiklenmesidir. Tekrarlar aynı kuralın kısa aralıklarla '
                 'yeniden tetiklenmesini gösterir; aynı olaya ait olduklarını kanıtlamaz. '
                 'Yalnızca takip edilen, saklama süresi dolmamış ve hesabın görebildiği kayıtlar incelenir.')
        identifier, directory, result = make_report(rows, list(FIELDS), settings,
            'Splunk management API', 'Triggered Alerts / tetiklenme kayıtları', scope, self.server.output_dir,
            rule_only=True)
        self.server.reports[identifier] = (directory, sid)
        return result


def create_server(port=8765, output_dir=None):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    actual_port = server.server_address[1]
    server.allowed_hosts = {f'localhost:{actual_port}', f'127.0.0.1:{actual_port}'}
    server.allowed_origins = {'http://' + host for host in server.allowed_hosts}
    server.token = secrets.token_hex(24)
    server.output_dir = Path(output_dir) if output_dir else ROOT / 'reports' / 'ui'
    server.sessions, server.reports = {}, {}
    server.service_actions = lambda: purge_sessions(server)
    server.busy = threading.Lock()
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description='Yerel Splunk alarm analiz arayüzü')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-open', action='store_true', help='Tarayıcıyı otomatik açma')
    args = parser.parse_args()
    try:
        with create_server(args.port) as server:
            url = f'http://127.0.0.1:{server.server_address[1]}'
            print(f'\nSplunk Alert Noise Analyzer\nArayüz: {url}\nDurdurmak için Ctrl+C.\n')
            if not args.no_open:
                webbrowser.open(url)
            server.serve_forever()
    except KeyboardInterrupt:
        print('\nUygulama kapatıldı.')
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            alternate = 8766 if args.port != 8766 else 8767
            print(f'{args.port} portu başka bir süreç tarafından kullanılıyor.')
            print(f'Başlatıcıyla farklı port deneyin: bash start.sh --port {alternate}')
        else:
            print(f'Yerel arayüz başlatılamadı (işletim sistemi hata kodu: {exc.errno}).')
            print('Port ayarını ve yerel izinleri kontrol edin. Başlatıcı: bash start.sh')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
