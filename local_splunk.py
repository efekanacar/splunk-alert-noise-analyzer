"""GET-only local connection checks and tracked alert retrieval."""
import getpass
import os
import socket
import time
from urllib.parse import urlsplit

import requests

from splunk_client import check_messages


def connection(base_url=None, insecure=False, interactive=False, credentials=None, verify_tls=None, ca_bundle=None):
    base = (base_url or os.getenv('SPLUNK_BASE_URL') or 'https://localhost:8089').rstrip('/')
    parsed = urlsplit(base)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or parsed.port == 8000):
        raise ValueError('HTTPS management adresi kullanın: https://localhost:8089 (web portu 8000 değil).')
    tls = os.getenv('SPLUNK_VERIFY_TLS', 'true').lower() if verify_tls is None else ('true' if verify_tls else 'false')
    if tls not in ('true', 'false'):
        raise ValueError('SPLUNK_VERIFY_TLS yalnızca true veya false olabilir.')
    ca = os.getenv('SPLUNK_CA_BUNDLE') if ca_bundle is None else ca_bundle
    verify = False if insecure or tls == 'false' else ca or True
    if verify is False:
        print('UYARI: TLS sertifika doğrulaması bu bağlantıda kapalı.')
    session = requests.Session()
    session.trust_env = False
    token = credentials.get('token') if credentials is not None else os.getenv('SPLUNK_TOKEN')
    user = credentials.get('username') if credentials is not None else os.getenv('SPLUNK_USERNAME')
    password = credentials.get('password') if credentials is not None else os.getenv('SPLUNK_PASSWORD')
    if token:
        session.headers['Authorization'] = f'Bearer {token}'
    else:
        if interactive and not (user and password):
            user = input('Splunk kullanıcı adı: ').strip()
            password = getpass.getpass('Splunk parolası (gizli, kaydedilmez): ')
        if user and password:
            session.auth = (user, password)
    return session, base, verify


def get_json(session, base, verify, path, timeout=15, params=None):
    try:
        response = session.get(base + path, params={'output_mode': 'json', **(params or {})},
                               verify=verify, timeout=timeout, allow_redirects=False)
        if response.status_code == 401:
            raise ValueError('401: Splunk kimlik doğrulaması başarısız. Kullanıcı/parola veya token kontrol edin.')
        if response.status_code == 403:
            raise ValueError('403: Bu kayıtları okuma yetkisi yok. Splunk rol/uygulama erişimini kontrol edin.')
        if not 200 <= response.status_code < 300:
            raise ValueError(f'HTTP {response.status_code}: Management API yolu veya sunucu durumunu kontrol edin.')
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError('API beklenen JSON nesnesini döndürmedi.')
        check_messages(data)
        return data
    except requests.exceptions.SSLError:
        raise ValueError('TLS: Sertifika doğrulanamadı. Özel CA dosyasını belirtin; yalnızca lab için TLS doğrulamasını kapatın.') from None
    except requests.exceptions.Timeout:
        raise ValueError('Timeout: Splunk yanıt vermedi; servis ve management portunu kontrol edin.') from None
    except requests.exceptions.JSONDecodeError:
        raise ValueError('API JSON döndürmedi; management portunu kontrol edin.') from None
    except requests.exceptions.RequestException:
        raise ValueError('Bağlantı kurulamadı. Aynı Ubuntu için localhost:8089 ve splunkd servis durumunu kontrol edin.') from None
    except OSError:
        raise ValueError('CA dosyası okunamadı; SPLUNK_CA_BUNDLE yolunu kontrol edin.') from None


def diagnose(base_url=None, insecure=False, interactive=False, credentials=None, verify_tls=None, ca_bundle=None):
    session, base, verify = connection(base_url, insecure, interactive, credentials, verify_tls, ca_bundle)
    with session:
        parsed = urlsplit(base)
        print(f'Management adresi: {base}')
        try:
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=4):
                print('TCP: erişilebilir. Bu tek başına Splunk oturumu demek değildir.')
        except OSError:
            raise ValueError('TCP erişilemiyor. Ubuntu’da: systemctl status Splunkd veya /opt/splunk/bin/splunk status') from None
        if not session.auth and 'Authorization' not in session.headers:
            raise ValueError('TCP açık; kimlik doğrulama test edilmedi. Menüyü kullanın veya .env kimlik bilgilerini doldurun.')
        data = get_json(session, base, verify, '/services/authentication/current-context')
        if not data.get('entry'):
            raise ValueError('Oturum yanıtı doğrulanamadı.')
        print('TLS/HTTP ve kimlik doğrulama: başarılı.')
        get_json(session, base, verify, '/servicesNS/-/-/alerts/fired_alerts/-', params={'count': 1})
        print('Triggered Alerts okuma: başarılı. Görünür kayıtlar yetki ve saklama süresiyle sınırlıdır.')
        return {'tcp': 'Başarılı', 'authentication': 'Başarılı', 'alerts': 'Başarılı',
                'tls': 'Doğrulama açık' if verify is not False else 'Doğrulama kapalı (lab)'}


def fetch_triggered(config, base_url=None, insecure=False, interactive=False, credentials=None, verify_tls=None, ca_bundle=None):
    session, base, verify = connection(base_url, insecure, interactive, credentials, verify_tls, ca_bundle)
    with session:
        if not session.auth and 'Authorization' not in session.headers:
            raise ValueError('Kimlik bilgisi yok. python3 cli.py menüsünü kullanın veya .env doldurun.')
        deadline = time.monotonic() + config['search_timeout_seconds']
        entries, seen, expected = [], set(), None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Triggered Alerts indirme süresi doldu; kısmi rapor oluşturulmadı.')
            data = get_json(session, base, verify, '/servicesNS/-/-/alerts/fired_alerts/-',
                            timeout=min(remaining, config['request_timeout_seconds']),
                            params={'count': config['page_size'], 'offset': len(entries)})
            if time.monotonic() >= deadline:
                raise ValueError('Triggered Alerts indirme süresi doldu.')
            batch = data.get('entry')
            paging = data.get('paging', {})
            if not isinstance(batch, list) or 'total' not in paging:
                raise ValueError('API sayfalama toplamı vermedi; bütünlük doğrulanamadı. CSV dışa aktarımı kullanın.')
            total = int(paging['total'])
            if total < 0 or total > config['max_results']:
                raise ValueError('Triggered Alerts sonuç limiti aşıldı; max_results veya dışa aktarım kapsamını düzenleyin.')
            if expected is not None and total != expected:
                raise ValueError('İndirme sırasında kayıt toplamı değişti; tutarlı rapor için tekrar deneyin.')
            expected = total
            if 'offset' in paging and int(paging['offset']) != len(entries):
                raise ValueError('API sayfa konumu uyuşmuyor; kısmi rapor oluşturulmadı.')
            for item in batch:
                identity = item.get('id')
                if not identity or identity in seen:
                    raise ValueError('Yinelenen/kimliksiz API kaydı; sayfalama doğrulanamadı.')
                seen.add(identity)
                entries.append(item)
            if len(entries) == expected:
                break
            if not batch or len(entries) > expected:
                raise ValueError('Eksik/fazla API sayfası; kısmi rapor oluşturulmadı.')
        rows = []
        for entry in entries:
            content = entry.get('content', {})
            # These are trigger records, not per-result events. Do not invent
            # a host/user from the search owner or server metadata.
            rows.append({'_time': content.get('trigger_time', ''),
                         'rule_name': content.get('savedsearch_name', ''),
                         'host': '', 'user': '',
                         'severity': content.get('severity', '')})
        return rows
