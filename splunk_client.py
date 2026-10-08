"""A deliberately restricted, read-only SPL search client."""
import os
import time
from urllib.parse import quote, urlsplit

import requests


def validate_search(search):
    # Reject expansion/nesting before dispatch; these can hide write commands.
    if not isinstance(search, str) or 'REPLACE_WITH_' in search or not search.strip():
        raise ValueError('Configure a real SPL search in config.json first.')
    if any(c in search for c in '`[]'):
        raise ValueError('Macros and subsearches are not supported in read-only mode.')
    # Conservative split: pipes inside strings are also rejected if they look
    # like unsupported commands. This intentionally favors safety over full SPL.
    if '\\' in search or search.count('"') % 2 or "'" in search:
        raise ValueError('Escapes, single quotes and unbalanced quotes are unsupported in read-only SPL.')
    parts = search.split('|')
    # Conservative grammar: only search, fields and rename are permitted.
    for i, part in enumerate(parts):
        command = part.strip().split(maxsplit=1)[0].lower() if part.strip() else ''
        if command not in ({'search'} if i == 0 else {'search', 'fields', 'rename'}):
            raise ValueError('Read-only SPL supports search, fields and rename only; start with search.')
    return search


def truth(value):
    return str(value).lower() in ('1', 'true')


def check_messages(payload):
    messages = payload.get('messages', [])
    if isinstance(messages, dict):
        messages = [{'type': k} for k in messages]
    if any(str(m.get('type', '')).upper() in ('WARN', 'WARNING', 'ERROR', 'FATAL') for m in messages):
        raise ValueError('Splunk reported a warning/error; results may be incomplete. Inspect the job in Splunk.')


def fetch_results(config, earliest, latest):
    search = validate_search(config['search'])
    base = os.getenv('SPLUNK_BASE_URL', 'https://localhost:8089').rstrip('/')
    url = urlsplit(base)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path or url.query or url.fragment or url.port == 8000:
        raise ValueError('SPLUNK_BASE_URL must be an HTTPS management origin (normally port 8089), without credentials/path.')
    tls = os.getenv('SPLUNK_VERIFY_TLS', 'true').lower()
    if tls not in ('true', 'false'):
        raise ValueError('SPLUNK_VERIFY_TLS must be true or false.')
    verify = (os.getenv('SPLUNK_CA_BUNDLE') or True) if tls == 'true' else False
    if verify is False:
        print('WARNING: TLS certificate verification explicitly disabled for this lab connection.')
    deadline = time.monotonic() + config['search_timeout_seconds']
    with requests.Session() as session:
        session.trust_env = False  # Do not implicitly use proxies or .netrc credentials.
        token = os.getenv('SPLUNK_TOKEN')
        if token:
            session.headers['Authorization'] = f'Bearer {token}'
        elif os.getenv('SPLUNK_USERNAME') and os.getenv('SPLUNK_PASSWORD'):
            session.auth = (os.environ['SPLUNK_USERNAME'], os.environ['SPLUNK_PASSWORD'])
        else:
            raise ValueError('Set SPLUNK_TOKEN or SPLUNK_USERNAME and SPLUNK_PASSWORD in .env.')

        def request(method, path, **kwargs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Splunk search/download timeout. Narrow the time range or increase the timeout.')
            try:
                response = session.request(method, base + path, verify=verify,
                    timeout=min(config['request_timeout_seconds'], remaining), allow_redirects=False,
                    params={'output_mode': 'json', **kwargs.pop('params', {})}, **kwargs)
                if response.status_code in (401, 403):
                    raise ValueError('Splunk authentication/authorization failed. Check credentials and read permissions.')
                if not 200 <= response.status_code < 300:
                    raise ValueError(f'Splunk request failed (HTTP {response.status_code}); check SPL, API address and job availability.')
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError('Unexpected Splunk JSON response.')
                check_messages(data)
                if time.monotonic() >= deadline:
                    raise ValueError('Splunk search/download timeout.')
                return data
            except requests.exceptions.SSLError:
                raise ValueError('TLS validation failed. Configure a trusted CA bundle; use TLS=false only explicitly in a lab.') from None
            except requests.exceptions.Timeout:
                raise ValueError('Splunk request timed out. Check reachability or increase timeouts.') from None
            except requests.exceptions.JSONDecodeError:
                raise ValueError('Splunk returned invalid JSON.') from None
            except requests.exceptions.RequestException:
                raise ValueError('Cannot connect to Splunk management API. Check address, network and port 8089.') from None

        created = request('POST', '/services/search/jobs', data={
            'search': search, 'earliest_time': earliest, 'latest_time': latest,
            'exec_mode': 'normal', 'max_count': config['max_results'] + 1,
            'max_time': 0, 'auto_cancel': config['search_timeout_seconds'],
        })
        if not isinstance(created.get('sid'), str) or not created['sid']:
            raise ValueError('Splunk did not return a search job ID.')
        path = '/services/search/jobs/' + quote(created['sid'], safe='')
        while True:
            status = request('GET', path)['entry'][0]['content']
            check_messages(status)
            if truth(status.get('isFailed')) or status.get('dispatchState') in ('FAILED', 'INTERNAL_CANCEL'):
                raise ValueError('Splunk search failed; inspect the SPL and job in Splunk.')
            if truth(status.get('isFinalized')) or truth(status.get('eventIsTruncated')):
                raise ValueError('Splunk search was finalized early or truncated; no report produced.')
            if truth(status.get('isDone')):
                break
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        expected = int(status['resultCount'])
        if expected < 0 or expected >= config['max_results']:
            raise ValueError('Result limit reached; narrow the search range or raise max_results. No partial report produced.')
        rows = []
        while len(rows) < expected:
            data = request('GET', path + '/results', params={
                'offset': len(rows), 'count': min(config['page_size'], expected - len(rows))})
            if truth(data.get('preview')):
                raise ValueError('Unexpected preview results; no report produced.')
            batch = data.get('results')
            if not isinstance(batch, list) or not batch or not all(isinstance(r, dict) for r in batch):
                raise ValueError('Incomplete or invalid result page; no report produced.')
            rows.extend(batch)
        if len(rows) != expected:
            raise ValueError('Result count mismatch; no report produced.')
        return rows
