"""Read explicit exports; discover candidates without touching Splunk indexes."""
import csv
import gzip
import io
import json
from pathlib import Path

from analyzer import FIELDS

ALIASES = {
    '_time': ('_time', 'trigger_time', 'timestamp', 'time'),
    'rule_name': ('rule_name', 'savedsearch_name', 'search_name', 'alert_name'),
    'host': ('host', 'dest', 'dest_host', 'hostname'),
    'user': ('user', 'src_user', 'username'),
    'severity': ('severity', 'urgency', 'priority'),
}


def parse_bytes(raw, filename, max_rows=100000, max_bytes=100 * 1024 * 1024):
    """Read UTF-8 exports supplied by the local UI or CLI."""
    path = Path(filename)
    try:
        if path.suffix.lower() == '.gz':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError('Dosya açılmış halde 100 MiB sınırını aşıyor; daha küçük bir dışa aktarım kullanın.')
        text = raw.decode('utf-8-sig')
        suffix = path.with_suffix('').suffix.lower() if path.suffix.lower() == '.gz' else path.suffix.lower()
        if suffix == '.csv':
            reader = csv.DictReader(io.StringIO(text, newline=''), strict=True)
            headers = reader.fieldnames or []
            if not headers or len(headers) != len(set(headers)):
                raise ValueError('CSV başlıkları boş veya yineleniyor.')
            rows = []
            for row in reader:
                if None in row or any(v is None for v in row.values()):
                    raise ValueError('CSV satırındaki sütun sayısı başlıklarla uyuşmuyor.')
                rows.append(row)
                if len(rows) > max_rows:
                    raise ValueError('Dosya satır limitini aşıyor; zaman aralığını daraltın veya max_results artırın.')
        elif suffix in ('.json', '.jsonl', '.ndjson'):
            if suffix in ('.jsonl', '.ndjson'):
                items = [json.loads(line) for line in text.splitlines() if line.strip()]
                rows = [item.get('result', item) if isinstance(item, dict) else item for item in items]
            else:
                data = json.loads(text)
                rows = data.get('results') if isinstance(data, dict) else data
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise ValueError('JSON, nesne listesi veya {"results": [...]} olmalı; JSONL her satırda bir kayıt olmalı.')
            headers = list(dict.fromkeys(k for row in rows for k in row))
        else:
            raise ValueError('CSV, CSV.GZ, JSON, JSONL ve NDJSON desteklenir (JSON türleri .gz olabilir).')
        if len(rows) > max_rows:
            raise ValueError('Dosya satır limitini aşıyor; daha küçük veri seçin veya max_results artırın.')
        return rows, headers
    except (OSError, EOFError, UnicodeError, csv.Error, json.JSONDecodeError):
        raise ValueError('Dosya okunamadı. Yol, okuma izni, UTF-8 ve CSV/JSON/GZip biçimini kontrol edin.') from None


def load_file(path, max_rows=100000, max_bytes=100 * 1024 * 1024):
    path = Path(path).expanduser()
    try:
        with path.open('rb') as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError('Dosya boyutu sınırı aşıldı; daha küçük bir dışa aktarım kullanın.')
        return parse_bytes(raw, path.name, max_rows, max_bytes)
    except OSError:
        raise ValueError('Dosya okunamadı; yol ve okuma iznini kontrol edin.') from None


def resolve_fields(headers, overrides=None, configured=None, interactive=False):
    """Show inferred mapping; require a choice if multiple aliases are possible."""
    mapping = {}
    overrides = overrides or {}
    for name in FIELDS:
        explicit = overrides.get(name) or (configured or {}).get(name)
        if explicit:
            if explicit not in headers and name in ('_time', 'rule_name'):
                raise ValueError(f'{name} için seçilen sütun dosyada yok: {explicit}')
            mapping[name] = explicit
            continue
        options = [k for k in ALIASES[name] if k in headers]
        if len(options) == 1:
            mapping[name] = options[0]
        elif len(options) > 1 or (not options and name in ('_time', 'rule_name')):
            if not interactive:
                raise ValueError(f'{name} eşleştirmesi belirsiz/eksik. --map {name}=SUTUN kullanın. Mevcut: {", ".join(headers)}')
            print(f'\n{name}: mevcut sütunlar: {", ".join(headers)}')
            selected = input('Kullanılacak sütun adını yazın: ').strip()
            if selected not in headers:
                raise ValueError('Seçilen sütun bulunamadı.')
            mapping[name] = selected
        else:
            mapping[name] = name  # Optional missing columns normalize to unknown.
    print('Alan eşleştirmesi: ' + ', '.join(f'{k} -> {v}' for k, v in mapping.items()))
    if interactive and input('Bu eşleştirme doğru mu? [E/h]: ').strip().lower() not in ('', 'e', 'evet'):
        raise ValueError('Eşleştirme onaylanmadı. --map veya ayrı --config ile tekrar deneyin.')
    return mapping


def discover_files(splunk_home, limit=200):
    """Only CSV exports and dispatch result files; bounded, no recursive index scan."""
    home = Path(splunk_home).expanduser()
    found, notes = [], []
    for folder, dispatch in ((home / 'var/run/splunk/csv', False),
                             (home / 'var/run/splunk/dispatch', True)):
        try:
            visited = 0
            for entry in folder.iterdir():
                visited += 1
                if visited > 5000:
                    notes.append(f'Tarama 5000 girişte durdu: {folder}; bilinen dosyayı --file ile seçin.')
                    break
                if entry.is_symlink():
                    continue
                candidate = entry / 'results.csv.gz' if dispatch and entry.is_dir() else entry
                if dispatch and not entry.is_dir():
                    continue
                if candidate.is_symlink():
                    continue
                if candidate.is_file() and candidate.name.lower().endswith(('.csv', '.csv.gz')):
                    stat = candidate.stat()
                    found.append({'path': str(candidate), 'bytes': stat.st_size, 'modified': stat.st_mtime})
                    if len(found) >= limit:
                        notes.append(f'İlk {limit} aday gösteriliyor; daha fazlasını doğrudan --file ile seçin.')
                        return sorted(found, key=lambda f: -f['modified']), notes
        except PermissionError:
            notes.append(f'Okuma izni yok: {folder}. Uygulamayı root çalıştırmak yerine dosyayı yetkili hesapla dışa aktarın.')
        except FileNotFoundError:
            notes.append(f'Klasör yok: {folder}')
        except OSError:
            notes.append(f'Tarama sırasında dosya değişti/okunamadı: {folder}; tekrar deneyin.')
    return sorted(found, key=lambda f: -f['modified']), notes
