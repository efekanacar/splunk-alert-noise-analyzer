"""Normalize alert rows and summarize fixed-window repeat candidates."""
import csv
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIELDS = ('_time', 'rule_name', 'host', 'user', 'severity')


def parse_time(value):
    text = str(value).strip()
    try:
        return datetime.fromtimestamp(float(text), timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    dt = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamp needs a timezone or Unix epoch seconds.')
    return dt.astimezone(timezone.utc)


def read_csv(path, fields):
    try:
        with Path(path).open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)):
                raise ValueError('CSV contains duplicate column names.')
            if not {fields['_time'], fields['rule_name']} <= set(headers):
                raise ValueError('CSV needs the configured time and rule columns.')
            rows = list(reader)
            if any(None in row or any(v is None for v in row.values()) for row in rows):
                raise ValueError('CSV row has an incorrect number of columns.')
            return rows
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError('Cannot read CSV: check path, UTF-8 encoding and CSV structure.') from exc


def analyze(rows, fields, window_minutes=5, earliest=None, latest=None, rule_only=False):
    alerts = []
    rejected = []
    skipped = filtered = 0
    for row_number, row in enumerate(rows, start=1):
        values = {}
        for name in FIELDS:
            value = row.get(fields[name])
            if isinstance(value, (list, dict)):
                raise ValueError('Mapped fields must contain scalar values, not multivalue data.')
            values[name] = '' if value is None else str(value).strip()
        try:
            stamp = parse_time(values['_time'])
        except (ValueError, OverflowError, OSError):
            skipped += 1
            rejected.append({'row': row_number, 'reason': 'Geçersiz/eksik zaman'})
            continue
        if not values['rule_name']:
            skipped += 1
            rejected.append({'row': row_number, 'reason': 'Eksik kural adı'})
            continue
        if (earliest is not None and stamp < earliest) or (latest is not None and stamp >= latest):
            filtered += 1
            continue
        values['_time'] = stamp
        values['low_confidence'] = any(not values[k] or values[k].lower() == 'unknown' for k in ('host', 'user'))
        for name in ('host', 'user', 'severity'):
            values[name] = values[name] or 'unknown'
        alerts.append(values)
    alerts.sort(key=lambda row: row['_time'])
    active, groups = {}, []
    window = timedelta(minutes=window_minutes)
    for row in alerts:
        # Trigger records describe a rule firing; they do not identify an event entity.
        key = (row['rule_name'], '', '') if rule_only else tuple(row[k] for k in ('rule_name', 'host', 'user'))
        group = active.get(key)
        if group is None or row['_time'] - group['start'] >= window:
            group = dict(zip(('rule_name', 'host', 'user'), key))
            group.update(start=row['_time'], end=row['_time'], count=0,
                         confidence='low' if rule_only or row['low_confidence'] else 'normal')
            active[key] = group
            groups.append(group)
        group['count'] += 1
        group['end'] = row['_time']
        if row['low_confidence']:
            group['confidence'] = 'low'
    repeats = [{**g, 'repeats': g['count'] - 1} for g in groups if g['count'] > 1]
    total = len(alerts)
    def counts(field):
        return [{field: k, 'count': v, 'percent': round(v * 100 / total, 2)}
                for k, v in sorted(Counter(a[field] for a in alerts).items(), key=lambda x: (-x[1], x[0]))]
    hours = Counter(a['_time'].replace(minute=0, second=0, microsecond=0).isoformat() for a in alerts)
    return {
        'summary': [{'input_rows': len(rows), 'total_alerts': total, 'skipped_rows': skipped,
                     'filtered_rows': filtered, 'repeat_groups': len(repeats),
                     'repeat_alerts': sum(g['repeats'] for g in repeats)}],
        'rules': counts('rule_name'), 'hosts': counts('host'), 'users': counts('user'),
        'hourly': [{'hour_utc': k, 'count': v} for k, v in sorted(hours.items())],
        'repeats': repeats,
        'alerts': [{k: a[k] for k in FIELDS} for a in alerts],
        'rejected': rejected,
    }


HEADERS = {
    'rejected': ['row', 'reason'],
    'severity': ['severity', 'count', 'percent'],
    'candidates': ['rule_name', 'count', 'percent', 'repeats', 'repeat_percent', 'groups', 'low_confidence_groups', 'hosts', 'users'],
    'quality': ['field', 'unknown_count', 'unknown_percent'],
    'alerts': list(FIELDS),
    'summary': ['input_rows', 'total_alerts', 'skipped_rows', 'filtered_rows', 'repeat_groups', 'repeat_alerts'],
    'rules': ['rule_name', 'count', 'percent'], 'hosts': ['host', 'count', 'percent'],
    'users': ['user', 'count', 'percent'], 'hourly': ['hour_utc', 'count'],
    'repeats': ['rule_name', 'host', 'user', 'start', 'end', 'count', 'confidence', 'repeats'],
}


def enrich_report(report):
    """Add explainable review metrics without a false-positive score."""
    alerts = report['alerts']
    total = len(alerts)
    severity = Counter(row['severity'] for row in alerts)
    report['severity'] = [{'severity': k, 'count': v, 'percent': round(v * 100 / total, 2)}
                          for k, v in sorted(severity.items(), key=lambda x: (-x[1], x[0]))]
    report['quality'] = []
    for field in ('host', 'user', 'severity'):
        missing = sum(a[field].lower() == 'unknown' for a in alerts)
        report['quality'].append({'field': field, 'unknown_count': missing,
                                  'unknown_percent': round(missing * 100 / total, 2) if total else 0})
    group_counts, low_counts, repeated = Counter(), Counter(), Counter()
    entities = {}
    for a in alerts:
        hosts, users = entities.setdefault(a['rule_name'], (set(), set()))
        if a['host'].lower() != 'unknown':
            hosts.add(a['host'])
        if a['user'].lower() != 'unknown':
            users.add(a['user'])
    for group in report['repeats']:
        rule = group['rule_name']
        group_counts[rule] += 1
        repeated[rule] += group['repeats']
        low_counts[rule] += group['confidence'] == 'low'
    report['candidates'] = []
    for rule in report['rules']:
        name = rule['rule_name']
        hosts, users = entities[name]
        report['candidates'].append({**rule, 'repeats': repeated[name],
            'repeat_percent': round(repeated[name] * 100 / rule['count'], 2),
            'groups': group_counts[name], 'low_confidence_groups': low_counts[name],
            'hosts': len(hosts), 'users': len(users)})
    report['candidates'].sort(key=lambda r: (-r['repeats'], -r['count'], r['rule_name']))
    return report


def write_reports(report, output_dir, headers=None):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    for name, rows in report.items():
        with (Path(output_dir) / f'{name}.csv').open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=(headers or HEADERS)[name])
            writer.writeheader()
            writer.writerows(rows)


def print_report(report):
    print('Splunk Alert Noise Analyzer (UTC)')
    print(' | '.join(f'{k}: {v}' for k, v in report['summary'][0].items()))
    for name in ('rules', 'hosts', 'users', 'hourly', 'repeats'):
        limit = 10 if name in ('rules', 'hosts', 'users') else 24
        print(f'\n{name.upper()} (showing up to {limit}; full data in CSV)')
        print(' | '.join(HEADERS[name]))
        for row in report[name][:limit]:
            print(' | '.join(str(row[k]).replace('\x1b', '').replace('\n', ' ').replace('\r', ' ') for k in HEADERS[name]))
        if not report[name]:
            print('(none)')
    print('\nRepeat groups are review candidates, not false-positive or rule-disable decisions.')
