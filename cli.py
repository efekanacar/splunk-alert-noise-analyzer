"""Menu-first CLI; file analysis needs neither credentials nor edited config."""
import argparse
import getpass
import json
import math
import os
import re
import sys
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from analyzer import FIELDS, analyze, enrich_report, parse_time, write_reports
from dashboard import write_dashboard
from input_files import discover_files, load_file, resolve_fields
from local_splunk import diagnose, fetch_triggered
from splunk_client import fetch_results

ROOT = Path(__file__).resolve().parent
DEFAULTS = {'search_timeout_seconds': 120, 'request_timeout_seconds': 15,
            'page_size': 1000, 'max_results': 100000}


def bound(value, now):
    if not value:
        return None
    if value == 'now':
        return now
    match = re.fullmatch(r'-(\d+)([mhd])', value)
    if match:
        return now - timedelta(seconds=int(match[1]) * {'m': 60, 'h': 3600, 'd': 86400}[match[2]])
    try:
        return parse_time(value)
    except (ValueError, OverflowError, OSError):
        raise ValueError('Zaman: saat dilimli ISO, epoch, now veya -24h/-7d/-30m gibi bir değer kullanın.') from None


def menu(args):
    print('\nSPLUNK ALERT NOISE ANALYZER · Kolay başlangıç\n'
          '1. Örnek veriyle dene (bağlantı gerekmez)\n'
          '2. CSV / CSV.GZ / JSON dosyasını analiz et\n'
          '3. Bu makinedeki Splunk sonuç dosyalarını bul\n'
          '4. Yerel Splunk Triggered Alerts kayıtlarını oku (SPL gerekmez)\n'
          '5. Splunk bağlantısını teşhis et\n'
          '6. Yapılandırılmış SPL sorgusunu çalıştır\n')
    choice = input('Seçim [1]: ').strip() or '1'
    if choice == '1':
        args.demo = True
    elif choice == '2':
        args.file = Path(input('Dosyanın yolu: ').strip()).expanduser()
    elif choice == '3':
        args.local_files = True
        value = input(f'Splunk kurulum dizini [{args.splunk_home}]: ').strip()
        if value:
            args.splunk_home = Path(value).expanduser()
    elif choice == '4':
        args.triggered = True
    elif choice == '5':
        args.doctor = True
    elif choice == '6':
        args.search = True
    else:
        raise ValueError('1-6 arasında seçim yapın.')
    if choice in ('4', '5', '6'):
        args.base_url = input('Management adresi [https://localhost:8089]: ').strip() or 'https://localhost:8089'
    if choice in ('2', '3', '4', '6'):
        value = input('Tekrar penceresi, dakika [5]: ').strip()
        args.window_minutes = float(value or '5')
    return args


def main(argv=None):
    parser = argparse.ArgumentParser(description='Splunk alarm analizi: menü, yerel dosya ve çevrimdışı HTML rapor.')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--file', '--csv', dest='file', type=Path, help='CSV/CSV.GZ/JSON/JSONL dosyası')
    source.add_argument('--demo', action='store_true', help='Sahte örnek veri')
    source.add_argument('--local-files', action='store_true', help='Yerel Splunk CSV sonuç dosyalarını listele/seç')
    source.add_argument('--triggered', action='store_true', help='SPL yazmadan takip edilen tetiklenmeleri oku')
    source.add_argument('--doctor', action='store_true', help='TCP, TLS, oturum ve okuma erişimini kontrol et')
    source.add_argument('--search', action='store_true', help='config.json içindeki SPL ile olay ara')
    parser.add_argument('--splunk-home', type=Path, default=Path(os.getenv('SPLUNK_HOME', '/opt/splunk')))
    parser.add_argument('--base-url', help='Yerel varsayılan: https://localhost:8089')
    parser.add_argument('--insecure', action='store_true', help='Yalnızca lab: TLS doğrulamasını açıkça kapat')
    parser.add_argument('--config', type=Path, help='İsteğe bağlı JSON; --search için config.json varsayılan')
    parser.add_argument('--map', action='append', default=[], metavar='ALAN=SUTUN', help='Örn: --map rule_name=alert_title')
    parser.add_argument('--rule-name', help='Tek kurala ait dışa aktarımda eksik kural sütununu verilen adla doldur')
    parser.add_argument('--earliest', help='ISO/epoch veya -24h; başlangıç dahil')
    parser.add_argument('--latest', help='ISO/epoch veya now; bitiş hariç')
    parser.add_argument('--window-minutes', type=float, default=5)
    parser.add_argument('--output-dir', type=Path, help='Varsayılan: reports altında her çalıştırmaya ayrı dizin')
    parser.add_argument('--open', action='store_true', help='Oluşan HTML raporunu varsayılan tarayıcıda aç')
    args = parser.parse_args(argv)
    interactive = False
    try:
        load_dotenv(ROOT / '.env')
        if not any((args.file, args.demo, args.local_files, args.triggered, args.doctor, args.search)):
            if sys.stdin.isatty():
                args = menu(args)
                interactive = True
            else:
                parser.print_help()
                return 0
        if not math.isfinite(args.window_minutes) or not 0 < args.window_minutes <= 525600:
            raise ValueError('Pencere 0’dan büyük ve en fazla 525600 dakika olmalı.')
        config = dict(DEFAULTS)
        config_path = args.config or (ROOT / 'config.json' if args.search else None)
        if config_path:
            content = json.loads(config_path.read_text(encoding='utf-8-sig'))
            if not isinstance(content, dict):
                raise ValueError('Yapılandırma bir JSON nesnesi olmalı.')
            config.update(content)
        for key in DEFAULTS:
            if type(config[key]) is not int or config[key] <= 0:
                raise ValueError(f'{key} pozitif tam sayı olmalı.')
        if 'fields' in config and (not isinstance(config['fields'], dict) or any(
                not isinstance(config['fields'].get(k), str) or not config['fields'][k].strip() for k in FIELDS)):
            raise ValueError('config.fields beş standart alanı da dolu sütun adlarıyla eşlemeli.')
        if args.doctor:
            diagnose(args.base_url, args.insecure, interactive or sys.stdin.isatty())
            return 0
        if args.local_files:
            files, notes = discover_files(args.splunk_home)
            for note in notes:
                print(note)
            print('Aday dosyalar alarm geçmişi garantisi taşımaz. Tek dosya seçilir; dosyalar otomatik birleştirilmez.')
            for i, entry in enumerate(files, start=1):
                print(f'{i}. {entry["path"]} ({entry["bytes"]} bayt)')
            if not files:
                raise ValueError('CSV sonucu bulunamadı. Splunk Web’den alarm sonuçlarını CSV dışa aktarın ve --file kullanın.')
            if not sys.stdin.isatty():
                print('Analiz için --file DOSYA_YOLU kullanın.')
                return 0
            choice = int(input('Analiz edilecek dosya numarası: '))
            if not 1 <= choice <= len(files):
                raise ValueError('Dosya numarası geçersiz.')
            args.file = Path(files[choice - 1]['path'])
            interactive = True
        overrides = {}
        for item in args.map:
            key, separator, value = item.partition('=')
            if not separator or key not in FIELDS or not value:
                raise ValueError('--map ALAN=SUTUN olmalı. Alanlar: ' + ', '.join(FIELDS))
            overrides[key] = value
        now = datetime.now(timezone.utc)
        earliest = latest = None
        if args.demo:
            args.file = ROOT / 'sample_alerts.csv'
        if args.file:
            rows, headers = load_file(args.file, config['max_results'])
            if (interactive and not args.demo and not args.rule_name and not overrides.get('rule_name')
                    and not config.get('fields') and not any(name in headers for name in
                    ('rule_name', 'savedsearch_name', 'search_name', 'alert_name'))):
                print('Dosyada tanınan kural sütunu yok. Yalnızca tek kurala ait bir sonuçsa gerçek kural adını verebilirsiniz.')
                args.rule_name = input('Tek kural adı (başka sütun seçmek için boş bırakın): ').strip() or None
            if args.rule_name:
                if any(name in headers for name in ('rule_name', 'savedsearch_name', 'search_name', 'alert_name')):
                    raise ValueError('--rule-name mevcut kural sütununu ezmez; --map kullanın.')
                for row in rows:
                    row['rule_name'] = args.rule_name
                headers.append('rule_name')
                overrides['rule_name'] = 'rule_name'
            if not rows and not headers:
                mapping = dict(zip(FIELDS, FIELDS))
            else:
                mapping = resolve_fields(headers, overrides, config.get('fields'), interactive and not args.demo)
            earliest, latest = bound(args.earliest, now), bound(args.latest, now)
            kind = 'Örnek veri' if args.demo else 'Dosyadan alınan kayıtlar'
            scope = 'Bir satır bir girdi kaydıdır. Dosyanın alarm sonuçları içerdiği kullanıcı tarafından doğrulanmalıdır; tam geçmiş varsayılmaz.'
            source_name = args.file.name
        elif args.triggered:
            rows = fetch_triggered(config, args.base_url, args.insecure, interactive or sys.stdin.isatty())
            mapping = dict(zip(FIELDS, FIELDS))
            earliest, latest = bound(args.earliest or '-24h', now), bound(args.latest or 'now', now)
            args.earliest, args.latest = args.earliest or '-24h', args.latest or 'now'
            kind = 'Triggered Alerts / tetiklenme kayıtları'
            scope = ('Her satır bir tetiklenme kaydıdır, ham olay sayısı değildir. Yalnızca takip edilen, süresi dolmamış ve yetkiyle görünen kayıtlar. '
                     'Host/kullanıcı bu API’den alınmaz; unknown ve düşük güven olarak değerlendirilir. Boş sonuç, alarm olmadığı anlamına gelmez.')
            source_name = 'Splunk management API / alerts/fired_alerts/-'
        else:
            if args.base_url:
                os.environ['SPLUNK_BASE_URL'] = args.base_url
            if args.insecure:
                os.environ['SPLUNK_VERIFY_TLS'] = 'false'
            if (interactive or sys.stdin.isatty()) and not os.getenv('SPLUNK_TOKEN') and not (
                    os.getenv('SPLUNK_USERNAME') and os.getenv('SPLUNK_PASSWORD')):
                os.environ['SPLUNK_USERNAME'] = input('Splunk kullanıcı adı: ').strip()
                os.environ['SPLUNK_PASSWORD'] = getpass.getpass('Splunk parolası (gizli, dosyaya kaydedilmez): ')
            rows = fetch_results(config, args.earliest or '-24h', args.latest or 'now')
            mapping = config.get('fields', dict(zip(FIELDS, FIELDS)))
            kind, scope = 'SPL arama sonuçları', 'Her sonuç bir alarm olmalı. Kapsam sorgu, yetki, saklama ve sunucu limitlerine bağlıdır.'
            source_name = 'Yapılandırılmış SPL / management API'
            args.earliest, args.latest = args.earliest or '-24h', args.latest or 'now'
        if earliest and latest and earliest >= latest:
            raise ValueError('Başlangıç bitişten önce olmalı.')
        report = enrich_report(analyze(rows, mapping, args.window_minutes, earliest, latest))
        directory = args.output_dir or Path('reports') / now.strftime('%Y%m%d-%H%M%S-%f')
        # Avoid mixing a new run with any previous output.
        if directory.exists() and any(directory.iterdir()):
            raise ValueError('Çıktı dizini dolu. Yeni bir --output-dir seçin; önceki raporların üzerine yazılmaz.')
        write_reports(report, directory)
        html = write_dashboard(report, directory, {'kind': kind, 'scope': scope, 'source': source_name,
             'window_minutes': args.window_minutes, 'earliest': args.earliest, 'latest': args.latest,
             'resolved_earliest_utc': earliest.isoformat() if earliest else None,
             'resolved_latest_utc': latest.isoformat() if latest else None,
             'mapping': mapping, 'rule_name_override': args.rule_name})
        s = report['summary'][0]
        print(f'\n{kind}\n{scope}\n')
        print(f'Geçerli: {s["total_alerts"]} | Atlanan: {s["skipped_rows"]} | Zaman dışı: {s["filtered_rows"]}')
        print(f'Tekrar grubu: {s["repeat_groups"]} | Tekrar kayıt: {s["repeat_alerts"]}')
        print('\nEn yoğun 10 kural:')
        for row in report['rules'][:10]:
            print(f'  {row["rule_name"]}: {row["count"]} (%{row["percent"]})')
        print(f'\nHTML rapor: {html.resolve()}\nCSV raporları: {directory.resolve()}')
        print('Tekrarlar inceleme adayıdır; otomatik false positive veya kural kapatma kararı değildir.')
        if args.open:
            webbrowser.open(html.resolve().as_uri())
        return 0
    except json.JSONDecodeError:
        print('Hata: config JSON biçimi geçersiz.', file=sys.stderr)
    except (OSError, UnicodeError):
        print('Hata: dosya/sertifika/rapor yolu okunamadı veya yazılamadı; yol ve izinleri kontrol edin.', file=sys.stderr)
    except (KeyError, IndexError, TypeError, AttributeError):
        print('Hata: yapılandırma veya Splunk yanıtı beklenen biçimde değil.', file=sys.stderr)
    except (ValueError, OverflowError) as exc:
        print(f'Hata: {exc}', file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print('\nİşlem iptal edildi.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
