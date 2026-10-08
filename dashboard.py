"""A self-contained offline HTML report. No server, CDN or telemetry."""
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import json


def write_dashboard(report, directory, metadata):
    out = Path(directory)
    esc = lambda value: escape(str(value), quote=True)
    summary = report['summary'][0]
    total = summary['total_alerts']
    percent = round(100 * summary['repeat_alerts'] / total, 1) if total else 0
    rule_only = metadata.get('grouping') == 'rule_name'

    def table(name, labels, keys, limit=500):
        rows = report[name]
        head = ''.join(f'<th scope="col">{esc(label)}</th>' for label in labels)
        body = ''.join('<tr>' + ''.join(f'<td>{esc(row[key])}</td>' for key in keys) + '</tr>' for row in rows[:limit])
        return (f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
                f'<p class="note">Gösterilen: {min(len(rows), limit)} / {len(rows)}. '
                f'Tamamı: <a href="{name}.csv">{name}.csv</a>. Tablo araması yalnızca gösterilen satırları filtreler.</p>')

    def bars(name, label, limit=10):
        rows = report[name][:limit]
        high = max((r['count'] for r in rows), default=1)
        if not rows:
            return '<p class="note">Bu kapsamda kayıt yok.</p>'
        return ''.join(f'<div class="bar"><span title="{esc(r[label])}">{esc(r[label])}</span>'
                       f'<div class="track"><i style="width:{100*r["count"]/high:.2f}%"></i></div>'
                       f'<strong>{r["count"]}</strong></div>' for r in rows)

    cards = [('Geçerli kayıt', total), ('Kural', len(report['rules'])),
             ('Tekrar kayıt', summary['repeat_alerts']), ('Tekrar oranı', f'%{percent}')]
    stat_html = ''.join(f'<div class="stat"><span>{label}</span><strong>{value}</strong></div>' for label, value in cards)
    candidates = table('candidates',
        ['Kural','Tetiklenme','Pay %','Tekrar','Tekrar %','Grup'] if rule_only else
        ['Kural','Kayıt','Pay %','Tekrar','Tekrar %','Grup','Düşük güven','Host','Kullanıcı'],
        ['rule_name','count','percent','repeats','repeat_percent','groups'] if rule_only else
        ['rule_name','count','percent','repeats','repeat_percent','groups','low_confidence_groups','hosts','users'])
    repeat_table = table('repeats',
        ['Kural','Başlangıç UTC','Son tetiklenme UTC','Tetiklenme','Tekrar'] if rule_only else
        ['Kural','Host','Kullanıcı','Başlangıç UTC','Son kayıt UTC','Kayıt','Tekrar','Güven'],
        ['rule_name','start','end','count','repeats'] if rule_only else
        ['rule_name','host','user','start','end','count','repeats','confidence'])
    alert_table = table('alerts', ['Zaman UTC','Kural'] if rule_only else
        ['Zaman UTC','Kural','Host','Kullanıcı','Severity'], ['_time','rule_name'] if rule_only else
        ['_time','rule_name','host','user','severity'])
    rejected = table('rejected', ['Girdi kayıt sırası','Atlama nedeni'], ['row','reason'])
    entities = '' if rule_only else f'''<div class="grid"><section><h2>En yoğun 10 host</h2>{bars('hosts','host')}</section><section><h2>En yoğun 10 kullanıcı</h2>{bars('users','user')}</section></div>'''
    counts_note = (f'Girdi: <b>{summary["input_rows"]}</b> · Atlanan: <b>{summary["skipped_rows"]}</b> '
                   f'· Zaman dışı: <b>{summary["filtered_rows"]}</b>')
    if rule_only:
        quality_section = f'<section id="quality"><h2>Atlanan kayıtlar</h2><p>{counts_note}</p>{rejected}</section>'
        candidate_note = 'Tekrar sayısına, sonra hacme göre sıralı. Tekrar % = kuraldaki tekrar / kuraldaki tetiklenme.'
        repeat_note = ('Aynı kuralın sabit pencere içindeki tetiklenmeleri. İlk kayıt hariç sayılır; '
                       'tam sınırdaki kayıt yeni grup açar. Aynı olaya ait olduklarını göstermez.')
        record_title, quality_title = 'Tetiklenme kayıtları', 'Atlananlar'
    else:
        quality = ' · '.join(f'{esc(r["field"])}: %{r["unknown_percent"]} unknown' for r in report['quality'])
        quality_section = f'''<div class="grid"><section id="quality"><h2>Veri kalitesi</h2><p>{counts_note}</p><p>{quality}</p><p class="note">Yüzdeler geçerli kapsam içi kayıtlar içindir. Eksik alanlar farklı varlıkların birleşmesine yol açabilir.</p>{rejected}</section><section><h2>Severity dağılımı</h2>{bars('severity','severity')}<p class="note">Kaynak değerleri aynen korunur; sayısal severity otomatik risk puanına çevrilmez.</p></section></div>'''
        candidate_note = 'Tekrar sayısına, sonra hacme göre sıralı. Host/kullanıcı sayıları unknown değerlerini içermez.'
        repeat_note = 'İlk kayıt hariç sayılır; pencere ilk alarma sabitlenir. Tam sınırdaki kayıt yeni grup açar. low: host veya kullanıcı eksik/unknown.'
        record_title, quality_title = 'Normalize edilmiş kayıtlar', 'Veri kalitesi'
    links = ' '.join(f'<a class="download" href="{esc(name)}.csv">{esc(name)} CSV</a>' for name in report)
    created = datetime.now(timezone.utc).isoformat(timespec='seconds')
    page = '''<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Splunk Alert Noise Analyzer · Analiz</title>
<style>
:root{--bg:#f6f8f9;--panel:#fff;--line:#e5e9eb;--text:#172b35;--muted:#718088;--accent:#e8572b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
header,main,footer{max-width:1280px;margin:auto;padding:28px 32px}header{padding-top:44px}
.eyebrow{letter-spacing:2px;color:var(--accent);font-size:12px;font-weight:700}h1{font-size:38px;line-height:1.2;margin:12px 0}h2{font-size:21px;margin:0 0 16px}h3{font-size:16px}
p{margin:8px 0}.note,.subtitle{color:var(--muted);font-size:13px}.notice{border-left:3px solid var(--accent);padding:14px 18px;background:#fff1eb;margin:20px 0;overflow-wrap:anywhere}
nav{display:flex;gap:18px;flex-wrap:wrap;margin:24px 0 0}a{color:var(--accent)}nav a{text-decoration:none}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.stat,section{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:24px}.stat span{color:var(--muted)}.stat strong{display:block;font-size:34px;margin-top:8px}
section{margin:20px 0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.grid section{margin:20px 0 0;min-width:0}
.bar{display:grid;grid-template-columns:minmax(90px,1fr) 1.3fr 40px;gap:12px;align-items:center;margin:12px 0;font-size:13px}.bar span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.track{height:9px;background:#eef2f4;border-radius:6px}.track i{display:block;height:100%;background:var(--accent);border-radius:6px}.bar strong{text-align:right}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px;white-space:nowrap}th{text-align:left;color:var(--muted);font-size:12px}th,td{padding:12px;border-bottom:1px solid var(--line)}tbody tr:hover{background:#f8fafb}td{max-width:420px;overflow:hidden;text-overflow:ellipsis}
input{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;color:var(--text);width:100%;max-width:400px;margin:0 0 14px}.download{display:inline-block;border:1px solid var(--line);padding:7px 12px;border-radius:6px;margin:4px;text-decoration:none}footer{color:var(--muted);font-size:12px}
@media(max-width:760px){header,main,footer{padding:20px}.stats{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}h1{font-size:28px}section{padding:16px}}
@media print{body{background:white;color:#182433}section,.stat{background:white;break-inside:avoid}nav,input{display:none}.table-wrap{overflow:visible}a,.note,.subtitle{color:#36546d}}
</style></head><body>'''
    page += f'''<header><div class="eyebrow">SOC / ALARM ANALİZİ</div><h1>Splunk Alert Noise Analyzer</h1>
<p class="subtitle">Çevrimdışı analiz raporu · UTC · {esc(created)}</p>
<div class="notice"><b>{esc(metadata['kind'])}</b><br>{esc(metadata['scope'])}<br>
Kaynak: {esc(metadata['source'])}<br>Pencere: {metadata['window_minutes']} dakika · Başlangıç: {esc(metadata.get('earliest') or 'Sınır yok')} · Bitiş: {esc(metadata.get('latest') or 'Sınır yok')}</div>
<nav><a href="#overview">Genel bakış</a><a href="#candidates">Kurallar</a><a href="#repeats">Tekrarlar</a><a href="#quality">{quality_title}</a><a href="#records">Kayıtlar</a></nav></header>
<main><div class="stats" id="overview">{stat_html}</div>
<div class="grid"><section><h2>En yoğun 10 kural</h2>{bars('rules','rule_name')}</section>
<section><h2>Saatlik dağılım</h2>{bars('hourly','hour_utc',24)}<p class="note">İlk 24 dolu saat gösterilir; sıfır saatler çizilmez. Tümü hourly.csv içinde.</p></section></div>
{entities}
<section id="candidates"><h2>Kural bazında inceleme</h2><p class="note">{candidate_note} Bu oran bir risk veya false positive puanı değildir.</p>
<label>Bu tabloda ara<br><input type="search" placeholder="Kural adı..."></label>{candidates}</section>
<section id="repeats"><h2>Tekrar grupları</h2><p class="note">{repeat_note}</p>
<label>Bu tabloda ara<br><input type="search" placeholder="Kural adı veya zaman..."></label>{repeat_table}</section>
{quality_section}
<section id="records"><h2>{record_title}</h2><label>Bu tabloda ara<br><input type="search" placeholder="Kayıtlarda ara..."></label>{alert_table}</section>
<section><h2>Dosyalar ve yöntem</h2>{links}<p class="note">Alan eşleştirmesi: {esc(json.dumps(metadata.get('mapping',{}),ensure_ascii=False))}</p><p>Tekrarlar inceleme adaylarıdır. Ham olaylar ve iş bağlamı incelenmeden kural kapatma veya false positive kararı verilmez.</p></section>
</main><footer>Yerel analiz raporu · UTC <span style="float:right">Efekan Acar</span></footer>
<script>document.querySelectorAll('input[type=search]').forEach(input=>input.addEventListener('input',()=>{{const q=input.value.toLocaleLowerCase('tr');input.closest('section').querySelectorAll('tbody tr').forEach(row=>row.hidden=!row.textContent.toLocaleLowerCase('tr').includes(q));}}));</script></body></html>'''
    (out / 'dashboard.html').write_text(page, encoding='utf-8')
    (out / 'run.json').write_text(json.dumps({**metadata, 'created_utc': created, 'summary': summary}, ensure_ascii=False, indent=2), encoding='utf-8')
    return out / 'dashboard.html'
