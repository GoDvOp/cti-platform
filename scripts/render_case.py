"""Render a local case note to offline HTML with the standard library."""
from pathlib import Path
import html
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
folder = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'docs/cases/novabev-2025'
source = (folder / 'case.md').read_text(encoding='utf-8')
case_title = source.splitlines()[0].lstrip('# ').strip()


def inline(text):
    value = html.escape(text)
    return re.sub(r'\[([^]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', value)


blocks = re.split(r'\n\s*\n', source.strip())
body = []
for block in blocks:
    if block.startswith('```'):
        body.append('<pre>' + html.escape('\n'.join(block.splitlines()[1:-1])) + '</pre>')
    elif block.startswith('#'):
        level = len(block) - len(block.lstrip('#'))
        body.append(f'<h{level}>' + inline(block[level:].strip()) + f'</h{level}>')
    elif block.startswith('|'):
        rows = block.splitlines()
        cells = lambda row, tag: '<tr>' + ''.join(f'<{tag}>' + inline(c.strip()) + f'</{tag}>' for c in row.strip('|').split('|')) + '</tr>'
        body.append('<div class="table-wrap"><table>' + cells(rows[0], 'th') + ''.join(cells(r, 'td') for r in rows[2:]) + '</table></div>')
    elif block.startswith('- '):
        body.append('<ul>' + ''.join('<li>' + inline(r[2:]) + '</li>' for r in block.splitlines()) + '</ul>')
    elif re.match(r'^\d+\. ', block):
        body.append('<ol>' + ''.join('<li>' + inline(re.sub(r'^\d+\. ', '', r)) + '</li>' for r in block.splitlines()) + '</ol>')
    else:
        body.append('<p>' + inline(block) + '</p>')
        if block.startswith('Схема:'):
            body.append('<figure><img src="graph.svg" alt="Граф связей по доказательствам кейса"></figure>')
page = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Кейс 01 · Novabev Group и ВинЛаб</title><style>
body{font:16px/1.6 system-ui,sans-serif;color:#1b2c43;background:#f5f7fb;margin:0}main{max-width:1000px;margin:30px auto;background:white;padding:36px 48px;border-radius:14px}h1{font-size:32px;line-height:1.2}h2{margin-top:2em;color:#23486d}a{color:#165e9e}nav{font-size:14px;border-bottom:1px solid #dae1e9;padding-bottom:16px}nav a{margin-right:18px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #d5dde7;padding:12px;text-align:left;vertical-align:top}th{background:#edf2f8}pre{white-space:pre-wrap;background:#edf2f8;padding:18px;border-radius:8px}figure{margin:22px 0}img{width:100%;height:auto}.table-wrap{overflow:auto}li{margin:.5em 0}@media(max-width:700px){main{padding:22px;margin:0;border-radius:0}h1{font-size:26px}}@media print{body{background:white}main{margin:0;padding:0}nav{display:none}h2{break-after:avoid}tr,figure,pre{break-inside:avoid}a{color:inherit}}
</style><main><nav><a href="evidence.json">Реестр доказательств</a><a href="score_snapshot.json">Расчёт</a><a href="graph.cypher">Запросы Neo4j</a></nav>'''+ '\n'.join(body) + '</main></html>'
page = page.replace('<title>Кейс 01 · Novabev Group и ВинЛаб</title>', '<title>' + html.escape(case_title) + '</title>')
nav = '<nav>' + ''.join(f'<a href="{name}">{label}</a>' for name, label in (
    ('evidence.json', 'Реестр доказательств'), ('score_snapshot.json', 'Расчёт'),
    ('graph.cypher', 'Запросы Neo4j'), ('sensitivity.html', 'Все сценарии'), ('snapshot.json.gz', 'Отдельный снимок'))
    if (folder / name).exists()) + '</nav>'
page = re.sub(r'<nav>.*?</nav>', lambda match: nav, page, count=1)
(folder / 'case.html').write_text(page, encoding='utf-8')

print(f'Готово: {folder / "case.html"}')
